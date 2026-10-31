"""Actual Runtime/Engine/Git handoffs, scripted replies and zero model fees."""
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from loommode.codex.adapter import AdapterTurnResult
from loommode.codex.errors import ErrorCategory, ErrorRecord
from loommode.roles.contracts import parse_result
from loommode.tools.runtime import ToolPhase, ToolProfile
from loommode.workflow.errors import WorkflowError
from loommode.workflow.managed_cli import parse_completed_cli_result, cli_argv
from loommode.workflow.transitions import Node
from tests.fake_workflow_adapter import FakeWorkflowAdapter
from tests.test_no_dev_change import NoChangeScene
from tests.workflow_support import response, PASS_EVIDENCE, mediation


class ReplyAdapter(FakeWorkflowAdapter):
    """Simulate completed AI text, using real bounded tools only on implementation."""
    replies = None

    def run_turn(self, **kwargs):
        node = Node(kwargs['prompt'].split('\nACTIVITY: ')[1].split('\n', 1)[0])
        correcting = self.registry.get(kwargs['thread_id']).activity_metadata.get('purpose') == 'REPORT_CORRECTION'
        validator = kwargs['result_validator']
        def read(original):
            texts = (self.replies or {}).get(node, [])
            return validator(texts.pop(0) if texts else original)
        try:
            if correcting:
                runtime = self.runtimes[kwargs['thread_id']]
                assert runtime.profile == ToolProfile.READ_ONLY_REVIEW
                assert not runtime.policy.writable_paths and not runtime.policy.test_specs
                self.prompts.append(kwargs)
                expected, result = self.script.pop(0)
                assert expected == node
                return AdapterTurnResult(True, kwargs['thread_id'], 'report-only', 'completed',
                    read(json.dumps(result)), [], (), 0, None, ('turn/completed',))
            return super().run_turn(**{**kwargs, 'result_validator': read})
        except WorkflowError as error:
            return AdapterTurnResult(False, kwargs['thread_id'], 'completed-bad-output', 'completed', None,
                [], (), 0, ErrorRecord(ErrorCategory.STRUCTURED_OUTPUT_ERROR, str(error)), ('turn/completed',))


class HandoffCorrectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loommode-a5-')
        self.root = Path(self.temp.name)
        self.scenes = []

    def tearDown(self):
        evidence = os.environ.get('LOOMMODE_A5_TEST_EVIDENCE')
        if evidence:
            snapshots = []
            for scene in self.scenes:
                state = scene.engine.state
                refs = {ref for values in state.artifact_refs.values() for ref in values}
                snapshots.append({'state': state.as_dict(), 'artifacts': {ref: scene.artifacts.read(ref) for ref in refs},
                    'git_before': scene.before, 'git_after': scene.git_facts(),
                    'calls': [{'activity': item['prompt'].split('\nACTIVITY: ')[1].split('\n', 1)[0],
                               'context': item['thread_id'], 'profile': item['tool_profile'].value}
                              for item in scene.adapter.prompts],
                    'tool_audits': {ref: [a.as_dict() for a in runtime.audit_since(0)]
                                    for ref, runtime in scene.adapter.runtimes.items()}})
            target = Path(evidence) / (self._testMethodName + '.json')
            target.write_text(json.dumps({'kind': 'NO_FEE_SCRIPTED_ROLE_REAL_ENGINE_GIT_PROOF',
                'test': self.id(), 'snapshots': snapshots}, indent=2), encoding='utf-8')
        self.temp.cleanup()

    def scene(self):
        scene = NoChangeScene(self.root, adapter_type=ReplyAdapter, mixed=True)
        scene.adapter.replies = {}
        self.scenes.append(scene)
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        return scene

    def report(self):
        return response(Node.EXECUTOR_IMPLEMENT, 'REPORT_READY', evidence=PASS_EVIDENCE)

    def finding(self, node, treatment='REPORT_CORRECTION'):
        return response(node, 'HUMAN_REQUIRED', artifacts=[], escalation={
            'origin_role': 'Executor' if node == Node.INDEPENDENT_REVIEW else 'Promoter',
            'origin_activity': node.value, 'stage_id': 'FX-A1', 'task_id': 'FX-A1-A0',
            'category': 'INTERNAL_FINDING', 'reason': 'Original report lacks explanation of the fixed test result.',
            'evidence_refs': ['owner'], 'requested_treatment': treatment})

    def test_normal_and_wrapped_real_cricket_reply_reach_actual_result_gate_checkpoint(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/cricket132_completed_reply.json').read_text(encoding='utf-8'))
        parsed, _ = parse_completed_cli_result(fixture['raw'].encode(), fixture['events'])
        self.assertEqual(parsed['action'], 'REPORT_READY')
        scene = self.scene()
        scene.adapter.replies[Node.EXECUTOR_IMPLEMENT] = [fixture['raw']]
        scene.advance(Node.TASK_COMPLETE)
        state = scene.engine.state
        self.assertTrue(state.acceptance_ref)
        self.assertEqual(state.commit_receipt['staged_files'], ['calc.py'])
        raw = [scene.artifacts.read_json(ref) for ref in state.artifact_refs['ROLE_OUTPUT']]
        self.assertTrue(any((item['invocation'] or {}).get('raw_output') == fixture['raw'] for item in raw))
        self.assertFalse(any(key.startswith('report-correction') for key in state.mediation_counts))

    def test_missing_report_corrects_once_without_reexecuting_code_or_tests(self):
        scene = self.scene()
        bad = self.report(); bad['artifacts'] = []
        scene.adapter.replies[Node.EXECUTOR_IMPLEMENT] = [json.dumps(bad)]
        scene.adapter.script.insert(1, (Node.EXECUTOR_IMPLEMENT, self.report()))
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.EXECUTOR_REPORT_READY)
        writer = scene.adapter.runtimes[scene.executor.main_context]
        audit = writer.audit_since(0)
        self.assertEqual(sum(item.tool == 'loommode_replace_file' for item in audit), 1)
        self.assertEqual(sum(item.tool == 'loommode_run_test' for item in audit), 1)
        self.assertEqual(writer.phase, ToolPhase.SUSPENDED)
        self.assertEqual(scene.engine.state.mediation_counts['report-correction|FX-A1-A0|EXECUTOR_IMPLEMENT'], 1)
        scene.advance(Node.TASK_COMPLETE)

    def test_prose_only_then_failed_correction_automatically_runs_decision_no_replay(self):
        scene = self.scene()
        scene.adapter.replies[Node.EXECUTOR_IMPLEMENT] = ['Code changed; tests passed; missing control.', 'Still missing control.']
        scene.adapter.script.insert(1, (Node.EXECUTOR_IMPLEMENT, self.report()))
        decision = mediation('RETAIN_INTERNAL', handoff=json.dumps(self.report()))
        decision['mediation']['notice'] = None
        scene.adapter.script.insert(2, (Node.DECISION_MEDIATION, decision))
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.DECISION_MEDIATION)
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.EXECUTOR_IMPLEMENT)
        before = len(scene.adapter.prompts)
        scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts), before)
        self.assertEqual(scene.engine.state.current_node, Node.EXECUTOR_REPORT_READY)
        self.assertEqual(len(scene.engine.state.artifact_refs['HOST_ALLOWANCE_CONSUMPTION']), 1)
        self.assertFalse(scene.engine.state.waiting_human)
        self.assertFalse(any(scene.artifacts.read_json(ref).get('origin') == 'DECISION_OWNER_NOTICE'
            for ref in scene.engine.state.artifact_refs.get('DECISION_NOTICE', [])))
        scene.advance(Node.TASK_COMPLETE)

    def test_downstream_material_gap_returns_to_original_executor_report_only(self):
        scene = self.scene(); scene.advance(Node.PROMOTER_RESULT_REVIEW)
        original = scene.engine.state.latest_execution_report_ref
        scene.adapter.script[:0] = [(Node.PROMOTER_RESULT_REVIEW, self.finding(Node.PROMOTER_RESULT_REVIEW)),
                                   (Node.EXECUTOR_IMPLEMENT, self.report())]
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.COMMIT_AUTHORIZATION)
        self.assertNotEqual(scene.engine.state.latest_execution_report_ref, original)
        scene.artifacts.read(original)
        writer = scene.adapter.runtimes[scene.executor.main_context]
        self.assertEqual(sum(a.tool == 'loommode_run_test' for a in writer.audit_since(0)), 1)
        scene.advance(Node.TASK_COMPLETE)

    def test_repeated_downstream_gap_and_conflict_reach_decision_without_owner_notice(self):
        for repeated in (False, True):
            with self.subTest(repeated=repeated):
                self.root = Path(self.temp.name) / str(repeated)
                scene = self.scene(); scene.advance(Node.PROMOTER_RESULT_REVIEW)
                finding = self.finding(Node.PROMOTER_RESULT_REVIEW, 'REPORT_CORRECTION' if repeated else 'RETAIN_INTERNAL')
                prefix = [(Node.PROMOTER_RESULT_REVIEW, finding)]
                if repeated:
                    prefix += [(Node.EXECUTOR_IMPLEMENT, self.report()), (Node.PROMOTER_RESULT_REVIEW, copy.deepcopy(finding))]
                decision = mediation('RETAIN_INTERNAL', handoff=json.dumps(response(Node.PROMOTER_RESULT_REVIEW, 'TASK_ACCEPTED', evidence=PASS_EVIDENCE)))
                decision['mediation']['notice'] = None
                prefix += [(Node.DECISION_MEDIATION, decision)]
                scene.adapter.script[:0] = prefix
                scene.engine.step(); self.assertEqual(scene.engine.state.current_node, Node.DECISION_MEDIATION)
                scene.engine.step()
                self.assertFalse(scene.engine.state.waiting_human)
                self.assertFalse(any(scene.artifacts.read_json(ref).get('origin') == 'DECISION_OWNER_NOTICE'
                    for ref in scene.engine.state.artifact_refs.get('DECISION_NOTICE', [])))
                if repeated:
                    self.assertNotEqual(scene.engine.state.role_context_refs['Promoter'], scene.engine.state.executor_context_ref)
                    scene.adapter.script.pop(0)  # Interpreted control needs no model turn.
                scene.advance(Node.TASK_COMPLETE)

    def test_fresh_review_correction_preserves_masked_state_and_read_only_context(self):
        scene = self.scene(); scene.advance(Node.PROMOTER_RESULT_REVIEW)
        scene.adapter.script[:0] = [
            (Node.PROMOTER_RESULT_REVIEW, response(Node.PROMOTER_RESULT_REVIEW, 'REQUEST_INDEPENDENT_REVIEW')),
            (Node.INDEPENDENT_REVIEW, response(Node.INDEPENDENT_REVIEW, 'REVIEW_READY')),
            (Node.INDEPENDENT_REVIEW, response(Node.INDEPENDENT_REVIEW, 'REVIEW_READY'))]
        scene.adapter.replies[Node.INDEPENDENT_REVIEW] = ['Review done; missing control.']
        scene.engine.step(); scene.engine.step()
        correction = scene.adapter.prompts[-1]['prompt']
        state = json.loads(correction.split('\nCURRENT STATE: ')[1].split('\nEXPLICIT MATERIAL')[0])
        for field in ('last_result', 'latest_execution_report_ref', 'executor_context_ref', 'acceptance_ref'):
            self.assertIsNone(state[field], field)
        self.assertEqual(state['artifact_refs'], {})
        self.assertEqual(scene.engine.state.active_review_context_ref, scene.executor.latest_review)
        self.assertTrue(scene.executor.review_has_report)
        scene.advance(Node.TASK_COMPLETE)

    def test_unknown_effects_save_failure_without_correction_or_decision(self):
        scene = self.scene()
        with patch.object(scene.executor, 'invoke', side_effect=WorkflowError('unknown side effects')):
            with self.assertRaises(WorkflowError):
                scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.FAILED)
        self.assertEqual(scene.engine.state.in_flight_activity, Node.EXECUTOR_IMPLEMENT)
        self.assertFalse(any(k.startswith('report-correction') for k in scene.engine.state.mediation_counts))

    def test_dynamic_fact_reference_gets_one_read_only_correction_before_decision(self):
        scene = self.scene(); scene.advance(Node.PROMOTER_RESULT_REVIEW)
        node = Node.PROMOTER_RESULT_REVIEW
        bad = self.finding(node, 'SAFE_STOP')
        bad['escalation']['evidence_refs'] = ['HOST_MANAGED_FIXED_TESTS']
        corrected = copy.deepcopy(bad)
        corrected['escalation']['evidence_refs'] = [scene.engine.state.latest_execution_report_ref, 'owner']
        scene.adapter.script[:0] = [(node, bad), (node, corrected)]
        before = scene.git_facts()
        scene.engine.step()
        state = scene.engine.state
        self.assertEqual(state.current_node, Node.DECISION_MEDIATION)
        handoff = scene.artifacts.read_json(state.decision_handoff_ref)
        self.assertEqual(handoff['evidence_refs'], corrected['escalation']['evidence_refs'])
        self.assertNotIn('HOST_MANAGED_FIXED_TESTS', scene.engine.authority)
        self.assertEqual(state.mediation_counts['report-correction|FX-A1-A0|PROMOTER_RESULT_REVIEW'], 1)
        self.assertEqual(scene.git_facts(), before)
        self.assertIsNone(state.acceptance_ref)
        self.assertIsNone(state.commit_receipt)
        self.assertEqual(sum('\nACTIVITY: PROMOTER_RESULT_REVIEW\n' in p['prompt'] for p in scene.adapter.prompts), 2)

    def test_repeated_unknown_evidence_stays_bounded_and_cannot_authorize_work(self):
        scene = self.scene(); scene.advance(Node.PROMOTER_RESULT_REVIEW)
        node = Node.PROMOTER_RESULT_REVIEW
        bad = self.finding(node, 'SAFE_STOP')
        bad['escalation']['evidence_refs'] = ['HOST_MANAGED_FIXED_TESTS']
        scene.adapter.script[:0] = [(node, bad), (node, copy.deepcopy(bad)),
                                    (Node.DECISION_MEDIATION, mediation('SAFE_STOP'))]
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.DECISION_MEDIATION)
        handoff = scene.artifacts.read_json(scene.engine.state.decision_handoff_ref)
        self.assertNotIn('HOST_MANAGED_FIXED_TESTS', handoff['evidence_refs'])
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.HUMAN_BLOCK)
        self.assertIsNone(scene.engine.state.acceptance_ref)
        self.assertIsNone(scene.engine.state.commit_receipt)
        self.assertIsNone(scene.executor.checkpoint_binding)

    def test_decision_itself_gets_one_read_only_format_correction(self):
        scene = self.scene(); scene.advance(Node.PROMOTER_RESULT_REVIEW)
        scene.adapter.script.insert(0, (Node.PROMOTER_RESULT_REVIEW, self.finding(Node.PROMOTER_RESULT_REVIEW, 'RETAIN_INTERNAL')))
        scene.engine.step()
        decision = mediation('RETAIN_INTERNAL')
        decision['mediation'].update(handoff_ref=scene.engine.state.decision_handoff_ref, notice=None)
        scene.adapter.script[:0] = [(Node.DECISION_MEDIATION, copy.deepcopy(decision)), (Node.DECISION_MEDIATION, decision)]
        scene.adapter.replies[Node.DECISION_MEDIATION] = ['Decision reached; missing control.']
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.PROMOTER_RESULT_REVIEW)
        self.assertEqual(scene.engine.state.mediation_counts['report-correction|FX-A1-A0|DECISION_MEDIATION'], 1)
        scene.advance(Node.TASK_COMPLETE)

    def test_ambiguous_controls_and_duplicate_keys_are_not_accepted(self):
        report = self.report()
        for text in (json.dumps(report) * 2, '{bad' + json.dumps(report),
                     json.dumps({'data': [report]}) + json.dumps(report), '[' + json.dumps(report) + ']',
                     json.dumps(report).replace('"action":', '"action":"REPORT_READY","action":', 1)):
            with self.subTest(text=text[:40]), self.assertRaises(WorkflowError):
                parse_result(text, Node.EXECUTOR_IMPLEMENT)

    def test_decision_cannot_replay_implementation_through_other_mediation_outcomes(self):
        for outcome in ('OWNER_ATTENTION', 'REGISTER_ISSUE', 'PLANNER_ADJUSTMENT'):
            with self.subTest(outcome=outcome):
                self.root = Path(self.temp.name) / outcome
                scene = self.scene()
                scene.adapter.replies[Node.EXECUTOR_IMPLEMENT] = ['missing', 'still missing']
                scene.adapter.script.insert(1, (Node.EXECUTOR_IMPLEMENT, self.report()))
                scene.adapter.script.insert(2, (Node.DECISION_MEDIATION, mediation(outcome)))
                scene.engine.step()
                with self.assertRaises(WorkflowError):
                    scene.engine.step()
                self.assertEqual(scene.engine.state.current_node, Node.FAILED)


if __name__ == '__main__':
    unittest.main()
