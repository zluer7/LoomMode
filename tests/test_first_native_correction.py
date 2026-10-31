"""First native report correction: real Engine/tools/proof, scripted AI, no models."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from loommode.codex.adapter import AdapterTurnResult
from loommode.codex.errors import ErrorCategory, ErrorRecord, LoomModeError
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node
from tests.test_native_test_receipts import ReceiptAdapter
from tests.test_no_dev_change import NoChangeScene


class FirstBadAdapter(ReceiptAdapter):
    bad_mode = 'schema'
    first_bad = True

    def run_turn(self, **kwargs):
        correcting = self.registry.get(kwargs['thread_id']).activity_metadata.get('purpose') == 'REPORT_CORRECTION'
        implementing = '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in kwargs['prompt']
        if implementing and not correcting and self.first_bad:
            self.first_bad = False
            validator = kwargs['result_validator']
            valid = []
            def bad(raw):
                self.original_report = json.loads(raw)
                valid.append(copy.deepcopy(self.original_report))
                if self.bad_mode == 'schema':
                    return validator('{"action":"REPORT_READY"}')
                result = json.loads(raw)
                result.update(action='HUMAN_REQUIRED', escalation={
                    'origin_role': 'Executor', 'origin_activity': 'EXECUTOR_IMPLEMENT',
                    'stage_id': 'FX-A1', 'task_id': 'FX-A1-A0', 'category': 'INTERNAL_FINDING',
                    'reason': 'Original report reference needs correction.',
                    'evidence_refs': ['tool chunk is not a formal reference'], 'requested_treatment': 'SAFE_STOP'})
                return validator(json.dumps(result))
            try:
                reply = super().run_turn(**{**kwargs, 'result_validator': bad})
                self.original_report = valid[-1]
                return reply
            except WorkflowError as error:
                return AdapterTurnResult(False, kwargs['thread_id'], 'completed-bad-schema', 'completed', None,
                    (), (), 0, ErrorRecord(ErrorCategory.STRUCTURED_OUTPUT_ERROR, str(error)), ('turn/completed',))
        return super().run_turn(**kwargs)


class FirstNativeCorrectionTests(unittest.TestCase):
    def scene(self, mode='schema'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        scene = NoChangeScene(Path(temp.name), adapter_type=FirstBadAdapter, mixed=True)
        scene.adapter.bad_mode = mode
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        return scene

    def corrections(self, scene):
        return [p for p in scene.adapter.prompts if scene.adapter.registry.get(p['thread_id']).activity_metadata.get('purpose') == 'REPORT_CORRECTION']

    def test_first_schema_and_handoff_reference_failures_correct_once_without_reexecution(self):
        for mode in ('schema', 'references'):
            with self.subTest(mode=mode):
                scene = self.scene(mode)
                public_verify = scene.executor.verify_native_test_evidence
                old_failure_checked = []
                def verify(local_state, context, receipt):
                    self.assertIsNone(scene.engine.state.executor_context_ref)
                    self.assertIsNone(scene.engine.state.latest_execution_report_ref)
                    with self.assertRaises(WorkflowError):
                        public_verify({**local_state, 'executor_context_ref': None}, context, receipt)
                    old_failure_checked.append(True)
                    return public_verify(local_state, context, receipt)
                with patch.object(scene.executor, 'verify_native_test_evidence', side_effect=verify):
                    scene.engine.step()
                self.assertTrue(old_failure_checked)
                self.assertEqual(scene.engine.state.current_node, 'EXECUTOR_REPORT_READY')
                corrections = self.corrections(scene)
                self.assertEqual(len(corrections), 1)
                prompt = corrections[0]['prompt']
                materials, _ = json.JSONDecoder().raw_decode(prompt.split('\nEXPLICIT MATERIAL REFERENCES AND CONTENTS: ', 1)[1])
                ref = materials['HOST_ORIGINAL_ROLE_OUTPUT_REF']
                original = scene.artifacts.read_json(ref)
                self.assertEqual(json.loads(materials[ref]), original)
                self.assertIn(ref, json.loads(materials['HOST_REPORT_CORRECTION_EVIDENCE_REFS']))
                facts = json.loads(materials['HOST_NATIVE_FIXED_TESTS'])['receipt']
                self.assertEqual(facts, original['invocation']['host_native_fixed_tests'])
                audits = [a for runtime in scene.adapter.runtimes.values() for a in runtime.audit]
                self.assertEqual(sum(a.tool == 'loommode_replace_file' for a in audits), 1)
                self.assertEqual(sum(a.tool == 'loommode_run_test' for a in audits), 1)
                runtime = scene.adapter.runtimes[corrections[0]['thread_id']]
                self.assertFalse(runtime.policy.writable_paths)
                self.assertFalse(runtime.policy.test_specs)
                self.assertEqual(scene.engine.state.mediation_counts['report-correction|FX-A1-A0|EXECUTOR_IMPLEMENT'], 1)
                scene.advance(Node.PROMOTER_RESULT_REVIEW)
                self.assertEqual(json.loads(scene.engine._materials(scene.engine.state, Node.PROMOTER_RESULT_REVIEW)['HOST_NATIVE_FIXED_TESTS'])['receipt'], facts)
                scene.engine.step()
                self.assertEqual(scene.engine.state.current_node, 'COMMIT_AUTHORIZATION')

    def test_invalid_binding_cache_output_and_live_proof_reject_before_correction_call(self):
        for fault in ('context', 'task', 'intent', 'final', 'cache', 'receipt', 'origin', 'live_nonce', 'output', 'raw'):
            with self.subTest(fault=fault):
                scene = self.scene()
                correction = scene.engine._correction
                def corrupt(state, node, materials, problem, override=None, **kwargs):
                    call = kwargs['call_state']
                    if fault in {'context', 'task', 'intent', 'final'}:
                        field = {'context':'executor_context_ref', 'task':'task_id',
                                 'intent':'formal_task_intent_ref', 'final':'formal_constraint_ref'}[fault]
                        kwargs['call_state'] = {**call, field: 'wrong'}
                    elif fault == 'cache':
                        scene.executor._native_test_receipts.clear()
                    elif fault in {'receipt', 'origin'}:
                        saved = scene.executor._native_test_receipts[state.task_id]
                        saved['origin' if fault == 'origin' else 'workspace'] = 'forged'
                    elif fault == 'live_nonce':
                        scene.adapter.runtimes[scene.executor.main_context].task_binding['nonce'] = 'changed'
                    elif fault == 'raw':
                        problem.raw = 'another rejected output'
                    else:
                        kwargs['original_output_ref'] = 'unregistered-output#sha256=' + '0'*64
                    return correction(state, node, materials, problem, override, **kwargs)
                with patch.object(scene.engine, '_correction', side_effect=corrupt):
                    with self.assertRaises((WorkflowError, LoomModeError)):
                        scene.engine.step()
                self.assertEqual(self.corrections(scene), [])
                self.assertIsNone(scene.engine.state.acceptance_ref)
                self.assertIsNone(scene.engine.state.latest_execution_report_ref)
                self.assertEqual(scene.engine.state.mediation_counts['report-correction|FX-A1-A0|EXECUTOR_IMPLEMENT'], 1)


if __name__ == '__main__':
    unittest.main()
