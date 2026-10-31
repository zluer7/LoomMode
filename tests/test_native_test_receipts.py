"""Owned native fixed-test receipts through real Engine persistence, no models."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from loommode.codex.adapter import AdapterTurnResult, ThinCodexAdapter
from loommode.codex.errors import ErrorCategory, ErrorRecord, LoomModeError
from loommode.tools.task_proof import HostTaskProof
from loommode.tools.test_runner import CommandResult
from loommode.workflow.allowance_history import report_unit
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node
from tests.fake_workflow_adapter import FakeWorkflowAdapter
from tests.test_no_dev_change import NoChangeScene
from tests.workflow_support import response


class ReceiptAdapter(FakeWorkflowAdapter):
    """Same actual ToolRuntime proof facade as the production Adapter."""
    task_proof = ThinCodexAdapter.task_proof

    def _runtime(self, context_ref):
        return self.runtimes[context_ref]

    def run_turn(self, **kwargs):
        record = self.registry.get(kwargs['thread_id'])
        if (record.activity_metadata or {}).get('purpose') == 'REPORT_CORRECTION':
            self.prompts.append(kwargs)
            result = kwargs['result_validator'](json.dumps(self.original_report))
            return AdapterTurnResult(True, kwargs['thread_id'], 'synthetic-report-only', 'completed',
                                     result, (), (), 0, None, ('turn/completed',))
        reply = super().run_turn(**kwargs)
        if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in kwargs['prompt']:
            self.original_report = copy.deepcopy(reply.structured_result)
        return reply


class NativeTestReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scene = NoChangeScene(self.root, adapter_type=ReceiptAdapter)

    def report_ready(self):
        self.scene.advance(Node.PROMOTER_RESULT_REVIEW)
        return self.scene.engine.state

    def material(self):
        scene = self.scene
        return json.loads(scene.engine._materials(scene.engine.state, Node.PROMOTER_RESULT_REVIEW)
                          ['HOST_NATIVE_FIXED_TESTS'])

    def test_actual_fixed_test_is_persisted_and_supplied_to_promoter(self):
        scene = self.scene
        state = self.report_ready()
        native = self.material()
        receipt = native['receipt']
        self.assertEqual(receipt['origin'], 'HOST_NATIVE_FIXED_TESTS')
        self.assertEqual(receipt['context_ref'], state.executor_context_ref)
        self.assertEqual(receipt['workspace'], str(scene.repo.resolve()))
        self.assertEqual(receipt['binding']['intent_ref'], state.formal_task_intent_ref)
        self.assertEqual(receipt['binding']['final_ref'], state.formal_constraint_ref)
        self.assertEqual(receipt['test_specs'][0]['test_id'], 'unit')
        actual = scene.adapter.task_proof(state.executor_context_ref).runtime.test_results
        self.assertEqual(receipt['tests'], actual)
        self.assertTrue(receipt['tests']['unit']['result']['passed'])
        self.assertEqual(receipt['unrun_test_ids'], [])
        output = scene.artifacts.read_json(native['role_output_ref'])
        self.assertEqual(output['invocation']['host_native_fixed_tests'], receipt)
        self.assertNotIn('host_fixed_tests', output['invocation'])
        report = {'reference': native['report_result_ref'], 'task_id': state.task_id,
                  'store_path': str(scene.store.path.resolve()), 'project': 'FX', 'stage_id': 'FX-A1'}
        self.assertEqual(report_unit(state, scene.store, scene.artifacts, report, str(scene.repo))[0], 'legacy-report')
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, 'COMMIT_AUTHORIZATION')
        prompt = next(p['prompt'] for p in scene.adapter.prompts if '\nACTIVITY: PROMOTER_RESULT_REVIEW\n' in p['prompt'])
        self.assertIn('HOST_NATIVE_FIXED_TESTS', prompt)
        prompt_materials, _ = json.JSONDecoder().raw_decode(
            prompt.split('\nEXPLICIT MATERIAL REFERENCES AND CONTENTS: ', 1)[1])
        supplied = json.loads(prompt_materials['HOST_NATIVE_FIXED_TESTS'])
        self.assertEqual(supplied['receipt']['tests'], actual)

    def test_report_correction_preserves_original_receipt_without_running_test_again(self):
        scene = self.scene
        state = self.report_ready()
        original = self.material()['receipt']
        first = scene.adapter.script.pop(0)
        self.assertEqual(first[0], Node.PROMOTER_RESULT_REVIEW)
        finding = response(Node.PROMOTER_RESULT_REVIEW, 'REQUEST_DECISION', escalation={
            'origin_role': 'Promoter', 'origin_activity': 'PROMOTER_RESULT_REVIEW',
            'stage_id': 'FX-A1', 'task_id': state.task_id, 'category': 'INTERNAL_FINDING',
            'reason': 'Explain the existing fixed-test receipt in the report.',
            'evidence_refs': ['owner'], 'requested_treatment': 'REPORT_CORRECTION'})
        scene.adapter.script[:0] = [(Node.PROMOTER_RESULT_REVIEW, finding), first]
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, 'COMMIT_AUTHORIZATION')
        self.assertEqual(self.material()['receipt'], original)
        tests = [item for runtime in scene.adapter.runtimes.values() for item in runtime.audit
                 if item.tool == 'loommode_run_test']
        self.assertEqual(len(tests), 1)
        corrections = [p for p in scene.adapter.prompts if
            scene.adapter.registry.get(p['thread_id']).activity_metadata.get('purpose') == 'REPORT_CORRECTION']
        self.assertEqual(len(corrections), 1)
        self.assertIn('HOST_NATIVE_FIXED_TESTS', corrections[0]['prompt'])
        self.assertEqual(scene.engine.state.mediation_counts['report-correction|FX-A1-A0|EXECUTOR_IMPLEMENT'], 1)

    def test_wrong_task_refs_context_and_tampered_receipt_are_rejected(self):
        scene = self.scene
        state = self.report_ready()
        receipt = self.material()['receipt']
        for field, value in [('task_id', 'FX-A1-A9'), ('project', 'OTHER'),
                             ('formal_task_intent_ref', 'wrong-intent'), ('formal_constraint_ref', 'wrong-final'),
                             ('executor_context_ref', 'wrong-context')]:
            with self.subTest(field=field), self.assertRaises(WorkflowError):
                scene.executor.verify_native_test_evidence({**state.as_dict(), field: value},
                                                          state.executor_context_ref, receipt)
        tampered = copy.deepcopy(receipt)
        tampered['tests']['unit']['result']['stdout'] = 'invented passing output'
        with self.assertRaises(WorkflowError):
            scene.executor.verify_native_test_evidence(state.as_dict(), state.executor_context_ref, tampered)
        self.assertEqual(self.material()['receipt'], receipt)

    def test_changed_live_test_receipt_is_not_replaced_by_saved_pass_claim(self):
        state = self.report_ready()
        runtime = self.scene.adapter.task_proof(state.executor_context_ref).runtime
        runtime.test_results['unit']['result']['passed'] = False
        with self.assertRaisesRegex(WorkflowError, 'changed after'):
            self.material()

    def test_missing_owned_snapshot_cannot_be_filled_from_model_or_saved_json(self):
        self.report_ready()
        self.scene.executor._native_test_receipts.clear()
        with self.assertRaisesRegex(WorkflowError, 'original evidence mismatch'):
            self.material()

    def test_missing_tests_are_explicitly_unrun_and_snapshot_is_a_copy(self):
        scene = self.scene
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        scene.engine.step()
        context = scene.executor.main_context
        runtime = scene.adapter.task_proof(context).runtime
        runtime.test_results.clear()
        receipt = HostTaskProof(runtime, context_ref=context, backend='codex_app_server').native_test_evidence(
            scene.executor.implementation_binding)
        self.assertEqual(receipt['unrun_test_ids'], ['unit'])
        self.assertEqual(receipt['tests'], {})
        receipt['tests']['unit'] = {'passed': True}
        self.assertEqual(runtime.test_results, {})

    def test_failed_truncated_timeout_and_inventory_error_are_preserved(self):
        state = self.report_ready()
        runtime = self.scene.adapter.task_proof(state.executor_context_ref).runtime
        for result in (CommandResult(1, 'actual failed test', '', 1, False, False),
                       CommandResult(0, 'bounded truncated output', '', 1, False, True),
                       CommandResult(None, '', 'actual timeout', 1, True, False)):
            with self.subTest(result=result):
                with patch.object(runtime.tests, 'run', return_value=result), patch.object(runtime.git,
                        'inventory', side_effect=LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR,
                                                              'Git inventory failed')):
                    runtime.handle_call({'tool': 'loommode_run_test', 'arguments': {'test_id': 'unit'}})
                actual = copy.deepcopy(runtime.test_results['unit'])
                self.assertEqual(actual['result'], result.as_dict())
                facts = HostTaskProof(runtime, context_ref=state.executor_context_ref,
                    backend='codex_app_server').native_test_evidence(self.scene.executor.implementation_binding)
                self.assertEqual(facts['tests']['unit'], actual)
                self.assertEqual(facts['tests']['unit']['inventory_error'], 'Git inventory failed')

    def test_failed_native_turn_keeps_actual_test_receipt_without_accepting_report(self):
        scene = self.scene
        original = scene.adapter.run_turn
        def fail_after_test(**kwargs):
            reply = original(**kwargs)
            if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in kwargs['prompt']:
                return replace(reply, success=False, terminal_status='failed', structured_result=None,
                               error=ErrorRecord(ErrorCategory.TURN_FAILED, 'Synthetic failed native turn'))
            return reply
        scene.adapter.run_turn = fail_after_test
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        state = scene.engine.state
        self.assertEqual(state.current_node, 'FAILED')
        self.assertIsNone(state.acceptance_ref)
        self.assertIsNone(state.latest_execution_report_ref)
        output = scene.artifacts.read_json(state.artifact_refs['ROLE_OUTPUT'][-1])
        self.assertEqual(output['result'], {})
        self.assertTrue(output['invocation']['host_native_fixed_tests']['tests']['unit']['result']['passed'])

    def test_fresh_review_does_not_receive_native_report_receipt(self):
        self.report_ready()
        for node in (Node.STAGE_REVIEW, Node.INDEPENDENT_REVIEW, Node.STAGE_ACCEPTANCE):
            with self.subTest(node=node):
                materials = self.scene.engine._materials(self.scene.engine.state, node)
                self.assertNotIn('HOST_NATIVE_FIXED_TESTS', materials)
                self.assertNotIn('HOST_NATIVE_FIXED_TESTS', json.dumps(materials))

    def test_original_report_output_tamper_is_rejected_before_handoff(self):
        self.report_ready()
        material = self.material()
        path = Path(material['role_output_ref'].split('#sha256=')[0])
        path.write_text('{}', encoding='utf-8')
        with self.assertRaises(WorkflowError):
            self.material()


if __name__ == '__main__':
    unittest.main()
