"""A7 real Engine/Host evidence paths with scripted model envelopes, no model calls."""
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from loommode.tools.runtime import BoundedToolRuntime, ToolPolicy, ToolProfile
from loommode.codex.errors import ErrorCategory, ErrorRecord, LoomModeError
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node
from tests.test_native_test_receipts import ReceiptAdapter
from tests.test_no_dev_change import NoChangeScene
from tests.test_handoff_correction import ReplyAdapter
from loommode.codex.adapter import ThinCodexAdapter
from tests.workflow_support import response, PASS_EVIDENCE, mediation


class NativeContractAdapter(ReceiptAdapter):
    native_workspace_development = True


class NativeDecisionAdapter(ReplyAdapter):
    native_workspace_development = True
    task_proof = ThinCodexAdapter.task_proof

    def _runtime(self, context_ref):
        return self.runtimes[context_ref]


def prompt_materials(prompt):
    return json.JSONDecoder().raw_decode(prompt.split('\nEXPLICIT MATERIAL REFERENCES AND CONTENTS: ', 1)[1])[0]


class HostExecutionHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scene = NoChangeScene(Path(self.temp.name), native=True, adapter_type=NativeContractAdapter)

    def tearDown(self):
        destination = os.environ.get('LOOMMODE_A7_TEST_EVIDENCE')
        if destination:
            state = self.scene.engine.state
            refs = {ref for values in state.artifact_refs.values() for ref in values}
            value = {'origin':'A7_OFFLINE_SCRIPTED_ADAPTER_REAL_HOST_ENGINE_GIT_EVIDENCE',
                'test':self.id(), 'model_calls':0, 'state':state.as_dict(),
                'artifacts':{ref:self.scene.artifacts.read(ref) for ref in refs},
                'calls':[{key:call[key] for key in ('prompt','thread_id','tool_profile','model','reasoning_effort')}
                         for call in self.scene.adapter.prompts],
                'reference_lifetime':'Disposable fixture original paths are removed after capture; captured bodies are test evidence, not live Smoke receipts.'}
            (Path(destination)/(self._testMethodName+'.json')).write_text(json.dumps(value,indent=2),encoding='utf-8')

    def ready(self):
        self.scene.advance(Node.PROMOTER_RESULT_REVIEW)
        return self.scene.engine.state

    def evidence(self):
        return json.loads(self.scene.engine._materials(self.scene.engine.state, Node.PROMOTER_RESULT_REVIEW)
                          ['HOST_EXECUTOR_EXECUTION_EVIDENCE'])

    def test_actual_capabilities_reach_constraint_discussant_and_final_before_execution(self):
        self.ready()
        for node in (Node.CONSTRAINT_DRAFT, Node.DISCUSS_NORMAL, Node.CONSTRAINT_FINALIZE):
            prompt = next(p['prompt'] for p in self.scene.adapter.prompts if '\nACTIVITY: '+node.value+'\n' in p['prompt'])
            facts = json.loads(prompt_materials(prompt)['HOST_EXECUTOR_CAPABILITIES'])
            self.assertEqual(facts['task_id'], 'FX-A1-A0')
            self.assertEqual(facts['development_mode'], 'native workspace-write')
            self.assertEqual(facts['writable_paths'], ['calc.py'])
            self.assertEqual(facts['fixed_tests'][0]['test_id'], 'unit')
            self.assertIn('not the Executor policy', prompt)
            self.assertIn('capabilities never override a restriction', prompt)

    def test_new_file_inspection_limit_is_truthful_and_does_not_expand_host_grant(self):
        scene = self.scene
        policy = ToolPolicy(scene.repo, ToolProfile.BOUNDED_DEVELOPMENT,
                            ('calc.py', 'created.py'), ('created.py',))
        runtime = BoundedToolRuntime(policy)
        initial = next(t for t in runtime.dynamic_tools() if t['name'] == 'loommode_read_file')
        self.assertNotIn('created.py', initial['inputSchema']['properties']['path']['enum'])
        # Simulate an authorized native creation, not an unavailable Host create-file tool.
        (scene.repo/'created.py').write_text('def result():\n    return 7\n')
        self.assertIn('created.py', runtime.files.list_allowed()['files'])
        self.assertNotIn('created.py', initial['inputSchema']['properties']['path']['enum'])
        facts = scene.executor.execution_capabilities({'project':'FX','stage_id':'FX-A1','task_id':'FX-A1-A0'})
        self.assertIn('only if the frozen Final permits', facts['new_file_inspection'])
        self.assertEqual(runtime.files.read_text('created.py')['text'], 'def result():\n    return 7\n')
        with self.assertRaises(LoomModeError):
            runtime.files.read_text('test_calc.py')  # Existing outside this grant remains forbidden.

    def test_changed_host_capability_cannot_silently_replace_constraint_basis(self):
        scene = self.scene
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        scene.adapter.native_workspace_development = False
        count = len(scene.adapter.prompts)
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts), count)
        self.assertIsNone(scene.engine.state.acceptance_ref)

    def test_original_policy_prompt_and_adapter_fields_are_saved_and_bound_to_report(self):
        state = self.ready()
        material = self.evidence()
        evidence = material['evidence']
        original = next(p for p in self.scene.adapter.prompts if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in p['prompt'])
        self.assertEqual(evidence['prompt'], original['prompt'])
        self.assertEqual(evidence['prompt_sha256'], hashlib.sha256(original['prompt'].encode()).hexdigest())
        self.assertEqual(evidence['policy_json'], prompt_materials(original['prompt'])['HOST_EXECUTOR_POLICY'])
        self.assertEqual(evidence['binding']['intent_ref'], state.formal_task_intent_ref)
        self.assertEqual(evidence['binding']['final_ref'], state.formal_constraint_ref)
        self.assertEqual(evidence['adapter_receipt']['thread_id'], state.executor_context_ref)
        self.assertTrue(evidence['adapter_receipt']['success'])
        self.assertIn('loommode_run_test', [x['tool'] for x in evidence['adapter_receipt']['tool_audit']])
        self.assertIn('NOT_CAPTURED', evidence['native_command_bodies'])
        saved = self.scene.artifacts.read_json(material['role_output_ref'])
        self.assertEqual(saved['invocation']['host_execution_evidence'], evidence)
        self.assertEqual(json.loads(evidence['policy_json'])['fixed_tests'],
                         json.loads(self.scene.engine._materials(state, Node.PROMOTER_RESULT_REVIEW)
                                    ['HOST_NATIVE_FIXED_TESTS'])['receipt']['test_specs'])

    def test_forged_policy_prompt_receipt_binding_and_missing_owned_cache_reject(self):
        state = self.ready()
        original = self.evidence()['evidence']
        for key, value in (('policy_json','invented policy'), ('prompt','invented prompt'),
                           ('context_ref','other-context'), ('adapter_receipt',{'success':True})):
            with self.subTest(key=key), self.assertRaises(WorkflowError):
                self.scene.executor.verify_execution_evidence(state.as_dict(), state.executor_context_ref,
                                                               {**original,key:value})
        for key in ('task_id','project','stage_id','formal_task_intent_ref','formal_constraint_ref','executor_context_ref'):
            with self.subTest(state=key), self.assertRaises(WorkflowError):
                self.scene.executor.verify_execution_evidence({**state.as_dict(),key:'wrong'}, state.executor_context_ref, original)
        self.scene.executor._execution_evidence.clear()
        with self.assertRaises(WorkflowError):
            self.evidence()

    def test_promoter_and_report_only_correction_get_exact_original_policy_without_reexecution(self):
        state = self.ready()
        original = self.evidence()['evidence']
        first = self.scene.adapter.script.pop(0)
        finding = response(Node.PROMOTER_RESULT_REVIEW, 'REQUEST_DECISION', escalation={
            'origin_role':'Promoter','origin_activity':'PROMOTER_RESULT_REVIEW','stage_id':'FX-A1',
            'task_id':state.task_id,'category':'INTERNAL_FINDING','reason':'Explain original Host policy',
            'evidence_refs':['owner'],'requested_treatment':'REPORT_CORRECTION'})
        self.scene.adapter.script[:0] = [(Node.PROMOTER_RESULT_REVIEW,finding),first]
        self.scene.engine.step()
        self.assertEqual(self.scene.engine.state.current_node, 'COMMIT_AUTHORIZATION')
        self.assertEqual(self.evidence()['evidence'],original)
        corrections = [p for p in self.scene.adapter.prompts if
            self.scene.adapter.registry.get(p['thread_id']).activity_metadata.get('purpose')=='REPORT_CORRECTION']
        self.assertEqual(len(corrections),1)
        materials = prompt_materials(corrections[0]['prompt'])
        self.assertEqual(materials['HOST_EXECUTOR_POLICY'], original['policy_json'])
        self.assertIn('NOT_CAPTURED', materials['HOST_EXECUTOR_EXECUTION_EVIDENCE'])
        self.assertEqual(len([p for p in self.scene.adapter.prompts if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in p['prompt']]),2)
        self.assertEqual(len([i for r in self.scene.adapter.runtimes.values() for i in r.audit if i.tool=='loommode_run_test']),1)

    def test_fresh_reviews_do_not_receive_developer_execution_prompt_or_receipt(self):
        self.ready()
        for node in (Node.STAGE_REVIEW,Node.INDEPENDENT_REVIEW,Node.STAGE_ACCEPTANCE):
            materials = self.scene.engine._materials(self.scene.engine.state,node)
            self.assertNotIn('HOST_EXECUTOR_EXECUTION_EVIDENCE',materials)
            self.assertNotIn('HOST_EXECUTOR_POLICY',materials)
            self.assertNotIn('EXACT_HOST_PREPARED_PROMPT',json.dumps(materials))

    def test_failed_turn_preserves_original_host_evidence_without_claiming_acceptance(self):
        scene = self.scene
        original = scene.adapter.run_turn
        def failed(**kwargs):
            reply = original(**kwargs)
            if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in kwargs['prompt']:
                return replace(reply,success=False,terminal_status='failed',structured_result=None,
                    error=ErrorRecord(ErrorCategory.TURN_FAILED,'Synthetic failure after actual fixed test'))
            return reply
        scene.adapter.run_turn = failed
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        state = scene.engine.state
        output = scene.artifacts.read_json(state.artifact_refs['ROLE_OUTPUT'][-1])
        evidence = output['invocation']['host_execution_evidence']
        self.assertFalse(evidence['adapter_receipt']['success'])
        self.assertEqual(evidence['adapter_receipt']['terminal_status'],'failed')
        self.assertIn('NOT_CAPTURED',evidence['native_command_bodies'])
        self.assertIsNone(state.acceptance_ref)
        self.assertIsNone(state.latest_execution_report_ref)

    def test_decision_interpretation_preserves_original_host_facts_and_runs_no_implementation_again(self):
        self.scene = NoChangeScene(Path(self.temp.name)/'decision',native=True,adapter_type=NativeDecisionAdapter,mixed=True)
        scene = self.scene
        scene.adapter.replies = {Node.EXECUTOR_IMPLEMENT:['Missing control object.','Still missing control.']}
        scene.advance(Node.EXECUTOR_IMPLEMENT)
        report = response(Node.EXECUTOR_IMPLEMENT,'REPORT_READY',evidence=PASS_EVIDENCE)
        scene.adapter.script.insert(1,(Node.EXECUTOR_IMPLEMENT,report))
        decision = mediation('RETAIN_INTERNAL',handoff=json.dumps(report))
        decision['mediation']['notice'] = None
        scene.adapter.script.insert(2,(Node.DECISION_MEDIATION,decision))
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'DECISION_MEDIATION')
        materials = scene.engine._materials(scene.engine.state,Node.DECISION_MEDIATION)
        original = json.loads(materials['HOST_EXECUTOR_EXECUTION_EVIDENCE'])['evidence']
        scene.engine.step()
        count = len(scene.adapter.prompts)
        scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts),count)
        scene.advance(Node.PROMOTER_RESULT_REVIEW)
        self.assertEqual(self.evidence()['evidence'],original)
        self.assertEqual(len([i for r in scene.adapter.runtimes.values() for i in r.audit if i.tool=='loommode_run_test']),1)
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'COMMIT_AUTHORIZATION')

    def test_second_task_preexecution_decision_does_not_consume_previous_task_receipt(self):
        # Actual first Task Gate and local fixture checkpoint; second Task has
        # an Intent but has never executed. Its Decision receives no A0 facts.
        self.scene = NoChangeScene(Path(self.temp.name)/'second',adapter_type=ReceiptAdapter,mixed=True)
        scene = self.scene
        scene.advance(Node.TASK_COMPLETE)
        self.assertIn('FX-A1-A0',scene.engine.state.task_checkpoint_refs)
        scene.engine.step()
        scene.advance(Node.CONSTRAINT_DRAFT)
        self.assertEqual(scene.engine.state.task_id,'FX-A1-A1')
        self.assertIsNone(scene.engine.state.latest_execution_report_ref)
        self.assertTrue(scene.engine.state.artifact_refs['REPORT_RESULT'])
        original = scene.adapter.script.pop(0)
        self.assertEqual(original[0],Node.CONSTRAINT_DRAFT)
        scene.adapter.script.insert(0,(Node.CONSTRAINT_DRAFT,response(Node.CONSTRAINT_DRAFT,'HUMAN_REQUIRED',artifacts=[])))
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'DECISION_MEDIATION')
        calls = len(scene.adapter.prompts)
        scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts),calls+1)
        self.assertEqual(scene.engine.state.current_node,'HUMAN_BLOCK')
        last = prompt_materials(scene.adapter.prompts[-1]['prompt'])
        self.assertNotIn('HOST_EXECUTOR_EXECUTION_EVIDENCE',last)
        self.assertNotIn('HOST_EXECUTOR_POLICY',last)
        self.assertNotIn('FX-A1-A1',scene.executor.task_requests)

    def test_settled_task_stage_decision_does_not_require_released_executor_cache(self):
        self.scene = NoChangeScene(Path(self.temp.name)/'settled',adapter_type=ReceiptAdapter)
        scene = self.scene
        scene.advance(Node.TASK_COMPLETE)
        scene.engine.step()  # Actual after_durable cleanup.
        self.assertFalse(scene.executor.task_requests)
        self.assertFalse(scene.executor._execution_evidence)
        self.assertFalse(scene.executor._native_test_receipts)
        scene.advance(Node.STAGE_SETTLEMENT)
        self.assertTrue(scene.engine.state.artifact_refs['REPORT_RESULT'])
        original = scene.adapter.script.pop(0)
        self.assertEqual(original[0],Node.STAGE_SETTLEMENT)
        scene.adapter.script.insert(0,(Node.STAGE_SETTLEMENT,response(Node.STAGE_SETTLEMENT,'HUMAN_REQUIRED',artifacts=[])))
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'DECISION_MEDIATION')
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'HUMAN_BLOCK')
        last = prompt_materials(scene.adapter.prompts[-1]['prompt'])
        self.assertNotIn('HOST_EXECUTOR_EXECUTION_EVIDENCE',last)
        self.assertNotIn('HOST_EXECUTOR_POLICY',last)

    def test_current_report_missing_its_binding_is_rejected_not_filtered_as_history(self):
        self.ready()
        self.scene.engine.state.artifact_refs['REPORT_RESULT'] = []
        with self.assertRaisesRegex(WorkflowError,'current execution evidence lacks'):
            self.scene.engine._materials(self.scene.engine.state,Node.PROMOTER_RESULT_REVIEW)

    def test_normal_result_escalation_and_rereview_receive_original_policy_and_fixed_test_receipt(self):
        state = self.ready()
        scene = self.scene
        original = scene.engine._materials(state,Node.PROMOTER_RESULT_REVIEW)
        first = scene.adapter.script.pop(0)
        self.assertEqual(first[0],Node.PROMOTER_RESULT_REVIEW)
        chain = [
            (Node.PROMOTER_RESULT_REVIEW,response(Node.PROMOTER_RESULT_REVIEW,'REQUEST_DECISION',blocker_id='host-policy',handoff='Judge original Host policy and receipts.')),
            (Node.DISCUSSANT_DECISION_ANALYSIS,response(Node.DISCUSSANT_DECISION_ANALYSIS,'ANALYSIS_READY')),
            (Node.DECISION_REVIEW,response(Node.DECISION_REVIEW,'DECISION_READY',handoff='Original evidence must remain available.')),
            (Node.PROMOTER_IMPLEMENTATION_PLAN,response(Node.PROMOTER_IMPLEMENTATION_PLAN,'IMPLEMENTATION_PLAN_READY',handoff='Retain existing facts; no execution.')),
            (Node.DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW,response(Node.DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW,'MAJOR_DISAGREEMENT')),
            (Node.DECISION_RE_REVIEW,response(Node.DECISION_RE_REVIEW,'OWNER_REQUIRED'))]
        scene.adapter.script[:0] = chain
        scene.advance(Node.DECISION_RE_REVIEW)
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'DECISION_MEDIATION')
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node,'HUMAN_BLOCK')
        for node in [item[0] for item in chain]+[Node.DECISION_MEDIATION]:
            prompt = next(p['prompt'] for p in scene.adapter.prompts if '\nACTIVITY: '+node.value+'\n' in p['prompt'])
            supplied = prompt_materials(prompt)
            self.assertEqual(supplied['HOST_EXECUTOR_POLICY'],original['HOST_EXECUTOR_POLICY'])
            self.assertEqual(json.loads(supplied['HOST_EXECUTOR_EXECUTION_EVIDENCE']),json.loads(original['HOST_EXECUTOR_EXECUTION_EVIDENCE']))
            self.assertEqual(json.loads(supplied['HOST_NATIVE_FIXED_TESTS']),json.loads(original['HOST_NATIVE_FIXED_TESTS']))
        self.assertEqual(len([i for r in scene.adapter.runtimes.values() for i in r.audit if i.tool=='loommode_run_test']),1)
        self.assertIsNone(scene.engine.state.acceptance_ref)


if __name__=='__main__':
    unittest.main()
