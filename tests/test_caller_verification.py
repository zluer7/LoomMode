"""C5 caller fact handoff through real Engine/RoleRuntime; scripted envelopes only."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from loommode.host.bootstrap import CallerVerification, inspect_config
from loommode.roles.contracts import empty_result
from loommode.workflow.errors import WorkflowError, OutputProblem
from loommode.workflow.transitions import Node, Role
from tests.test_no_dev_change import NoChangeScene
from tests import test_public_bootstrap
from tests.workflow_support import response, mediation


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def supplied(prompt):
    return json.JSONDecoder().raw_decode(prompt.split('\nEXPLICIT MATERIAL REFERENCES AND CONTENTS: ', 1)[1])[0]


def caller_inputs(root, workspace, policy, task='FX-A1-A0'):
    directory = root / 'Caller'
    directory.mkdir()
    refs = {}
    raw = {}
    def put(ref, value):
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        path = directory / (ref + '.md')
        path.write_text(text, encoding='utf-8')
        refs[ref] = {'path': str(path), 'sha256': sha(path)}
        raw[ref] = text
    identity = {'project':'FX', 'stage_id':'FX-A1', 'task_id':task,
                'workspace':str(workspace.resolve()), 'caller_id':'fixture-trusted-caller'}
    limits = {'max_run_turns':12, 'per_turn_seconds':240, 'total_seconds':7200,
              'max_additional_charge':0}
    put('owner-original', 'HOST_ONLY_FULL_OWNER_SENTINEL; explicit synthetic bounded authorization.')
    put('resource-supplement', 'Exact required supplement: only current Task scope, twelve turns, zero new direct charge; no new grant.')
    internal = directory / 'private-prepared-prompt.txt'
    internal.write_text('HOST_ONLY_INTERNAL_PROMPT_SENTINEL', encoding='utf-8')
    put('prepared-inputs', {'origin':'CALLER_PREPARATION_MANIFEST', **identity,
        'scope':list(policy.writable_paths), 'pins':{'internal-preparation':{'path':str(internal), 'sha256':sha(internal)}}})
    now = datetime.now(timezone.utc)
    put('approved-resources', {'origin':'OWNER_APPROVED_RESOURCE_AUTHORIZATION', **identity,
        'owner_source_ref':'owner-original', 'supplement_ref':'resource-supplement',
        'preparation_ref':'prepared-inputs', 'limits':limits,
        'authorized_at_utc':(now-timedelta(seconds=5)).isoformat(),
        'valid_until_utc':(now+timedelta(seconds=3600)).isoformat(),
        'route':'existing_chatgpt_subscription_codex_app_server'})
    put('caller-input', {'origin':'CALLER_VERIFICATION_INPUT', **identity,
        'resource_ref':'approved-resources', 'preparation_ref':'prepared-inputs',
        'owner_source_ref':'owner-original', 'supplement_ref':'resource-supplement',
        'approved_limits':limits, 'scope':list(policy.writable_paths)})
    return {'project':'FX', 'stage_id':'FX-A1', 'workspace':str(workspace),
            'authorities':refs, 'caller_verification_ref':'caller-input'}, raw, put


class CallerVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loommode-caller-verification-')
        self.addCleanup(self.temp.cleanup)
        self.scene = NoChangeScene(Path(self.temp.name))
        self.addCleanup(self.scene.engine.close_resources)
        policy = self.scene.executor.task_policies['FX-A1-A0']
        self.config, self.sources, self.put = caller_inputs(Path(self.temp.name), self.scene.repo, policy)
        self.put('owner', self.scene.engine.authority['owner'])
        self.scene.engine.authority.update(self.sources)
        selection = next(reply for node, reply in self.scene.adapter.script if node == Node.TASK_SELECTION)
        selection['intent']['authority_refs'] += ['approved-resources', 'resource-supplement']
        self.install()

    def install(self):
        self.scene.engine.authority.update(self.sources)
        self.verification = CallerVerification(self.config, self.scene.engine.authority,
            self.scene.executor.task_policies)
        self.scene.engine.caller_verification = self.verification
        self.scene.engine.roles.caller_verification = self.verification
        self.scene.engine.roles.caller_verification_authorities = self.scene.engine.authority

    def tearDown(self):
        output = os.environ.get('LOOMMODE_C5_A1_TEST_EVIDENCE')
        if output:
            state = self.scene.engine.state
            refs = {ref for values in state.artifact_refs.values() for ref in values}
            value = {'origin':'C5_A1_SCRIPTED_ADAPTER_REAL_ENGINE_ROLE_RUNTIME_EVIDENCE',
                'test':self.id(), 'real_product_model_calls':0, 'state':state.as_dict(),
                'artifacts':{ref:self.scene.artifacts.read(ref) for ref in refs},
                'calls':[{key:call[key] for key in ('prompt','thread_id','tool_profile','model','reasoning_effort')}
                         for call in self.scene.adapter.prompts],
                'original_test_sources':self.sources,
                'lifetime':'Disposable fixture paths are removed after capture. Captured bodies are offline test evidence, not a real Smoke or acceptance.'}
            (Path(output)/(self._testMethodName+'.json')).write_text(json.dumps(value,indent=2),encoding='utf-8')

    def draft(self):
        self.scene.advance(Node.CONSTRAINT_DRAFT)
        return self.scene.engine.state

    def rewrite(self, ref, **fields):
        value = json.loads(self.sources[ref])
        value.update(fields)
        self.put(ref, value)
        self.scene.engine.authority.update(self.sources)

    def test_actual_draft_continues_with_bound_minimal_materials(self):
        state = self.draft()
        self.scene.engine.step()
        self.assertEqual(self.scene.engine.state.current_node, 'DISCUSS_NORMAL')
        call = next(c for c in self.scene.adapter.prompts if '\nACTIVITY: CONSTRAINT_DRAFT\n' in c['prompt'])
        material = supplied(call['prompt'])
        fact = json.loads(material['HOST_CALLER_VERIFICATION'])
        self.assertEqual(fact['context_ref'], call['thread_id'])
        self.assertEqual(fact['intent_ref'], state.formal_task_intent_ref)
        self.assertEqual(fact['task_id'], 'FX-A1-A0')
        self.assertEqual(material['approved-resources'], self.sources['approved-resources'])
        self.assertEqual(material['resource-supplement'], self.sources['resource-supplement'])
        self.assertEqual(fact['legal_evidence_refs'], ['approved-resources','resource-supplement'])
        self.assertIn('DERIVED_HOST', fact['source'])
        for hidden in ('caller-input','prepared-inputs','owner-original'):
            self.assertNotIn(hidden, material)
        self.assertNotIn('HOST_ONLY_FULL_OWNER_SENTINEL', call['prompt'])
        self.assertNotIn('HOST_ONLY_INTERNAL_PROMPT_SENTINEL', call['prompt'])
        # The first fresh Stage review receives neither caller source bodies nor a caller projection.
        fresh = supplied(next(c['prompt'] for c in self.scene.adapter.prompts if '\nACTIVITY: STAGE_REVIEW\n' in c['prompt']))
        self.assertNotIn('HOST_CALLER_VERIFICATION', fresh)
        self.assertNotIn('approved-resources', fresh)
        self.assertIsNone(self.scene.engine.state.acceptance_ref)

    def test_legal_original_refs_pass_actual_handoff_and_decision_gate(self):
        self.draft()
        finding = empty_result('HUMAN_REQUIRED', 'Scripted inspection of actual supplied originals; request protected stop.')
        finding['escalation'] = {'origin_role':'Constraint','origin_activity':'CONSTRAINT_DRAFT',
            'stage_id':'FX-A1','task_id':'FX-A1-A0','category':'UPSTREAM_AUTHORITY_OR_CONTRACT',
            'reason':'Exercise legal original citation without trusting a dynamic alias.',
            'evidence_refs':['approved-resources','resource-supplement'],'requested_treatment':'SAFE_STOP'}
        self.scene.adapter.script[0] = (Node.CONSTRAINT_DRAFT, finding)
        self.scene.adapter.script.insert(1,(Node.DECISION_MEDIATION,mediation('SAFE_STOP')))
        self.scene.engine.step()
        self.assertEqual(self.scene.engine.state.current_node,'DECISION_MEDIATION')
        handoff = self.scene.artifacts.read_json(self.scene.engine.state.decision_handoff_ref)
        self.assertEqual(handoff['evidence_refs'],finding['escalation']['evidence_refs'])
        self.scene.engine.step()
        self.assertEqual(self.scene.engine.state.current_node,'HUMAN_BLOCK')
        self.assertFalse(self.scene.engine.state.owner_accepted)

    def test_required_originals_remain_available_to_executor_without_host_only_bodies(self):
        self.scene.advance(Node.EXECUTOR_IMPLEMENT)
        material = self.scene.engine._materials(self.scene.engine.state,Node.EXECUTOR_IMPLEMENT)
        self.assertEqual(material['approved-resources'],self.sources['approved-resources'])
        self.assertEqual(material['resource-supplement'],self.sources['resource-supplement'])
        self.assertNotIn('owner-original',material)
        self.assertNotIn('prepared-inputs',material)
        self.assertNotIn('HOST_CALLER_VERIFICATION',material)

    def test_dynamic_alias_is_still_rejected_by_original_validator(self):
        state = self.draft()
        finding = empty_result('HUMAN_REQUIRED')
        finding['escalation'] = {'origin_role':'Constraint','origin_activity':'CONSTRAINT_DRAFT',
            'stage_id':'FX-A1','task_id':'FX-A1-A0','category':'UPSTREAM_AUTHORITY_OR_CONTRACT',
            'reason':'Deliberate invalid dynamic alias.', 'evidence_refs':['HOST_CALLER_VERIFICATION'],
            'requested_treatment':'SAFE_STOP'}
        with self.assertRaisesRegex(OutputProblem,'dynamic Host fact'):
            self.scene.engine._check_handoff(Node.CONSTRAINT_DRAFT,finding,state)

    def test_missing_selected_source_is_rejected(self):
        del self.config['authorities']['owner-original']
        with self.assertRaises(WorkflowError):
            self.install()

    def test_forged_owner_or_preparation_bytes_fail_before_next_dispatch(self):
        self.draft()
        calls = len(self.scene.adapter.prompts)
        path = Path(self.config['authorities']['owner-original']['path'])
        path.write_text('forged replacement',encoding='utf-8')
        with self.assertRaises(WorkflowError):
            self.scene.engine.step()
        self.assertEqual(len(self.scene.adapter.prompts),calls)

    def test_wrong_identity_scope_caller_and_resource_ref_rejected(self):
        for field, wrong in [('task_id','FX-A1-A9'),('stage_id','FX-A2'),
                             ('project','OTHER'),('caller_id','forged-caller'),
                             ('owner_source_ref','resource-supplement')]:
            with self.subTest(field=field):
                original = self.sources['approved-resources']
                self.rewrite('approved-resources',**{field:wrong})
                with self.assertRaises(WorkflowError):
                    self.install()
                self.put('approved-resources',original)
        self.rewrite('caller-input',scope=['outside.py'])
        with self.assertRaises(WorkflowError):
            self.install()

    def test_over_budget_paid_route_and_boolean_amount_rejected(self):
        original = self.sources['approved-resources']
        for field, wrong in [('limits',{'max_run_turns':13,'per_turn_seconds':240,'total_seconds':7200,'max_additional_charge':0}),
                             ('limits',{'max_run_turns':12,'per_turn_seconds':240,'total_seconds':7200,'max_additional_charge':False}),
                             ('route','api_key_paid')]:
            with self.subTest(field=field,wrong=wrong):
                self.rewrite('approved-resources',**{field:wrong})
                with self.assertRaises(WorkflowError):
                    self.install()
                self.put('approved-resources',original)

    def test_expired_and_oversized_fixed_window_rejected(self):
        original = self.sources['approved-resources']
        now = datetime.now(timezone.utc)
        for end in (now-timedelta(seconds=1),now+timedelta(seconds=7201)):
            self.rewrite('approved-resources',valid_until_utc=end.isoformat())
            with self.assertRaisesRegex(WorkflowError,'fixed window'):
                self.install()
            self.put('approved-resources',original)

    def test_runtime_expiry_is_rechecked_after_admission(self):
        self.draft()
        class ExpiredClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(timezone.utc)+timedelta(days=1)
        calls = len(self.scene.adapter.prompts)
        with patch('loommode.host.bootstrap.datetime',ExpiredClock):
            with self.assertRaises(WorkflowError):
                self.scene.engine.step()
        self.assertEqual(len(self.scene.adapter.prompts),calls)
        self.assertEqual(self.scene.engine.state.current_node,'FAILED')

    def test_wrong_task_or_intent_binding_rejected(self):
        state = self.draft()
        material = self.scene.engine._materials(state,Node.CONSTRAINT_DRAFT)
        for field, wrong in [('task_id','FX-A1-A9'),('stage_id','FX-A2'),('formal_task_intent_ref','unregistered')]:
            with self.subTest(field=field):
                altered = {**state.as_dict(),field:wrong}
                with self.assertRaises(WorkflowError):
                    self.verification.materials(altered,'CONSTRAINT_DRAFT',material,self.scene.engine.authority)
        corrupted = dict(material)
        intent = json.loads(corrupted[state.formal_task_intent_ref])
        intent['scope'] = ['outside.py']
        corrupted[state.formal_task_intent_ref] = json.dumps(intent)
        with self.assertRaises(WorkflowError):
            self.verification.materials(state.as_dict(),'CONSTRAINT_DRAFT',corrupted,self.scene.engine.authority)

    def test_forged_projection_and_wrong_context_rejected(self):
        state = self.draft()
        roles = self.scene.engine.roles
        model,effort = roles.profiles.resolve(Node.CONSTRAINT_DRAFT)
        current = roles._context(Role.CONSTRAINT,model,effort)
        material = self.scene.engine._materials(state,Node.CONSTRAINT_DRAFT)
        wrong = copy.deepcopy(material)
        fact = json.loads(wrong['HOST_CALLER_VERIFICATION'])
        fact['context_ref'] = 'forged-prior-context'
        wrong['HOST_CALLER_VERIFICATION'] = json.dumps(fact)
        with self.assertRaisesRegex(WorkflowError,'forged'):
            self.verification.bind_context(state.as_dict(),'CONSTRAINT_DRAFT',wrong,self.scene.engine.authority,current,self.scene.adapter.registry)
        promoter = roles.contexts[Role.PROMOTER]
        with self.assertRaisesRegex(WorkflowError,'Context'):
            self.verification.bind_context(state.as_dict(),'CONSTRAINT_DRAFT',material,self.scene.engine.authority,promoter,self.scene.adapter.registry)

    def test_role_report_only_correction_binds_its_actual_new_context(self):
        self.draft()
        finding = empty_result('HUMAN_REQUIRED')
        finding['escalation'] = {'origin_role':'Constraint','origin_activity':'CONSTRAINT_DRAFT',
            'stage_id':'FX-A1','task_id':'FX-A1-A0','category':'UPSTREAM_AUTHORITY_OR_CONTRACT',
            'reason':'Scripted legal citation before report-only correction test.',
            'evidence_refs':['approved-resources'],'requested_treatment':'SAFE_STOP'}
        self.scene.adapter.script[0] = (Node.CONSTRAINT_DRAFT,finding)
        self.scene.adapter.script.insert(1,(Node.DECISION_MEDIATION,mediation('SAFE_STOP')))
        self.scene.engine.step()
        state = self.scene.engine.state
        material = self.scene.engine._materials(state,Node.DECISION_MEDIATION)
        self.scene.engine.roles.correct_report(Role.DECISION,Node.DECISION_MEDIATION,state.as_dict(),material)
        call = self.scene.adapter.prompts[-1]
        fact = json.loads(supplied(call['prompt'])['HOST_CALLER_VERIFICATION'])
        self.assertEqual(fact['context_ref'],call['thread_id'])
        self.assertIn('Correct the report only',call['prompt'])
        self.assertNotIn('HOST_ONLY_FULL_OWNER_SENTINEL',call['prompt'])

    def test_preparation_pin_drift_and_fake_origin_rejected(self):
        preparation = json.loads(self.sources['prepared-inputs'])
        preparation['origin'] = 'MODEL_CLAIMED_VERIFIED'
        self.put('prepared-inputs',preparation)
        with self.assertRaises(WorkflowError):
            self.install()
        preparation['origin'] = 'CALLER_PREPARATION_MANIFEST'
        self.put('prepared-inputs',preparation)
        path = Path(preparation['pins']['internal-preparation']['path'])
        path.write_text('changed original prepared bytes',encoding='utf-8')
        with self.assertRaises(WorkflowError):
            self.install()


class CallerBootstrapIntegrationTests(unittest.TestCase):
    def test_public_inspect_config_rechecks_selected_caller_sources_without_connection(self):
        fixture = test_public_bootstrap.PublicBootstrapTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        from loommode.host.bootstrap import _policy
        policy = _policy(fixture.value['policy'],fixture.workspace)
        config,sources,put = caller_inputs(fixture.root,fixture.workspace,policy,task='FX-A1-A1')
        fixture.value['authorities'].update(config['authorities'])
        fixture.value['caller_verification_ref'] = 'caller-input'
        fixture.save()
        facts = inspect_config(fixture.config,expected_sha256=sha(fixture.config))
        self.assertIsInstance(facts['caller_verification'],CallerVerification)
        Path(config['authorities']['owner-original']['path']).write_text('forged',encoding='utf-8')
        with self.assertRaises(WorkflowError):
            inspect_config(fixture.config,expected_sha256=sha(fixture.config))


if __name__ == '__main__':
    unittest.main()
