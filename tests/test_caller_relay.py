"""Directed live Host/Engine/RoleRuntime relay handoff; scripted model envelopes."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from loommode.host.decision import DecisionEntry
from loommode.host.driver import DecisionHost
from loommode.roles.contracts import empty_result
from loommode.workflow.errors import WorkflowError, OutputProblem
from loommode.workflow.transitions import Node, Role
from tests.test_no_dev_change import NoChangeScene
from tests.test_caller_verification import supplied
from tests.workflow_support import mediation


class CallerRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loommode-relay-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.extra = []
        self.scene = NoChangeScene(self.root)
        self.addCleanup(self.scene.engine.close_resources)
        # Exercise production step and timers, with an explicit controlled test clock.
        self.scene.engine.step = self.scene.engine._unwrapped_step
        self.clock = 100.0
        self.callbacks = []
        def schedule(delay, callback):
            self.callbacks.append(callback)
            return SimpleNamespace(cancel=lambda: None)
        self.host = DecisionHost(DecisionEntry(self.scene.projection()), self.scene.engine,
            allow_progress=True, window_clock=lambda: self.clock,
            window_scheduler=schedule, test_window_durations=(10.0, 10.0))
        self.addCleanup(self.host.windows.close)
        self.pin = None
        self.verifier = self.host.require_caller_relay(task_id='FX-A1-A0',
            caller_id='trusted-fixture-caller', source_provider=lambda: self.pin)
        self.host.advance(4)
        self.assertEqual(self.scene.engine.state.current_node, 'SOFT_REVIEW_WAIT')
        state = self.scene.engine.state
        self.original = {'origin': 'CALLER_LOCAL_NOTICE_RELAY_CAPTURE', 'project': 'FX',
            'stage_id': 'FX-A1', 'task_id': 'FX-A1-A0', 'workspace': str(self.scene.repo.resolve()),
            'caller_id': 'trusted-fixture-caller', 'notice_ref': state.stage_notice_ref,
            'plan_ref': state.stage_plan_ref, 'decision_ref': state.stage_plan_decision_ref,
            'window': copy.deepcopy(self.host.windows.current),
            'relayed_at_utc': datetime.now(timezone.utc).isoformat(),
            'valid_until_utc': (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
            'owner_notice_relayed': True, 'owner_accepted': False}

    def tearDown(self):
        output = os.environ.get('LOOMMODE_C5_A4_TEST_EVIDENCE')
        if output:
            state = self.scene.engine.state
            refs = {r for values in state.artifact_refs.values() for r in values}
            evidence = {'origin': 'A4_SCRIPTED_ENVELOPES_PRODUCTION_HOST_ENGINE_ROLE_RUNTIME',
                'test': self.id(), 'real_product_model_calls': 0, 'state': state.as_dict(),
                'source': self.original, 'relay_verification_ref': self.verifier.receipt_ref,
                'artifacts': {r: self.scene.artifacts.read(r) for r in refs},
                'calls': [{k: c[k] for k in ('prompt','thread_id','tool_profile','model','reasoning_effort')}
                          for c in self.scene.adapter.prompts],
                'lifetime': 'Disposable synthetic fixture; captured bodies retained, paths removed after test.'}
            evidence['additional_scenarios'] = [{'state': scene.engine.state.as_dict(),
                'artifacts': {r: scene.artifacts.read(r) for refs in scene.engine.state.artifact_refs.values() for r in refs},
                'calls': [{k:c[k] for k in ('prompt','thread_id','tool_profile','model','reasoning_effort')}
                          for c in scene.adapter.prompts]} for scene in self.extra]
            (Path(output)/(self._testMethodName+'.json')).write_text(json.dumps(evidence,indent=2),encoding='utf-8')

    def publish(self, value=None):
        path = self.root/'relay-capture.json'
        path.write_text(json.dumps(self.original if value is None else value),encoding='utf-8')
        self.pin = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def capture(self):
        self.publish()
        self.host.process_windows()
        self.assertIsNotNone(self.verifier.receipt_ref)

    def expire(self):
        self.clock = 110.0
        self.callbacks[0]()
        self.host.process_windows()
        self.assertEqual(self.scene.engine.state.current_node, 'TASK_SELECTION')

    def selection(self):
        self.capture()
        self.expire()
        self.host.advance(1)

    def test_selection_and_downstream_actual_contexts_receive_lawful_evidence(self):
        self.selection()
        self.host.advance(3)
        self.assertEqual(self.scene.engine.state.current_node, 'EXECUTOR_IMPLEMENT')
        ref = self.verifier.receipt_ref
        self.assertNotIn(ref, self.scene.engine.authority)
        self.assertFalse(self.scene.engine.state.owner_accepted)
        for activity in ('TASK_SELECTION','CONSTRAINT_DRAFT','DISCUSS_NORMAL','CONSTRAINT_FINALIZE'):
            call = next(c for c in self.scene.adapter.prompts if '\nACTIVITY: '+activity+'\n' in c['prompt'])
            material = supplied(call['prompt'])
            fact = json.loads(material[self.verifier.label])
            self.assertEqual(fact['context_ref'], call['thread_id'])
            self.assertEqual(fact['verification_ref'], ref)
            self.assertEqual(material[ref], self.verifier.receipt_body)
            self.assertEqual(fact['active_task_id'], None if activity == 'TASK_SELECTION' else 'FX-A1-A0')
            self.assertNotIn('CALLER_LOCAL_NOTICE_RELAY_CAPTURE', call['prompt'])
        fresh = supplied(self.scene.adapter.prompts[0]['prompt'])
        self.assertNotIn(self.verifier.label, fresh)
        self.assertNotIn(ref, fresh)

    def finding(self, ref):
        finding = empty_result('HUMAN_REQUIRED', 'Scripted evidence citation for protected route.')
        finding['escalation'] = {'origin_role': 'Promoter', 'origin_activity': 'TASK_SELECTION',
            'stage_id': 'FX-A1', 'task_id': None, 'category': 'TRUE_UNRESOLVED_BLOCKER',
            'reason': 'Exercise original formal-ref validation and independent protected Decision route.',
            'evidence_refs': [ref], 'requested_treatment': 'SAFE_STOP'}
        return finding

    def test_registered_verification_ref_consumed_by_original_handoff_and_decision(self):
        self.capture()
        self.expire()
        finding = self.finding(self.verifier.receipt_ref)
        self.scene.adapter.script[0] = (Node.TASK_SELECTION, finding)
        self.scene.adapter.script.insert(1, (Node.DECISION_MEDIATION, mediation('SAFE_STOP')))
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node, 'DECISION_MEDIATION')
        handoff = self.scene.artifacts.read_json(self.scene.engine.state.decision_handoff_ref)
        self.assertEqual(handoff['evidence_refs'], [self.verifier.receipt_ref])
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node, 'HUMAN_BLOCK')
        call = self.scene.adapter.prompts[-1]
        material = supplied(call['prompt'])
        self.assertEqual(json.loads(material[self.verifier.label])['context_ref'], call['thread_id'])
        self.assertIn(self.verifier.receipt_ref, material)
        self.assertFalse(self.scene.engine.state.owner_accepted)

    def test_missing_source_fails_before_selection_model_call(self):
        self.expire()
        before = len(self.scene.adapter.prompts)
        with self.assertRaises(WorkflowError):
            self.host.advance(1)
        self.assertEqual(len(self.scene.adapter.prompts), before)
        self.assertEqual(self.scene.engine.state.current_node, 'FAILED')

    def test_wrong_identity_originals_window_or_boolean_refused_without_receipt(self):
        cases = [('project','OTHER'), ('stage_id','FX-A9'), ('task_id','FX-A1-A9'),
                 ('workspace',str(self.root)), ('caller_id','forged'), ('notice_ref','bad'),
                 ('plan_ref','bad'), ('decision_ref','bad'), ('owner_notice_relayed',1),
                 ('owner_accepted',True), ('origin','PLATFORM_AUTHENTICATED')]
        for key, wrong in cases:
            with self.subTest(field=key):
                self.publish({**self.original,key:wrong})
                with self.assertRaises(WorkflowError):
                    self.host.process_windows()
                self.assertIsNone(self.verifier.receipt_ref)
        for key in ('window_id','run_id','stage_epoch','notice_ref','deadline'):
            with self.subTest(window_field=key):
                window = {**self.original['window'],key:'wrong'}
                self.publish({**self.original,'window':window})
                with self.assertRaises(WorkflowError):
                    self.host.process_windows()

    def test_expired_future_or_naive_capture_refused(self):
        now = datetime.now(timezone.utc)
        for fields in ({'valid_until_utc':(now-timedelta(seconds=1)).isoformat()},
                       {'relayed_at_utc':(now+timedelta(days=1)).isoformat()},
                       {'valid_until_utc':now.replace(tzinfo=None).isoformat()}):
            self.publish({**self.original,**fields})
            with self.assertRaises(WorkflowError):
                self.host.process_windows()

    def test_source_drift_refused_before_next_actual_dispatch(self):
        self.capture()
        self.expire()
        Path(self.pin['path']).write_text('forged replacement',encoding='utf-8')
        before = len(self.scene.adapter.prompts)
        with self.assertRaises(WorkflowError):
            self.host.advance(1)
        self.assertEqual(len(self.scene.adapter.prompts),before)

    def test_saved_verification_cannot_replace_missing_original_source(self):
        self.capture()
        self.expire()
        Path(self.pin['path']).unlink()
        with self.assertRaises((WorkflowError,OSError)):
            self.host.advance(1)

    def test_runtime_expiry_rechecked_after_capture(self):
        self.capture()
        self.expire()
        class Later(datetime):
            @classmethod
            def now(cls,tz=None):
                return datetime.now(timezone.utc)+timedelta(days=1)
        with patch('loommode.host.caller_relay.datetime',Later):
            with self.assertRaises(WorkflowError):
                self.host.advance(1)

    def test_changed_state_or_window_generation_refused(self):
        self.capture()
        self.expire()
        state = self.scene.engine.state.as_dict()
        material = self.scene.engine._materials(self.scene.engine.state,Node.TASK_SELECTION)
        cases = [('stage_notice_ref','bad'), ('stage_plan_ref','bad'), ('stage_plan_decision_ref','bad'),
                 ('task_id','FX-A1-A9'), ('stage_id','FX-A2'), ('soft_window_events',[]),
                 ('human_events',[{'event':'PAUSE'}]), ('owner_window_refs',['new-input']),
                 ('artifact_refs',{})]
        for key, wrong in cases:
            with self.subTest(field=key):
                with self.assertRaises(WorkflowError):
                    self.verifier.materials({**state,key:wrong},'TASK_SELECTION',material)
        self.host.windows.next_stage()
        with self.assertRaises(WorkflowError):
            self.verifier.materials(state,'TASK_SELECTION',material)

    def test_context_spoofing_and_dynamic_alias_still_refused(self):
        self.selection()
        state = self.scene.engine.state
        materials = self.scene.engine._materials(state,Node.CONSTRAINT_DRAFT)
        roles = self.scene.engine.roles
        model, effort = roles.profiles.resolve(Node.CONSTRAINT_DRAFT)
        context = roles._context(Role.CONSTRAINT,model,effort)
        corrupted = dict(materials)
        fact = json.loads(corrupted[self.verifier.label])
        fact['context_ref'] = 'old-context'
        corrupted[self.verifier.label] = json.dumps(fact)
        with self.assertRaises(WorkflowError):
            self.verifier.bind_context(state.as_dict(),'CONSTRAINT_DRAFT',corrupted,context,self.scene.adapter.registry)
        with self.assertRaises(WorkflowError):
            self.verifier.bind_context(state.as_dict(),'CONSTRAINT_DRAFT',materials,
                roles.contexts[Role.PROMOTER],self.scene.adapter.registry)
        finding = self.finding(self.verifier.label)
        finding['escalation'].update(origin_role='Constraint', origin_activity='CONSTRAINT_DRAFT',task_id='FX-A1-A0')
        with self.assertRaises(OutputProblem):
            self.scene.engine._check_handoff(Node.CONSTRAINT_DRAFT,finding,state)

    def test_plain_authority_text_is_not_host_verification(self):
        self.scene.engine.authority['fake-relay'] = json.dumps(self.original)
        self.expire()
        with self.assertRaises(WorkflowError):
            self.host.advance(1)

    def test_requirement_cannot_be_installed_late_or_replaced(self):
        with self.assertRaises(WorkflowError):
            self.host.require_caller_relay(task_id='FX-A1-A0',caller_id='other',source_provider=lambda:None)

    def test_only_minimal_receipt_is_exposed_not_source_body(self):
        self.selection()
        receipt = json.loads(self.verifier.receipt_body)
        self.assertEqual(receipt['source_class'],'CALLER_LOCAL_CAPTURE_NOT_PLATFORM_AUTHENTICATION')
        self.assertFalse(receipt['permissions_expanded'])
        self.assertFalse(receipt['owner_accepted'])
        self.assertIn('caller-reported',receipt['limits'])
        prompt = self.scene.adapter.prompts[-1]['prompt']
        self.assertNotIn('CALLER_LOCAL_NOTICE_RELAY_CAPTURE',prompt)

    def test_actual_predeadline_admission_survives_delayed_timer_consumption(self):
        self.publish()
        self.clock = 109.0
        ref = self.host.verify_caller_relay()
        self.assertEqual(ref, self.verifier.receipt_ref)
        self.clock = 115.0
        self.callbacks[0]()
        self.host.process_windows()
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'CONSTRAINT_DRAFT')

    def test_late_first_submission_cannot_extend_actual_deadline(self):
        self.publish()
        self.clock = 110.0
        before = len(self.scene.adapter.prompts)
        with self.assertRaisesRegex(WorkflowError,'deadline'):
            self.host.verify_caller_relay()
        self.assertIsNone(self.verifier.receipt_ref)
        self.assertEqual(len(self.scene.adapter.prompts),before)
        self.assertEqual(self.scene.engine.state.current_node,'SOFT_REVIEW_WAIT')

    def test_original_reads_crossing_deadline_cannot_admit_capture(self):
        self.publish()
        original = self.scene.artifacts.read
        def crossing(ref):
            self.clock = 110.0
            return original(ref)
        with patch.object(self.scene.artifacts,'read',crossing):
            with self.assertRaises(WorkflowError):
                self.host.verify_caller_relay()
        self.assertIsNone(self.verifier.receipt_ref)

    def test_capture_predating_current_window_is_refused(self):
        self.publish({**self.original,'relayed_at_utc':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()})
        with self.assertRaisesRegex(WorkflowError,'predates'):
            self.host.verify_caller_relay()

    def test_repeated_explicit_check_revalidates_source_and_current_window(self):
        self.capture()
        self.assertEqual(self.host.verify_caller_relay(),self.verifier.receipt_ref)
        Path(self.pin['path']).write_text('changed local capture',encoding='utf-8')
        with self.assertRaises(WorkflowError):
            self.host.verify_caller_relay()

    def test_explicit_check_cannot_return_stale_ref_after_expiry(self):
        self.capture()
        self.expire()
        with self.assertRaises(WorkflowError):
            self.host.verify_caller_relay()

    def test_original_record_drift_rejected_before_dispatch(self):
        self.capture()
        self.expire()
        path = Path(self.original['plan_ref'].split('#sha256=')[0])
        original = path.read_bytes()
        try:
            path.write_text('changed plan',encoding='utf-8')
            with self.assertRaises(WorkflowError):
                self.scene.engine._materials(self.scene.engine.state,Node.TASK_SELECTION)
        finally:
            path.write_bytes(original)

    def test_report_only_correction_binds_new_actual_readonly_context(self):
        self.selection()
        state = self.scene.engine.state
        materials = self.scene.engine._materials(state,Node.CONSTRAINT_DRAFT)
        self.scene.engine.roles.correct_report(Role.CONSTRAINT,Node.CONSTRAINT_DRAFT,state.as_dict(),materials)
        call = self.scene.adapter.prompts[-1]
        projection = json.loads(supplied(call['prompt'])[self.verifier.label])
        self.assertEqual(projection['context_ref'],call['thread_id'])
        self.assertIn('Correct the report only',call['prompt'])

    def test_existing_resource_verifier_and_relay_handoff_coexist(self):
        from loommode.host.bootstrap import CallerVerification
        from tests.test_caller_verification import caller_inputs
        policy = self.scene.executor.task_policies['FX-A1-A0']
        config, sources, put = caller_inputs(self.root,self.scene.repo,policy)
        self.scene.engine.authority.update(sources)
        resource = CallerVerification(config,self.scene.engine.authority,self.scene.executor.task_policies)
        self.scene.engine.caller_verification = resource
        self.scene.engine.roles.caller_verification = resource
        self.scene.engine.roles.caller_verification_authorities = self.scene.engine.authority
        self.scene.adapter.script[0][1]['intent']['authority_refs'] += ['approved-resources','resource-supplement']
        self.selection()
        self.host.advance(1)
        material = supplied(self.scene.adapter.prompts[-1]['prompt'])
        self.assertIn('HOST_CALLER_VERIFICATION',material)
        self.assertIn(self.verifier.label,material)
        self.assertNotIn('owner-original',material)
        self.assertNotIn('HOST_ONLY_INTERNAL_PROMPT_SENTINEL',self.scene.adapter.prompts[-1]['prompt'])

    def test_source_revocation_still_blocks_executor_after_final(self):
        self.selection()
        self.host.advance(3)
        self.assertEqual(self.scene.engine.state.current_node,'EXECUTOR_IMPLEMENT')
        before = len(self.scene.adapter.prompts)
        Path(self.pin['path']).write_text('revoked capture',encoding='utf-8')
        with self.assertRaises(WorkflowError):
            self.host.advance(1)
        self.assertEqual(len(self.scene.adapter.prompts),before)

    def test_managed_joined_boundary_uses_same_live_host_verification(self):
        from loommode.host import SupervisorHost, DelegationRequest
        supervisor = SupervisorHost(self.host)
        self.addCleanup(lambda: supervisor.close(timeout=15))
        request = DelegationRequest.from_snapshot(self.host.entry.query(),'current_stage',request_id='RelayTest')
        supervisor.start(request)
        supervisor.wait_for_idle(10)
        before = len(self.scene.adapter.prompts)
        self.publish()
        ref = supervisor.verify_caller_relay()
        self.assertEqual(ref,self.verifier.receipt_ref)
        self.assertEqual(self.host.entry.query().view['issues'],[])
        self.assertEqual(len(self.scene.adapter.prompts),before)
        self.assertIsNone(supervisor.status()['facts']['managed_run']['failure'])
        # Finite caller cannot race the retained managed owner.
        with self.assertRaises(WorkflowError):
            self.host.verify_caller_relay()
        cursor = supervisor.status()['facts']['managed_run']['update_cursor']
        self.clock = 110.0
        self.callbacks[0]()
        supervisor.wait_for_update(cursor,10)
        self.assertEqual(self.scene.engine.state.current_node,'TASK_SELECTION')
        supervisor.submit(supervisor.event())
        supervisor.wait_for_idle(10)
        self.assertEqual(self.scene.engine.state.current_node,'CONSTRAINT_DRAFT')

    def initial_scene(self):
        root = self.root/('additional-'+str(len(self.extra)))
        root.mkdir()
        scene = NoChangeScene(root)
        self.extra.append(scene)
        self.addCleanup(scene.engine.close_resources)
        scene.engine.step = scene.engine._unwrapped_step
        host = DecisionHost(DecisionEntry(scene.projection()),scene.engine,allow_progress=True,
            window_clock=lambda:100.0,window_scheduler=lambda delay,callback:SimpleNamespace(cancel=lambda:None),
            test_window_durations=(10.0,10.0))
        self.addCleanup(host.windows.close)
        verifier = host.require_caller_relay(task_id='FX-A1-A0',caller_id='trusted-fixture-caller',source_provider=lambda:None)
        return scene,host,verifier

    def diagnostic(self, scene=None):
        scene = scene or self.scene
        call = scene.adapter.prompts[-1]
        self.assertIn('\nACTIVITY: DECISION_MEDIATION\n',call['prompt'])
        fact = json.loads(supplied(call['prompt'])[self.verifier.label])
        self.assertEqual(fact['context_ref'],call['thread_id'])
        return fact

    def test_pre_notice_findings_at_review_planning_and_plan_decision_reach_safe_stop(self):
        from loommode.workflow.transitions import TABLE
        for node, steps in ((Node.STAGE_REVIEW,1),(Node.STAGE_PLANNING,2),(Node.STAGE_PLAN_DECISION,3)):
            with self.subTest(origin=node.value):
                scene,host,verifier = self.initial_scene()
                host.advance(steps)
                finding = self.finding('owner')
                finding['escalation'].update(origin_role=TABLE[node][0].value,origin_activity=node.value)
                scene.adapter.script[0] = (node,finding)
                scene.adapter.script.insert(1,(Node.DECISION_MEDIATION,mediation('SAFE_STOP')))
                host.advance(1)
                self.assertEqual(scene.engine.state.current_node,'DECISION_MEDIATION')
                self.assertIsNone(scene.engine.state.stage_notice_ref)
                host.advance(1)
                self.assertEqual(scene.engine.state.current_node,'HUMAN_BLOCK')
                fact = self.diagnostic(scene)
                self.assertEqual(fact['origin_activity'],node.value)
                self.assertEqual(fact['applicability'],'NOT_REQUIRED_FOR_THIS_JUDGMENT')
                self.assertEqual(fact['verification_status'],'MISSING')
                self.assertFalse(fact['current_valid'])
                self.assertIsNone(fact['verification_ref'])

    def owner_window_adjustment(self):
        result = self.host.handle_text('DIRECTION Reconsider the actual current Stage plan.',displayed=self.host.entry.query())
        self.assertEqual(result['status'],'QUEUED_FOR_DECISION')
        self.assertEqual(self.scene.engine.state.current_node,'DECISION_MEDIATION')
        self.scene.adapter.script.insert(0,(Node.DECISION_MEDIATION,mediation('PLANNER_ADJUSTMENT')))
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'STAGE_PLANNING')
        self.assertFalse(self.scene.engine.state.owner_accepted)
        return self.diagnostic()

    def test_owner_window_input_without_relay_retains_original_decision_route(self):
        fact = self.owner_window_adjustment()
        self.assertEqual(fact['origin_activity'],'SOFT_REVIEW_WAIT')
        self.assertEqual(fact['verification_status'],'MISSING')
        self.assertFalse(fact['origin_requires_relay_for_progress'])
        self.assertFalse(fact['current_valid'])
        self.assertIsNone(fact['verification_ref'])

    def test_owner_window_input_marks_prior_relay_invalid_without_blocking_judgment(self):
        self.capture()
        fact = self.owner_window_adjustment()
        self.assertEqual(fact['verification_status'],'INVALID')
        self.assertFalse(fact['current_valid'])
        self.assertIsNone(fact['verification_ref'])
        self.assertEqual(fact['historical_verification_refs'],[self.verifier.receipt_ref])

    def prepare_relay_finding(self, *, protected=True):
        self.capture()
        self.expire()
        finding = self.finding(self.verifier.receipt_ref)
        if not protected:
            finding['escalation'].update(category='INTERNAL_FINDING',requested_treatment='RETAIN_INTERNAL')
        self.scene.adapter.script[0] = (Node.TASK_SELECTION,finding)
        self.scene.adapter.script.insert(1,(Node.DECISION_MEDIATION,mediation('SAFE_STOP' if protected else 'RETAIN_INTERNAL')))
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'DECISION_MEDIATION')

    def test_revoked_source_still_reaches_decision_safestop_with_historical_evidence(self):
        self.prepare_relay_finding()
        Path(self.pin['path']).write_text('SECRET_REVOKED_CAPTURE_BODY_SENTINEL',encoding='utf-8')
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'HUMAN_BLOCK')
        fact = self.diagnostic()
        self.assertEqual(fact['applicability'],'EXECUTION_PREREQUISITE')
        self.assertEqual(fact['verification_status'],'INVALID')
        self.assertFalse(fact['current_valid'])
        self.assertIsNone(fact['verification_ref'])
        self.assertEqual(fact['legal_evidence_refs'],[self.verifier.receipt_ref])
        self.assertNotIn('SECRET_REVOKED_CAPTURE_BODY_SENTINEL',self.scene.adapter.prompts[-1]['prompt'])

    def test_expired_source_does_not_block_decision_safestop(self):
        self.prepare_relay_finding()
        class Later(datetime):
            @classmethod
            def now(cls,tz=None):return datetime.now(timezone.utc)+timedelta(days=1)
        with patch('loommode.host.caller_relay.datetime',Later):
            self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'HUMAN_BLOCK')
        self.assertEqual(self.diagnostic()['verification_status'],'INVALID')

    def test_decision_diagnostic_never_bypasses_strict_execution_revalidation(self):
        self.prepare_relay_finding(protected=False)
        Path(self.pin['path']).write_text('revoked capture',encoding='utf-8')
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'TASK_SELECTION')
        fact = self.diagnostic()
        self.assertFalse(fact['current_valid'])
        before = len(self.scene.adapter.prompts)
        with self.assertRaises(WorkflowError):
            self.host.advance(1)
        self.assertEqual(len(self.scene.adapter.prompts),before)

    def test_forged_decision_validity_projection_is_rejected(self):
        self.prepare_relay_finding()
        state = self.scene.engine.state
        materials = self.scene.engine._materials(state,Node.DECISION_MEDIATION)
        altered = dict(materials)
        fact = json.loads(altered[self.verifier.label])
        fact.update(current_valid=True,verification_status='VALID')
        altered[self.verifier.label] = json.dumps(fact)
        roles = self.scene.engine.roles
        model,effort = roles.profiles.resolve(Node.DECISION_MEDIATION)
        context = roles._context(Role.DECISION,model,effort)
        with self.assertRaises(WorkflowError):
            self.verifier.bind_context(state.as_dict(),'DECISION_MEDIATION',altered,context,self.scene.adapter.registry)


if __name__ == '__main__':
    unittest.main()
