"""Synthetic transport/caller with actual Host/Engine/native dispatch and Git.

No app-server is connected and no product model/quota RPC is made. Pinned
durable accounting is real local fixture IO, not a real resource authorization.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time
import tempfile
import unittest
from unittest.mock import patch

from loommode.codex.adapter import AdapterTurnResult
from loommode.codex.context import ContextPurpose, FreshnessState, ResourceState
from loommode.host.bootstrap import CallerVerification
from loommode.host.decision import DecisionEntry
from loommode.host.driver import DecisionHost
from loommode.tools.runtime import ToolPhase
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node
from tests.test_caller_verification import caller_inputs, supplied
from tests.test_no_dev_change import NoChangeScene, NativeAdapter
from tests.workflow_support import response
from tests.workflow_support import normal_script


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p): return json.loads(Path(p).read_text(encoding='utf-8'))
def put(p,v):
    with Path(p).open('x',encoding='utf-8') as f:
        json.dump(v,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
    return {'path':str(p),'sha256':sha(p)}


class AdmissionAdapter(NativeAdapter):
    """Explicit synthetic adapter; original bounded runtime/TaskProof retained."""
    def __init__(self,script):
        super().__init__(script)
        self.owner_id='SYNTHETIC-NATIVE-OWNER';self._connected=True;self._closed=False
        self.usage=[True,True];self.rpc=[];self.before_context=None;self.auth='chatgpt'
        self.on_quota=None
        self.client=SimpleNamespace(request=self.quota)
    def quota(self,method,params,**kwargs):
        assert method=='account/rateLimits/read'
        assert params=={'supportsLunaReserve':False,'excludeResetCreditDetails':True}
        self.rpc.append({'method':method,'params':params})
        value=self.usage.pop(0) if self.usage else True
        if self.on_quota:self.on_quota(len(self.rpc))
        return {'ordinaryUsageAllowed':value,'RAW_ACCOUNT_SECRET':'SYNTHETIC_ACCOUNT_BODY_NOT_FOR_PROMPT'}
    def runtime_metadata(self): return {'auth_mode':self.auth}
    def start_context(self,**kwargs):
        c=super().start_context(**kwargs);record=self.registry.get(c.thread_id)
        record.owner_id=self.owner_id
        if kwargs['purpose']==ContextPurpose.DEVELOPMENT and self.before_context:self.before_context(c.thread_id)
        return c
    def run_turn(self,**kwargs):
        record=self.registry.get(kwargs['thread_id'])
        if (record.activity_metadata or {}).get('purpose')=='REPORT_CORRECTION':
            self.prompts.append(kwargs)
            result=kwargs['result_validator'](json.dumps(self.original_report))
            return AdapterTurnResult(True,kwargs['thread_id'],'synthetic-report-only','completed',result,(),(),0,None,('turn/completed',))
        reply=super().run_turn(**kwargs)
        if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in kwargs['prompt']:self.original_report=copy.deepcopy(reply.structured_result)
        return reply


class DurableCaller:
    """Fixture caller, not product accounting. Actually persists before return."""
    def __init__(self,root,resource_pin):
        self.root=root/'NativeCaller';self.root.mkdir();self.resource_pin=resource_pin
        self.ledger=self.root/'ledger.json';put(self.ledger,{'rows':[]})
        self.cap=12;self.global_cap=72;self.reserve_calls=0;self.seal_calls=0
        self.on_reserved=None;self.on_sealed=None;self.requests=[]
        self.monotonic_deadline=time.monotonic()+3600
    def check_deadline(self):
        if time.monotonic()>=self.monotonic_deadline:raise WorkflowError('synthetic original monotonic deadline exhausted')
    def save(self,v):
        temp=self.root/'owned.tmp'
        with temp.open('x',encoding='utf-8') as f:json.dump(v,f);f.flush();os.fsync(f.fileno())
        os.replace(temp,self.ledger)
    def snapshot(self,name):return put(self.root/name,load(self.ledger))
    def reserve(self,request):
        self.check_deadline()
        v=load(self.ledger)
        if len(v['rows'])>=min(self.cap,self.global_cap):raise WorkflowError('synthetic actual resource exhausted')
        if any(r['request']['reservation_id']==request['reservation_id'] for r in v['rows']):raise WorkflowError('duplicate reservation')
        self.reserve_calls+=1;self.requests.append(copy.deepcopy(request))
        v['rows'].append({'request':copy.deepcopy(request),'seal':None});self.save(v)
        evidence=self.snapshot('reserved-'+request['reservation_id']+'.json')
        receipt={'origin':'CALLER_NATIVE_DISPATCH_RESERVATION','request':copy.deepcopy(request),
            'resource_pin':self.resource_pin,'accounting_evidence_pin':evidence,
            'checks':{'reservation_consumed':True,'limits_checked':True,
                'chain_ordinal':len(v['rows']),'global_ordinal':len(v['rows']),
                'checked_at_utc':datetime.now(timezone.utc).isoformat(),'valid_until_utc':request['valid_until_utc']}}
        if self.on_reserved:self.on_reserved(receipt)
        return put(self.root/('reservation-'+request['reservation_id']+'.json'),receipt)
    def seal(self,expected):
        self.check_deadline()
        self.seal_calls+=1;v=load(self.ledger)
        matching=[r for r in v['rows'] if r['request']['reservation_id']==expected['reservation_id']]
        if len(matching)!=1 or matching[0]['seal'] is not None:raise WorkflowError('reservation absent or seal replay')
        original=next(r for r in self.requests if r['reservation_id']==expected['reservation_id'])
        if matching[0]['request']!=original:raise WorkflowError('actual ledger binding changed after reservation')
        if len(v['rows'])>min(self.cap,self.global_cap):raise WorkflowError('actual limits revoked before seal')
        matching[0]['seal']=copy.deepcopy(expected);self.save(v)
        body={**expected,'accounting_evidence_pin':self.snapshot('sealed-'+expected['reservation_id']+'.json'),
              'reservation_still_consumed':True,'limits_rechecked':True}
        if self.on_sealed:self.on_sealed(body)
        return put(self.root/('seal-'+expected['reservation_id']+'.json'),body)


class NativeExecutorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='loommode-native-admission-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.scene=NoChangeScene(self.root,native=True,adapter_type=AdmissionAdapter)
        self.addCleanup(self.scene.engine.close_resources)
        self.scene.engine.step=self.scene.engine._unwrapped_step
        policy=self.scene.executor.task_policies['FX-A1-A0']
        self.config,self.sources,self.source_put=caller_inputs(self.root,self.scene.repo,policy)
        self.source_put('owner',self.scene.engine.authority['owner'])
        self.scene.engine.authority.update(self.sources)
        selected=next(r for n,r in self.scene.adapter.script if n==Node.TASK_SELECTION)
        selected['intent']['authority_refs']+=['approved-resources','resource-supplement']
        cv=CallerVerification(self.config,self.scene.engine.authority,self.scene.executor.task_policies)
        self.scene.engine.caller_verification=self.scene.engine.roles.caller_verification=cv
        self.scene.engine.roles.caller_verification_authorities=self.scene.engine.authority
        self.clock=100.;self.callbacks=[]
        def schedule(delay,callback):self.callbacks.append(callback);return SimpleNamespace(cancel=lambda:None)
        self.host=DecisionHost(DecisionEntry(self.scene.projection()),self.scene.engine,allow_progress=True,
            window_clock=lambda:self.clock,window_scheduler=schedule,test_window_durations=(10.,10.))
        self.addCleanup(self.host.windows.close)
        self.capture_pin=None
        self.relay=self.host.require_caller_relay(task_id='FX-A1-A0',caller_id='fixture-trusted-caller',source_provider=lambda:self.capture_pin)
        self.caller=DurableCaller(self.root,self.config['authorities']['approved-resources'])
        self.admission=self.host.require_native_executor_admission(task_id='FX-A1-A0',caller_id='fixture-trusted-caller',reserve=self.caller.reserve,seal=self.caller.seal)
        self.host.advance(4);state=self.scene.engine.state
        body={'origin':'CALLER_LOCAL_NOTICE_RELAY_CAPTURE','project':'FX','stage_id':'FX-A1','task_id':'FX-A1-A0',
            'workspace':str(self.scene.repo.resolve()),'caller_id':'fixture-trusted-caller','notice_ref':state.stage_notice_ref,
            'plan_ref':state.stage_plan_ref,'decision_ref':state.stage_plan_decision_ref,'window':copy.deepcopy(self.host.windows.current),
            'relayed_at_utc':datetime.now(timezone.utc).isoformat(),'valid_until_utc':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
            'owner_notice_relayed':True,'owner_accepted':False}
        self.capture_pin=put(self.root/'relay.json',body);self.host.process_windows()
        self.clock=110.;self.callbacks[0]();self.host.process_windows();self.host.advance(4)
        self.assertEqual(self.scene.engine.state.current_node,'EXECUTOR_IMPLEMENT')
    def tearDown(self):
        output=os.environ.get('LOOMMODE_C5_A9_TEST_EVIDENCE')
        if output:
            value={'origin':'A9_SYNTHETIC_ADAPTER_REAL_HOST_NATIVE_DISPATCH_CALLER_IO','test':self.id(),
                'state':self.scene.engine.state.as_dict(),'rpc':self.scene.adapter.rpc,
                'ledger':load(self.caller.ledger),'reserve_calls':self.caller.reserve_calls,'seal_calls':self.caller.seal_calls,
                'prompts':[{k:c[k] for k in ('thread_id','prompt','model','reasoning_effort')} for c in self.scene.adapter.prompts],
                'tickets':[{k:t[k] for k in ('request','reference','sealed','dispatch_attempted')} for t in self.admission.tickets.values()],
                'real_model_turns':0,'actual_appserver_connections':0,'actual_quota_RPC':0,
                'limit':'Only synthetic transport/account/caller data; original Engine, Context registry, TaskProof, ToolRuntime and private fixture Git. No Smoke or platform authentication.'}
            Path(output,self._testMethodName+'.json').write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    def dispatch(self):self.host.advance(1)
    def executor_calls(self):return [c for c in self.scene.adapter.prompts if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in c['prompt']]
    def refuse(self):
        with self.assertRaises(Exception):self.dispatch()
        self.assertEqual(self.executor_calls(),[])
    def test_actual_native_dispatch_receives_current_minimal_facts_and_seals_original_prompt(self):
        self.dispatch();calls=self.executor_calls();self.assertEqual(len(calls),1)
        call=calls[0];m=supplied(call['prompt']);fact=json.loads(m['HOST_NATIVE_EXECUTOR_ADMISSION'])
        self.assertEqual(fact['context_ref'],call['thread_id']);self.assertTrue(fact['current_valid'])
        self.assertIn(fact['verification_ref'],m)
        self.assertEqual(json.loads(m['HOST_CALLER_RELAY_VERIFICATION'])['context_ref'],call['thread_id'])
        self.assertEqual(json.loads(m['HOST_CALLER_VERIFICATION'])['context_ref'],call['thread_id'])
        self.assertNotIn('SYNTHETIC_ACCOUNT_BODY_NOT_FOR_PROMPT',call['prompt'])
        self.assertNotIn('CALLER_LOCAL_NOTICE_RELAY_CAPTURE',call['prompt'])
        row=load(self.caller.ledger)['rows'][0]
        self.assertNotIn('prompt_sha256',row['request'])
        self.assertEqual(row['seal']['prompt_sha256'],hashlib.sha256(call['prompt'].encode()).hexdigest())
        self.assertEqual((self.caller.reserve_calls,self.caller.seal_calls,len(self.scene.adapter.rpc)),(1,1,2))
        self.assertEqual(call['deadline_seconds'],240)
        self.assertTrue(self.scene.engine.state.artifact_refs['HOST_NATIVE_EXECUTOR_ADMISSION'])
        self.assertEqual(self.scene.projection().capture().view['issues'],[])
    def test_false_or_missing_quota_refuses_before_reservation(self):
        self.scene.adapter.usage=[False];self.refuse();self.assertEqual(load(self.caller.ledger)['rows'],[])
    def test_non_boolean_quota_refused(self):self.scene.adapter.usage=[1];self.refuse()
    def test_wrong_account_route_refused(self):self.scene.adapter.auth='api';self.refuse()
    def test_actual_resource_exhaustion_refused(self):self.caller.cap=0;self.refuse()
    def test_actual_shared_resource_exhaustion_refused(self):self.caller.global_cap=0;self.refuse()
    def test_actual_monotonic_deadline_refused(self):self.caller.monotonic_deadline=0;self.refuse()
    def test_actual_monotonic_deadline_expiring_after_reservation_refuses_seal(self):
        self.caller.on_reserved=lambda r:setattr(self.caller,'monotonic_deadline',0)
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_actual_ledger_binding_drift_is_rejected_by_trusted_caller(self):
        def mutate(receipt):
            ledger=load(self.caller.ledger);ledger['rows'][0]['request']['binding']['context_ref']='old-context';self.caller.save(ledger)
        self.caller.on_reserved=mutate;self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_old_pre_prompt_usage_observation_refused_without_dispatch(self):
        import loommode.host.native_admission as native
        original=native.time.monotonic
        guard=patch.object(native.time,'monotonic',side_effect=lambda:original()+61)
        self.caller.on_reserved=lambda r:guard.start()
        try:self.refuse()
        finally:guard.stop()
        self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_same_client_replacement_before_dispatch_refused(self):
        self.caller.on_reserved=lambda r:setattr(self.scene.adapter,'client',SimpleNamespace(request=self.scene.adapter.quota))
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_dispatch_rpc_return_replacing_client_refused(self):
        def replace_client(ordinal):
            if ordinal==2:self.scene.adapter.client=SimpleNamespace(request=self.scene.adapter.quota)
        self.scene.adapter.on_quota=replace_client
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_dispatch_rpc_return_replacing_owner_refused(self):
        def replace_owner(ordinal):
            if ordinal==2:
                self.scene.adapter.owner_id='OTHER-OWNER'
                for r in self.scene.adapter.registry.all():r.owner_id='OTHER-OWNER'
        self.scene.adapter.on_quota=replace_owner
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_dispatch_rpc_return_changed_seal_source_refused_before_model(self):
        def drift(ordinal):
            if ordinal==2:
                rid=load(self.caller.ledger)['rows'][0]['request']['reservation_id']
                (self.caller.root/('seal-'+rid+'.json')).write_text('changed seal',encoding='utf-8')
        self.scene.adapter.on_quota=drift;self.refuse()
    def test_dispatch_rpc_return_changed_initial_usage_source_refused_before_model(self):
        def drift(ordinal):
            if ordinal==2:
                pin=load(self.caller.ledger)['rows'][0]['request']['quota_snapshot_pin']
                Path(pin['path']).write_text('changed raw usage',encoding='utf-8')
        self.scene.adapter.on_quota=drift;self.refuse()
    def test_dispatch_rpc_return_changed_admission_record_refused_before_model(self):
        def drift(ordinal):
            if ordinal==2:
                ticket=next(iter(self.admission.tickets.values()))
                Path(ticket['reference'].rsplit('#sha256=',1)[0]).write_text('changed admission',encoding='utf-8')
        self.scene.adapter.on_quota=drift;self.refuse()
    def test_wrong_context_purpose_refused(self):
        self.scene.adapter.before_context=lambda c:setattr(self.scene.adapter.registry.get(c),'purpose',ContextPurpose.READ_ONLY_ROLE)
        self.refuse()
    def test_wrong_context_owner_refused(self):
        self.scene.adapter.before_context=lambda c:setattr(self.scene.adapter.registry.get(c),'owner_id','OTHER')
        self.refuse()
    def test_released_context_refused(self):
        self.scene.adapter.before_context=lambda c:setattr(self.scene.adapter.registry.get(c),'resource_state',ResourceState.RELEASED)
        self.refuse()
    def test_wrong_task_binding_refused(self):
        original=self.scene.adapter.configure_task
        def wrong(c,p,**kwargs):original(c,p,**kwargs);self.scene.adapter.runtimes[c].task_binding['task_id']='OTHER'
        self.scene.adapter.configure_task=wrong;self.refuse()
    def test_wrong_reservation_binding_refused_after_consumption(self):
        self.caller.on_reserved=lambda r:r['request']['binding'].update(final_ref='forged')
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_false_caller_limit_check_refused(self):
        self.caller.on_reserved=lambda r:r['checks'].update(limits_checked=False)
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_source_drift_after_reservation_refused_without_refund(self):
        self.caller.on_reserved=lambda r:Path(self.capture_pin['path']).write_text('revoked',encoding='utf-8')
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_bad_seal_refuses_and_same_ticket_cannot_resume(self):
        self.caller.on_sealed=lambda r:r.update(prompt_sha256='0'*64)
        self.refuse();ticket=next(iter(self.admission.tickets.values()))
        self.assertTrue(ticket['dispatch_attempted']);self.assertEqual(len(load(self.caller.ledger)['rows']),1)
        with self.assertRaisesRegex(WorkflowError,'already sealed'):
            self.admission.seal_dispatch(ticket,{},'another prompt')
        self.assertEqual(self.caller.seal_calls,1)
        self.assertTrue(self.scene.engine.state.artifact_refs['HOST_NATIVE_EXECUTOR_ADMISSION'])
    def test_seal_callback_returns_changed_pin_after_durable_seal_without_refund(self):
        original=self.admission.seal
        def wrong(expected):
            pin=original(expected);return {'path':pin['path'],'sha256':'0'*64}
        self.admission.seal=wrong;self.refuse()
        ticket=next(iter(self.admission.tickets.values()))
        with self.assertRaisesRegex(WorkflowError,'already sealed'):self.admission.seal_dispatch(ticket,{},'same')
        self.assertEqual(self.caller.seal_calls,1);self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_quota_revoked_after_seal_refuses_and_cannot_resume(self):
        self.scene.adapter.usage=[True,False];self.refuse()
        ticket=next(iter(self.admission.tickets.values()));self.assertTrue(ticket['dispatch_attempted'])
        with self.assertRaisesRegex(WorkflowError,'already sealed'):self.admission.seal_dispatch(ticket,{},'same')
        self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_seal_rechecks_actual_caller_limit(self):
        self.caller.on_reserved=lambda r:setattr(self.caller,'cap',0)
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_plain_text_or_late_configuration_cannot_enable_handoff(self):
        with self.assertRaisesRegex(WorkflowError,'initial trusted Host'):
            self.host.require_native_executor_admission(task_id='FX-A1-A0',caller_id='fixture-trusted-caller',reserve='model says yes',seal=self.caller.seal)
    def test_ordinary_role_projections_stay_readonly_and_do_not_reserve(self):
        self.assertEqual(self.caller.reserve_calls,0)
        call=next(c for c in self.scene.adapter.prompts if '\nACTIVITY: CONSTRAINT_FINALIZE\n' in c['prompt'])
        m=supplied(call['prompt']);self.assertNotIn('HOST_NATIVE_EXECUTOR_ADMISSION',m)
        self.assertEqual(self.scene.adapter.registry.get(call['thread_id']).purpose,ContextPurpose.READ_ONLY_ROLE)
    def test_missing_reservation_pin_refused_after_actual_consumption(self):
        original=self.admission.reserve
        def missing(r):original(r);return None
        self.admission.reserve=missing;self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_pinned_accounting_source_drift_after_seal_refused(self):
        def drift(body):
            original=load(body['reservation_pin']['path'])
            Path(original['accounting_evidence_pin']['path']).write_text('revoked',encoding='utf-8')
        self.caller.on_sealed=drift;self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_wrong_phase_refused(self):
        original=self.scene.adapter.configure_task
        def wrong(c,p,**kw):original(c,p,**kw);self.scene.adapter.runtimes[c].phase=ToolPhase.SUSPENDED
        self.scene.adapter.configure_task=wrong;self.refuse()
    def test_wrong_freshness_refused(self):
        self.scene.adapter.before_context=lambda c:setattr(self.scene.adapter.registry.get(c),'freshness',FreshnessState.READ_ONLY_ROLE)
        self.refuse()
    def test_non_current_executor_context_refused_after_reservation(self):
        self.caller.on_reserved=lambda r:setattr(self.scene.executor,'main_context','old-context')
        self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_wrong_caller_original_resource_pin_refused(self):
        self.caller.on_reserved=lambda r:r.update(resource_pin=self.config['authorities']['caller-input'])
        self.refuse()
    def test_expired_resource_source_refused_before_model(self):
        import loommode.host.bootstrap as bootstrap
        real=bootstrap.datetime
        until=datetime.fromisoformat(load(self.config['authorities']['approved-resources']['path'])['valid_until_utc'])
        class Expired(datetime):
            @classmethod
            def now(cls,tz=None):return until+timedelta(seconds=1)
        with patch.object(bootstrap,'datetime',Expired):self.refuse()
    def test_wrong_original_final_bytes_refused_after_reservation(self):
        def drift(r):Path(r['request']['binding']['final_ref'].rsplit('#sha256=',1)[0]).write_text('changed Final',encoding='utf-8')
        self.caller.on_reserved=drift;self.refuse();self.assertEqual(len(load(self.caller.ledger)['rows']),1)
    def test_future_dated_caller_reservation_refused(self):
        self.caller.on_reserved=lambda r:r['checks'].update(checked_at_utc=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat())
        self.refuse()
    def test_duplicate_successful_ticket_cannot_dispatch_twice(self):
        self.dispatch();ticket=next(iter(self.admission.tickets.values()))
        with self.assertRaisesRegex(WorkflowError,'already sealed'):self.admission.seal_dispatch(ticket,{},'same')
        self.assertEqual(len(self.executor_calls()),1);self.assertEqual(self.caller.reserve_calls,1)
    def test_report_correction_keeps_original_admission_and_does_not_reserve_again(self):
        self.dispatch();self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'PROMOTER_RESULT_REVIEW')
        first=self.scene.adapter.script.pop(0)
        finding=response(Node.PROMOTER_RESULT_REVIEW,'REQUEST_DECISION',escalation={
            'origin_role':'Promoter','origin_activity':'PROMOTER_RESULT_REVIEW','stage_id':'FX-A1','task_id':'FX-A1-A0',
            'category':'INTERNAL_FINDING','reason':'Explain existing evidence only.','evidence_refs':['owner'],
            'requested_treatment':'REPORT_CORRECTION'})
        self.scene.adapter.script[:0]=[(Node.PROMOTER_RESULT_REVIEW,finding),first]
        self.host.advance(1)
        self.assertEqual(self.scene.engine.state.current_node,'COMMIT_AUTHORIZATION')
        self.assertEqual(self.caller.reserve_calls,1);self.assertEqual(self.caller.seal_calls,1)
        self.assertEqual(len(self.scene.adapter.rpc),2)
        self.assertEqual(len(self.executor_calls()),2)  # Original implementation plus tools-free report correction.


PUBLIC_CALLERS={}


class PublicAdmissionStopAdapter(AdmissionAdapter):
    def run_turn(self,**kwargs):
        if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' not in kwargs['prompt']:return super().run_turn(**kwargs)
        self.prompts.append(kwargs)
        m=supplied(kwargs['prompt'])
        assert json.loads(m['HOST_NATIVE_EXECUTOR_ADMISSION'])['context_ref']==kwargs['thread_id']
        report=response(Node.EXECUTOR_IMPLEMENT,'HUMAN_REQUIRED',artifacts=[{'kind':'EXECUTION_REPORT',
            'content':'Explicit synthetic transport stops after checking actual prepared admission facts. No code or tests run.'}],
            evidence={'goals_met':False,'tests_passed':False,'self_review_done':False,'nonblocking_handled':True,'report_complete':True},
            escalation={'origin_role':'Executor','origin_activity':'EXECUTOR_IMPLEMENT','stage_id':'FX-A1','task_id':'FX-A1-A0',
                'category':'TRUE_UNRESOLVED_BLOCKER','reason':'End this zero-model wiring fixture without implementation.',
                'evidence_refs':['owner'],'requested_treatment':'SAFE_STOP'})
        result=kwargs['result_validator'](json.dumps(report))
        return AdapterTurnResult(True,kwargs['thread_id'],'synthetic-public-dispatch','completed',result,(),(),0,None,('turn/completed',))


class PublicNativeAdmissionAssemblyTests(unittest.TestCase):
    def test_actual_open_canonical_public_assembly_and_native_dispatch_with_explicit_transport_double(self):
        import subprocess
        from loommode.codex.adapter import ThinCodexAdapter
        from loommode.codex.app_server import AppServerClient
        from loommode.host.canonical import open_canonical
        from loommode.host.ownership import WorkspaceLease
        from loommode.host.supervisor import SupervisorHost
        from tests.test_public_bootstrap import PublicBootstrapTests
        from tests.support import make_repo
        fixture=PublicBootstrapTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        repo=make_repo(fixture.root/'public-Git-business')
        fixture.value.update(workspace=str(repo),policy={'readable':['calc.py','test_calc.py'],'writable':['calc.py'],'tests':[]})
        fixture.value['task_policies']={'FX-A1-A0':copy.deepcopy(fixture.value['policy'])}
        fixture.value['codex']['connect_on_assembly']=False;fixture.value['grants']['allow_progress']=True
        policy=SimpleNamespace(writable_paths=('calc.py',))
        config,sources,source_put=caller_inputs(fixture.root,repo,policy)
        fixture.value['authorities'].update(config['authorities']);fixture.value['caller_verification_ref']='caller-input'
        for pin in fixture.value['roles'].values():
            Path(pin['path']).write_text('## Part I — Fixed Role Definition\nSynthetic fixture only.\n## Part II — Long-term Role Experience\nNone.\n',encoding='utf-8')
            pin['sha256']=sha(pin['path'])
        fixture.save()
        caller=DurableCaller(fixture.root,config['authorities']['approved-resources']);caller.capture_pin=None
        key=fixture.root.name;PUBLIC_CALLERS[key]=caller;self.addCleanup(PUBLIC_CALLERS.pop,key,None)
        factory=fixture.root/'Inputs/native-factory.py'
        factory.write_text('from loommode.host.bootstrap import create_host as assemble\nfrom tests.test_native_executor_admission import PUBLIC_CALLERS\n'
            +'CANONICAL_FACTORY_API=1\ndef create_host(*,canonical_context):\n'
            +f'    supervisor=assemble({str(fixture.config)!r},expected_sha256={sha(fixture.config)!r},canonical_context=canonical_context)\n'
            +f'    caller=PUBLIC_CALLERS[{key!r}]\n'
            +"    supervisor.host.require_caller_relay(task_id='FX-A1-A0',caller_id='fixture-trusted-caller',source_provider=lambda:caller.capture_pin)\n"
            +"    caller.admission=supervisor.host.require_native_executor_admission(task_id='FX-A1-A0',caller_id='fixture-trusted-caller',reserve=caller.reserve,seal=caller.seal)\n"
            +'    return supervisor\n',encoding='utf-8')
        binding={'schema_version':1,'project':'FX','stage_id':'FX-A1','workspace':str(repo),'stage_authorization_ref':'owner',
            'stage_authorization_sha256':sha(fixture.authority),'decision_role':'Decision','grants':fixture.value['grants'],
            'runtime':{'kind':'development','source_root':str(Path(__file__).resolve().parents[1]/'src'),
                'approval_ref':'Explicit A9 offline public-path synthetic transport fixture, not actual model authority'},
            'factory':{'path':str(factory),'sha256':sha(factory)}}
        def version(argv,**kw):
            self.assertEqual(argv,[str(Path(fixture.value['codex']['binary']['path']).resolve()),'--version'])
            return subprocess.CompletedProcess(argv,0,'Python '+fixture.value['codex']['supported_versions'][0]+'\n','')
        with patch.object(AppServerClient,'start',side_effect=AssertionError('no actual appserver')) as appserver, \
             patch.object(AppServerClient,'request',side_effect=AssertionError('no actual protocol/quota RPC')) as rpc, \
             patch.object(ThinCodexAdapter,'connect',side_effect=AssertionError('no actual connection')) as connect, \
             patch.object(ThinCodexAdapter,'run_turn',side_effect=AssertionError('no real product turn')) as turn:
            with patch('loommode.codex.app_server.subprocess.run',side_effect=version):client=open_canonical(binding)
            self.assertIsInstance(client.supervisor,SupervisorHost)
            host=client.supervisor.host;engine=host.engine;original=engine.executor.adapter
            original_lease=engine._workspace_writer_lease
            self.assertTrue(original_lease.held)
            script=normal_script();script[2][1]['intent']['authority_refs']+=['approved-resources','resource-supplement']
            scripted=PublicAdmissionStopAdapter(script);scripted.registry=original.registry
            engine.roles.adapter=engine.executor.adapter=scripted
            clock=[100.];callbacks=[]
            host.windows.clock=lambda:clock[0]
            def schedule(delay,callback):callbacks.append(callback);return SimpleNamespace(cancel=lambda:None)
            host.windows.scheduler=schedule
            try:
                from loommode.workflow.failure_evidence import failure_evidence
                def observe_error(exc):
                    print('SYNTHETIC_PUBLIC_FIXTURE_ORIGINAL_CAUSE: '+type(exc).__name__+': '+str(exc))
                    return failure_evidence(exc)
                with patch('loommode.workflow.engine.failure_evidence',side_effect=observe_error):host.advance(4)
                state=engine.state
                caller.capture_pin=put(fixture.root/'public-relay.json',{'origin':'CALLER_LOCAL_NOTICE_RELAY_CAPTURE',
                    'project':'FX','stage_id':'FX-A1','task_id':'FX-A1-A0','workspace':str(repo.resolve()),'caller_id':'fixture-trusted-caller',
                    'notice_ref':state.stage_notice_ref,'plan_ref':state.stage_plan_ref,'decision_ref':state.stage_plan_decision_ref,
                    'window':copy.deepcopy(host.windows.current),'relayed_at_utc':datetime.now(timezone.utc).isoformat(),
                    'valid_until_utc':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),'owner_notice_relayed':True,'owner_accepted':False})
                host.process_windows();clock[0]=1900.;callbacks[0]();host.process_windows();host.advance(5)
                self.assertEqual(engine.state.current_node,'DECISION_MEDIATION')
                calls=[c for c in scripted.prompts if '\nACTIVITY: EXECUTOR_IMPLEMENT\n' in c['prompt']]
                self.assertEqual(len(calls),1);self.assertEqual(caller.reserve_calls,1);self.assertEqual(caller.seal_calls,1)
                self.assertEqual(len(scripted.rpc),2)
                captured={'factory':factory.read_text(encoding='utf-8'),'binding':binding,'actual_grant':engine.grant().as_dict(),
                    'actual_registered_type':type(client.supervisor).__name__,'actual_host_type':type(host).__name__,
                    'prepared_native_prompt':calls[0]['prompt'],'actual_context':scripted.registry.get(calls[0]['thread_id']).as_dict(),
                    'caller_ledger':load(caller.ledger),'clock':'Explicit synthetic monotonic window fixture, not a real 1800-second Smoke.'}
            finally:
                # Dispose only the explicit transport double's metadata. Restore
                # and close the original unconnected production Adapter through
                # the original canonical owner; no fake OS exit receipt is used.
                for record in scripted.registry.all():
                    if record.owner_id==scripted.owner_id:
                        scripted.registry.resource(record.thread_id,ResourceState.RELEASED,
                            receipt={'proof':'SYNTHETIC_NO_PROCESS_FIXTURE_DISPOSAL'})
                engine.roles.adapter=engine.executor.adapter=original
                client.owner.close()
            self.assertTrue(engine._resources_closed);self.assertTrue(original._closed)
            self.assertFalse(original_lease.held)
            lease=WorkspaceLease(repo);self.assertTrue(lease.acquire());lease.release()
            self.assertEqual([appserver.call_count,rpc.call_count,connect.call_count,turn.call_count],[0,0,0,0])
            output=os.environ.get('LOOMMODE_C5_A9_TEST_EVIDENCE')
            if output:
                captured.update(origin='A9_ACTUAL_PUBLIC_CANONICAL_ASSEMBLY_NATIVE_DISPATCH_SYNTHETIC_TRANSPORT',
                    original_adapter_close=original.close_receipt,original_owner_diagnostic=client.owner.diagnostic(),
                    actual_lease_reacquired_released=True,actual_appserver_connections=0,actual_quota_RPC=0,real_model_turns=0,
                    limits='Actual public factory/assembly/registered Supervisor/Engine/Executor and Writer/Grant checks. Explicitly substituted synthetic adapter/registry transport observations for offline dispatch, then disposed them; original unconnected production Adapter closed normally. No actual CLI compatibility/auth/quota/Smoke or native process exit claim.')
                Path(output,self._testMethodName+'.json').write_text(json.dumps(captured,ensure_ascii=False,indent=2),encoding='utf-8')


if __name__=='__main__':unittest.main()
