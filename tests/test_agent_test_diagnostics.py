"""In-process deadline/late/missing reply and delivered-layout regressions.

No child process, real Codex/discovery/provider/network or inherited evidence is
executed. Original transport methods run through explicit in-process doubles.
"""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from loommode.codex.app_server import AppServerClient
from loommode.codex.adapter import ThinCodexAdapter
from loommode.codex.context import ContextPurpose
from loommode.codex.errors import ErrorCategory,LoomModeError
from loommode.tools.filesystem import WorkspaceGuard
from loommode.tools.runtime import ToolPolicy,ToolProfile,BoundedToolRuntime
from loommode.workflow.failure_evidence import safe_observation

# Capture the actual method before the outer verifier blocks class-level live
# transport calls. This client is never started; request/cleanup are local doubles.
TRANSPORT_TURN=AppServerClient.run_turn


class AgentTestDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def client(self):
        client=AppServerClient(('in-process-no-executable',),self.root)
        cleanup=[]
        def close():
            cleanup.append(True)
            client.close_receipt={'released':True,'proof':'EXPLICIT_IN_PROCESS_DOUBLE_NO_PROCESS'}
        client._cleanup_process=close
        return client,cleanup

    def call(self,client,duration=.02):
        return TRANSPORT_TURN(client,thread_id='thread',prompt='SYNTHETIC_SECRET_NOT_IN_DIAGNOSTICS',
                              model='fixture',effort='low',output_schema={},deadline_seconds=duration)

    def test_completed_matching_reply_is_still_a_success(self):
        client,cleanup=self.client()
        def request(method,params,timeout):
            self.assertEqual(method,'turn/start');self.assertLessEqual(timeout,.2)
            client._turn_state.start_sent=True
            client.messages.put({'method':'turn/completed','params':{'threadId':'thread',
                'turn':{'id':'turn','status':'completed','items':[{'type':'agentMessage','text':'{}'}]}}})
            return {'turn':{'id':'turn'}}
        client.request=request
        result=self.call(client,.2)
        self.assertEqual(result.terminal.status,'completed')
        self.assertIsNone(client.last_turn_diagnostics);self.assertEqual(cleanup,[])

    def test_missing_start_ack_keeps_unknown_and_marks_exact_wait_phase(self):
        client,cleanup=self.client()
        def request(*args,**kwargs):
            client._turn_state.start_sent=True
            raise LoomModeError(ErrorCategory.DEADLINE_EXCEEDED,'synthetic missing acknowledgement')
        client.request=request
        with self.assertRaises(LoomModeError):self.call(client)
        diag=client.last_turn_diagnostics
        self.assertEqual(diag['effect'],'UNKNOWN_EFFECT');self.assertFalse(diag['automatic_replay'])
        self.assertEqual(diag['transport_timing']['wait_phase'],'TURN_START_RESPONSE')
        self.assertFalse(diag['transport_timing']['turn_start_acknowledged'])
        self.assertTrue(diag['transport_timing']['turn_start_sent_or_uncertain'])
        self.assertEqual(len(cleanup),1)
        with self.assertRaises(LoomModeError):self.call(client)
        self.assertEqual(len(cleanup),1)  # Poisoned transport cannot dispatch again.

    def test_ack_without_terminal_and_late_completion_never_become_pass(self):
        for late in (False,True):
            with self.subTest(late=late):
                client,cleanup=self.client()
                def request(*args,**kwargs):
                    client._turn_state.start_sent=True
                    return {'turn':{'id':'turn'}}
                client.request=request
                if late:
                    def wait(**kwargs):
                        client._event({'method':'turn/completed','params':{'threadId':'thread',
                            'turn':{'id':'turn','status':'completed'}}})
                        raise LoomModeError(ErrorCategory.DEADLINE_EXCEEDED,'synthetic late completion')
                    client._wait_for_turn=wait
                with self.assertRaises(LoomModeError):self.call(client)
                diag=client.last_turn_diagnostics
                self.assertEqual(diag['transport_timing']['wait_phase'],'MATCHING_TERMINAL')
                self.assertTrue(diag['transport_timing']['turn_start_acknowledged'])
                self.assertAlmostEqual(diag['transport_timing']['deadline_seconds'],.02,places=4)
                self.assertGreaterEqual(diag['transport_timing']['elapsed_before_diagnosis_ms'],0)
                self.assertEqual(diag['effect'],'UNKNOWN_EFFECT');self.assertFalse(diag['automatic_replay'])
                self.assertEqual(bool(diag['terminal_evidence']),late)
                self.assertEqual(len(cleanup),1)
                self.assertNotIn('SYNTHETIC_SECRET_NOT_IN_DIAGNOSTICS',json.dumps(diag))

    def test_adapter_forwards_explicit_deadline_and_safe_diagnostics(self):
        from tests.support import make_repo
        workspace=make_repo(self.root/'repo')
        for explicit,expected in ((240,240),(None,420)):
            with self.subTest(explicit=explicit):
                client,_=self.client()
                client.process=SimpleNamespace(poll=lambda:None)
                adapter=ThinCodexAdapter(client=client,workspace_guard=WorkspaceGuard((self.root,)))
                adapter._connected=True;adapter._models={'fixture':{'low'}}
                policy=ToolPolicy(workspace,ToolProfile.READ_ONLY_REVIEW,())
                adapter.registry.create(thread_id='thread',purpose=ContextPurpose.READ_ONLY_ROLE,workspace=workspace,
                    model='fixture',reasoning_effort='low',tool_profile=policy.profile.value,
                    codex_version='in-process-fixture',owner_id=adapter.owner_id)
                adapter._owned.add('thread');adapter._runtimes['thread']=BoundedToolRuntime(policy)
                timing={'wait_phase':'MATCHING_TERMINAL','deadline_seconds':expected,
                        'elapsed_before_diagnosis_ms':1,'turn_start_sent_or_uncertain':True,'turn_start_acknowledged':True}
                def fail(**kwargs):
                    self.assertEqual(kwargs['deadline_seconds'],expected)
                    client.last_turn_diagnostics={'thread_id':'thread','turn_id':'turn','transport_timing':timing}
                    raise LoomModeError(ErrorCategory.DEADLINE_EXCEEDED,'synthetic deadline')
                client.run_turn=fail
                result=adapter.run_turn(thread_id='thread',prompt='synthetic',model='fixture',reasoning_effort='low',
                                        tool_profile=policy.profile,deadline_seconds=explicit)
                self.assertFalse(result.success)
                self.assertEqual(result.error.category,ErrorCategory.DEADLINE_EXCEEDED)
                self.assertEqual(safe_observation(adapter.last_safe_observation)['transport_timing'],timing)

    def test_safe_timing_rejects_arbitrary_text_nonfinite_and_wrong_types(self):
        timing={'wait_phase':'MATCHING_TERMINAL','deadline_seconds':240,
                'elapsed_before_diagnosis_ms':10,'turn_start_sent_or_uncertain':True,'turn_start_acknowledged':True}
        self.assertEqual(safe_observation({'transport_timing':timing})['transport_timing'],timing)
        for value in ({**timing,'wait_phase':'secret endpoint'}, {**timing,'deadline_seconds':float('inf')},
                      {**timing,'wait_phase':[]},
                      {**timing,'deadline_seconds':True},{**timing,'extra':'secret'},
                      {**timing,'turn_start_acknowledged':'true'}):
            self.assertNotIn('transport_timing',safe_observation({'transport_timing':value}))

    def test_failure_timing_reaches_durable_original_host_receipt(self):
        from tests.workflow_support import make_engine
        from loommode.roles.runtime import run_handoff
        from loommode.codex.adapter import AdapterTurnResult
        from loommode.workflow.errors import WorkflowError
        from loommode.workflow.transitions import Node
        engine,participants=make_engine(self.root/'engine',[],grant=False)
        self.addCleanup(engine._test_windows.close)
        timing={'wait_phase':'MATCHING_TERMINAL','deadline_seconds':240,
                'elapsed_before_diagnosis_ms':240001,'turn_start_sent_or_uncertain':True,'turn_start_acknowledged':True}
        secret='SYNTHETIC_SECRET_MUST_NOT_REACH_HOST'
        error=LoomModeError(ErrorCategory.DEADLINE_EXCEEDED,secret,details={'stderr':secret}).record
        reply=AdapterTurnResult(False,'thread','turn','deadline_exceeded',None,(),(),240001,error,())
        adapter=SimpleNamespace(run_turn=lambda **kw:reply,last_safe_observation={
            'stage':'transport','category':'DEADLINE_EXCEEDED','transport_timing':timing,'stderr':secret})
        engine._unwrapped_step()
        def fail(*args):return run_handoff(adapter,node=Node.STAGE_REVIEW,state=engine.state.as_dict())
        participants.invoke=fail
        with self.assertRaises(WorkflowError):engine._unwrapped_step()
        reference=engine.state.artifact_refs['HOST_STAGE_FAILURE'][-1]
        saved=engine.artifacts.read_json(reference)
        self.assertEqual(saved['observation']['transport_timing'],timing)
        self.assertEqual(engine.state.current_node,'FAILED')
        self.assertEqual(engine.state.in_flight_activity,'STAGE_REVIEW')
        self.assertEqual(json.loads(engine.store.path.read_text())['last_result']['safe_observation']['transport_timing'],timing)
        self.assertNotIn(secret,engine.artifacts.read(reference))

    def test_caller_clamps_turn_and_global_deadlines_without_refund(self):
        import time
        from tests.test_agent_test_package import AgentTestPackageTests
        case=AgentTestPackageTests();self.addCleanup(case.doCleanups)
        fixture,caller,original=case.caller_scene()
        reference=next(ref for ref,record in fixture.scene.adapter.registry._records.items()
                       if record.resource_state.value in {'ACTIVE','RETAINED'})
        caller.monotonic_deadline=time.monotonic()+123
        captured=[]
        def capture(**kwargs):captured.append(kwargs);return 'in-process-only'
        caller.run_turn(capture,thread_id=reference,prompt='ordinary budget fixture')
        caller.run_turn(capture,thread_id=reference,prompt='ordinary budget fixture',deadline_seconds=90)
        self.assertLessEqual(captured[0]['deadline_seconds'],123)
        self.assertGreater(captured[0]['deadline_seconds'],0)
        self.assertLessEqual(captured[1]['deadline_seconds'],90)
        self.assertEqual(caller.resource['limits']['per_turn_seconds'],240)
        self.assertEqual([r['kind'] for r in caller.events()],['reserve','claim','reserve','claim'])

    def test_delivered_layout_positive_selection_and_original_refusals(self):
        from tools.agent_test_package import prepare,build
        root=Path(__file__).resolve().parents[1]
        spec=json.loads((root/'config/agent_test_package.json').read_text())
        delivered=self.root/'delivered';delivered.mkdir()
        for row in spec['files']:
            origin=root/row['source']
            if not origin.exists():origin=root/row['target']
            output=delivered/row['target'];output.parent.mkdir(parents=True,exist_ok=True)
            output.write_bytes(origin.read_bytes())
            row['source']=row['target']
        path=self.root/'delivered.json';path.write_text(json.dumps(spec),encoding='utf-8')
        selected=prepare(delivered,path)
        self.assertEqual(set(selected),{r['target'] for r in spec['files']})
        self.assertEqual(selected['README.md'][0],(delivered/'README.md').read_bytes())
        conflict=copy.deepcopy(spec);conflict['files'].append({'source':'pyproject.toml','target':'PYPROJECT.TOML'})
        bad=self.root/'bad.json';bad.write_text(json.dumps(conflict),encoding='utf-8')
        with self.assertRaises(ValueError):prepare(delivered,bad)
        with self.assertRaises(ValueError):build(delivered,path,self.root/'out',delivered/'bad evidence',self.root/'x.zip')
        with self.assertRaises(ValueError):build(delivered,path,self.root/'out',self.root/'evidence',self.root/'out/x.zip')
        self.assertFalse((self.root/'out').exists())


if __name__=='__main__':unittest.main()
