"""Candidate setup/caller tests, with explicit synthetic authorities.

Original Host/Context/accounting filesystem APIs run; transports remain fixtures.
No test grants authorization for actual deployment or calls a real model.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from loommode.workflow.errors import WorkflowError
from loommode.host.ownership import WorkspaceLease
from tools.agent_test_setup import prepare
from tools.agent_test_caller import OneTaskCaller, publish


class AgentTestPackageTests(unittest.TestCase):
    def setup_request(self):
        from tests.test_public_bootstrap import PublicBootstrapTests
        from tests.test_caller_verification import caller_inputs
        from loommode.tools.runtime import ToolPolicy, ToolProfile
        fixture=PublicBootstrapTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        value=fixture.value
        policy=ToolPolicy(fixture.workspace,ToolProfile.BOUNDED_DEVELOPMENT,('example.py',),('example.py',))
        config, sources, put=caller_inputs(fixture.root,fixture.workspace,policy,task='FX-A1-A1')
        request={k:value[k] for k in ('project','stage_id','workspace','records_root','runtime_root','records_tuple','codex','policy')}
        request.update(task_id='FX-A1-A1',caller_id='fixture-trusted-caller',
            owner_source=config['authorities']['owner-original'],
            stage_authority={'path':str(fixture.authority),'sha256':hashlib.sha256(fixture.authority.read_bytes()).hexdigest()},
            resource_authorization=config['authorities']['approved-resources'],
            resource_supplement=config['authorities']['resource-supplement'])
        path=fixture.root/'Inputs/setup-request.json'
        path.write_text(json.dumps(request),encoding='utf-8')
        return fixture,request,path

    def test_setup_is_inert_and_preserves_originals_live_stores_and_existing_outputs(self):
        fixture,request,path=self.setup_request()
        target=fixture.root/'new generated inputs'
        before={p: p.read_bytes() for p in fixture.root.rglob('*') if p.is_file()}
        result=prepare(path,target)
        self.assertFalse(result['active'])
        value=json.loads((target/'bootstrap.json').read_text())
        self.assertEqual(value['grants'],{'allow_progress':False,'allow_owner_events':False,'local_commit_authorized':False})
        self.assertFalse(value['codex']['connect_on_assembly'])
        self.assertEqual(sorted((fixture.root/'Runtime').iterdir()),[])
        self.assertEqual(sorted((fixture.root/'Records').iterdir()),[])
        for file,raw in before.items():self.assertEqual(file.read_bytes(),raw)
        with self.assertRaises(WorkflowError):prepare(path,target)
        with self.assertRaises(WorkflowError):prepare(path,fixture.root/'active denied',activate=True)

    def test_setup_source_drift_and_resource_identity_mismatch_refuse(self):
        fixture,request,path=self.setup_request()
        Path(request['owner_source']['path']).write_text('changed synthetic original',encoding='utf-8')
        with self.assertRaises(WorkflowError):prepare(path,fixture.root/'drift denied')
        self.assertFalse((fixture.root/'drift denied').exists())

    def test_setup_original_request_namespace_is_checked_before_resolve(self):
        from tests.test_bootstrap_namespace import junction
        import os
        fixture,request,path=self.setup_request()
        link=fixture.root/'linked original inputs'
        junction(link,path.parent)
        try:
            with self.assertRaises(Exception):prepare(link/path.name,fixture.root/'linked denied')
            self.assertFalse((fixture.root/'linked denied').exists())
        finally:
            os.rmdir(link) if os.name=='nt' else link.unlink()

    def caller_scene(self):
        from tests.test_native_executor_admission import NativeExecutorAdmissionTests
        fixture=NativeExecutorAdmissionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.addCleanup(fixture.tearDown)
        scene=fixture.scene
        lease=WorkspaceLease(scene.repo)
        self.assertTrue(lease.acquire())
        lease.owner=scene.engine
        scene.engine._workspace_writer_lease=lease
        self.addCleanup(lease.release)
        self.addCleanup(lambda:delattr(scene.engine,'_workspace_writer_lease'))
        config={**fixture.config,'task_policies':{'FX-A1-A0':{}}}
        request=publish(fixture.root/'setup-request.json',{'origin':'EXPLICIT_SYNTHETIC_TEST_ONLY'})
        caller=OneTaskCaller(fixture.host,config=config,request_pin=request,directory=fixture.root/'new accounting')
        fixture.admission.reserve=caller.reserve_native
        fixture.admission.seal=caller.seal_native
        original=scene.adapter.run_turn
        scene.adapter.run_turn=lambda **kwargs:caller.run_turn(original,**kwargs)
        return fixture,caller,original

    def test_native_reserves_seals_and_claims_once_before_one_scripted_dispatch(self):
        fixture,caller,original=self.caller_scene()
        fixture.dispatch()
        rows=caller.events()
        self.assertEqual([r['kind'] for r in rows],['reserve','seal','claim'])
        self.assertEqual(len({r['reservation_id'] for r in rows}),1)
        self.assertEqual(len(fixture.executor_calls()),1)
        call=fixture.executor_calls()[0]
        with self.assertRaises(WorkflowError):caller.run_turn(original,**call)
        expected=rows[1]['expected']
        with self.assertRaises(WorkflowError):caller.seal_native(expected)
        self.assertEqual([r['kind'] for r in caller.events()],['reserve','seal','claim'])

    def test_missing_changed_accounting_and_exhausted_quota_do_not_refund_or_replay(self):
        fixture,caller,original=self.caller_scene()
        for i in range(caller.resource['limits']['max_run_turns']):caller.reserve(str(i))
        with self.assertRaises(WorkflowError):caller.reserve('over limit')
        with self.assertRaises(WorkflowError):caller.reserve('0')
        (caller.directory/'event-000012.json').unlink()
        with self.assertRaises(WorkflowError):caller.events()

    def test_native_wrong_seal_context_and_original_source_drift_refuse(self):
        fixture,caller,original=self.caller_scene()
        original_seal=caller.seal_native
        def wrong(expected):
            changed={**expected,'context_ref':'not-current'}
            return original_seal(changed)
        fixture.admission.seal=wrong
        fixture.refuse()
        self.assertEqual([r['kind'] for r in caller.events()],['reserve'])
        Path(caller.request_pin['path']).write_text('changed original',encoding='utf-8')
        with self.assertRaises(WorkflowError):caller.check()

    def test_failed_or_unknown_dispatch_keeps_native_consumption_and_claim(self):
        fixture,caller,original=self.caller_scene()
        def fail(**kwargs):raise RuntimeError('synthetic unknown transport result')
        fixture.scene.adapter.run_turn=lambda **kwargs:caller.run_turn(fail,**kwargs)
        with self.assertRaises(Exception):fixture.dispatch()
        self.assertEqual([r['kind'] for r in caller.events()],['reserve','seal','claim'])
        self.assertEqual(fixture.executor_calls(),[])

    def test_false_quota_and_wrong_context_refuse_before_ordinary_reservation(self):
        fixture,caller,original=self.caller_scene()
        # Actual native Context exists only during dispatch; current role Context
        # from the synthetic registry is enough for ordinary metadata guards.
        reference=next(ref for ref,record in fixture.scene.adapter.registry._records.items()
                       if record.resource_state.value in {'ACTIVE','RETAINED'})
        fixture.scene.adapter.usage=[False]
        before=len(fixture.scene.adapter.rpc)
        with self.assertRaises(WorkflowError):caller.run_turn(original,thread_id=reference,prompt='ordinary')
        self.assertEqual(caller.events(),[])
        self.assertEqual(len(fixture.scene.adapter.rpc),before+1)
        fixture.scene.adapter.registry.get(reference).owner_id='wrong-owner'
        with self.assertRaises(WorkflowError):caller.run_turn(original,thread_id=reference,prompt='ordinary')
        self.assertEqual(caller.events(),[])

    def test_final_native_quota_refusal_consumes_claim_without_replay(self):
        fixture,caller,original=self.caller_scene()
        fixture.scene.adapter.usage=[True,True,False]
        fixture.refuse()
        rows=caller.events()
        self.assertEqual([r['kind'] for r in rows],['reserve','seal','claim'])
        expected=rows[1]['expected']
        with self.assertRaises(WorkflowError):
            caller.run_turn(original,thread_id=expected['context_ref'],prompt='unbound native\nACTIVITY: EXECUTOR_IMPLEMENT\n')
        self.assertEqual(len(caller.events()),3)

    def test_builder_casefold_escape_and_output_namespace_refusals(self):
        from tools.agent_test_package import prepare as select,build
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as name:
            temporary=Path(name)
            spec=json.loads((root/'config/agent_test_package.json').read_text())
            spec['files'].append({'source':'pyproject.toml','target':'PYPROJECT.TOML'})
            path=temporary/'set.json';path.write_text(json.dumps(spec),encoding='utf-8')
            with self.assertRaises(ValueError):select(root,path)
            spec['files'][-1]['target']='../escape'
            path.write_text(json.dumps(spec),encoding='utf-8')
            with self.assertRaises(ValueError):select(root,path)
            # Source selection succeeds, then unsafe output placement refuses
            # before any target/build/ZIP writes.
            with self.assertRaises(ValueError):
                build(root,root/'config/agent_test_package.json',temporary/'target',root/'bad evidence',temporary/'x.zip')
            with self.assertRaises(ValueError):
                build(root,root/'config/agent_test_package.json',temporary/'target',temporary/'evidence',temporary/'target/x.zip')
            self.assertFalse((temporary/'target').exists())

    def test_integrity_exact_members_and_unsafe_zip_refuse_before_extract(self):
        from tools.agent_test_integrity import verify_bytes,extract,safe_name
        import zipfile
        raw=b'candidate synthetic content'
        digest=hashlib.sha256(raw).hexdigest()
        manifest={'kind':'LOOMMODE_AGENT_TEST_CANDIDATE_V1','version':'2.0.0-rc.1',
                  'files':{'README.md':{'sha256':digest,'bytes':len(raw)}}}
        files={'README.md':raw,'MANIFEST.json':json.dumps(manifest).encode()}
        files['SHA256SUMS']=''.join(hashlib.sha256(v).hexdigest()+'  '+k+'\n' for k,v in files.items()).encode()
        verify_bytes(files)
        with self.assertRaises(ValueError):verify_bytes({**files,'unlisted.txt':b'x'})
        for value in ('../escape','C:/escape','.git/config','AUX.txt','a\\b'):
            with self.assertRaises(ValueError):safe_name(value)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);archive=root/'unsafe.zip'
            with zipfile.ZipFile(archive,'x') as stream:stream.writestr('../escape',b'x')
            with self.assertRaises(ValueError):extract(archive,root/'extract',hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertFalse((root/'extract').exists())

    def test_actual_canonical_advance_captures_relay_before_unchanged_window_deadline(self):
        from tests.test_caller_relay import CallerRelayTests
        from loommode.host.canonical import open_canonical
        from unittest.mock import patch
        fixture=CallerRelayTests();fixture.setUp()
        self.addCleanup(fixture.doCleanups);self.addCleanup(fixture.tearDown)
        fixture.scene.engine.commit_authorized=False  # Match this no-Git canonical fixture binding.
        source=Path(__file__).resolve().parents[1]/'src'
        factory=fixture.root/'factory.py';factory.write_text('# explicit scripted Host fixture factory boundary\n',encoding='utf-8')
        authority=fixture.scene.engine.authority['owner']
        binding={'schema_version':1,'project':'FX','stage_id':'FX-A1','workspace':str(fixture.scene.repo),
                 'stage_authorization_ref':'owner','stage_authorization_sha256':hashlib.sha256(authority.encode()).hexdigest(),
                 'decision_role':'Decision','grants':{'allow_progress':True,'allow_owner_events':False,'local_commit_authorized':False},
                 'runtime':{'kind':'development','source_root':str(source),'approval_ref':'synthetic public-frame relay test'},
                 'factory':{'path':str(factory),'sha256':hashlib.sha256(factory.read_bytes()).hexdigest()}}
        def load(binding,context):return context.register_host(fixture.host)
        with patch('loommode.host.canonical._load_factory',load):client=open_canonical(binding)
        self.addCleanup(client.owner.close)
        snapshot=fixture.host.entry.query()
        client.request({'op':'start','scope':'current_stage','expected_revision':snapshot.revision,'automatic':False})
        client.supervisor.wait_for_idle(10)
        before=len(fixture.scene.adapter.prompts)
        deadline=fixture.host.windows.current['deadline']
        fixture.publish()  # Explicit synthetic capture, never actual chat attestation.
        self.assertIsNone(fixture.verifier.receipt_ref)
        client.request({'op':'advance'})  # Original public canonical request route.
        client.supervisor.wait_for_idle(10)
        self.assertIsNotNone(fixture.verifier.receipt_ref)
        self.assertEqual(fixture.host.windows.current['deadline'],deadline)
        self.assertEqual(fixture.scene.engine.state.current_node,'SOFT_REVIEW_WAIT')
        self.assertEqual(len(fixture.scene.adapter.prompts),before)
        self.assertFalse(fixture.verifier.receipt_body and json.loads(fixture.verifier.receipt_body)['owner_accepted'])

    def test_optional_native_checkout_snapshot_does_not_relax_runtime_closure(self):
        from loommode.host import managed_native
        from unittest.mock import patch
        self.assertEqual(managed_native.SOURCE_FILES,managed_native.source_files())
        self.assertEqual(len(managed_native.SOURCE_FILES),64)
        with tempfile.TemporaryDirectory() as name,patch.object(managed_native,'SOURCE_ROOT',Path(name)):
            decoy=Path(name)/'src/loommode/host/managed_native.py'
            decoy.parent.mkdir(parents=True);decoy.write_text('# unrelated coincidental tree\n',encoding='utf-8')
            with self.assertRaises(WorkflowError):managed_native.source_files()
        with self.assertRaises(WorkflowError):managed_native.ManagedNativeHost.from_trusted_config(None)


if __name__=='__main__':unittest.main()
