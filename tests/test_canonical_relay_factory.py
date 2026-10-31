"""Actual pinned public canonical factories; zero app-server/model activities."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from loommode.codex.adapter import ThinCodexAdapter
from loommode.codex.app_server import AppServerClient
from loommode.host.canonical import CanonicalFactoryContext, open_canonical
from loommode.host.driver import DecisionHost
from loommode.host.ownership import WorkspaceLease
from loommode.host.supervisor import SupervisorHost
from loommode.workflow.engine import WorkflowEngine
from loommode.workflow.errors import WorkflowError
from tests import test_public_bootstrap


class CanonicalRelayFactoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_public_bootstrap.PublicBootstrapTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.value['codex']['connect_on_assembly'] = False
        self.fixture.save()
        self.root = self.fixture.root
        self.registrations = []
        self.clients = []
        self.facts = []
        self.version_probes = []
        self.version_response = self.fixture.value['codex']['supported_versions'][0]
        self.guards = {}
        for name, target in (
                ('adapter_connect', 'loommode.codex.adapter.ThinCodexAdapter.connect'),
                ('adapter_run_turn', 'loommode.codex.adapter.ThinCodexAdapter.run_turn'),
                ('adapter_start_context', 'loommode.codex.adapter.ThinCodexAdapter.start_context'),
                ('appserver_start', 'loommode.codex.app_server.AppServerClient.start'),
                ('appserver_run_turn', 'loommode.codex.app_server.AppServerClient.run_turn'),
                ('any_subprocess', 'subprocess.Popen'),
                ('engine_step', 'loommode.workflow.engine.WorkflowEngine.step'),
                ('supervisor_start', 'loommode.host.supervisor.SupervisorHost.start')):
            guard = patch(target, side_effect=AssertionError('forbidden in zero-connection assembly: '+name))
            self.guards[name] = guard.start()
            self.addCleanup(guard.stop)
        def version_response(argv, **kwargs):
            expected = [str(Path(self.fixture.value['codex']['binary']['path']).resolve()), '--version']
            self.assertEqual(argv,expected)
            self.assertIs(kwargs['shell'],False)
            self.assertEqual(kwargs['cwd'],str(Path(expected[0]).parent))
            self.version_probes.append({'argv':argv,'response':'Python '+self.version_response,
                'synthetic_external_version_response':True,'binary_executed':False})
            return subprocess.CompletedProcess(argv,0,'Python '+self.version_response+'\n','')
        # Only this external version-probe response is synthetic. The original
        # BinaryPolicy.inspect, file/pin/namespace checks and version parser run;
        # all subprocess launches remain denied. This proves no Codex version
        # compatibility and supplies no model/connection or permission receipt.
        probe_stub = patch('loommode.codex.app_server.subprocess.run',side_effect=version_response)
        probe_stub.start()
        self.addCleanup(probe_stub.stop)
        original = CanonicalFactoryContext.register_host
        def register(context, host, **kwargs):
            # Observe the actual original call; do not replace its result,
            # registration, ownership or cleanup behavior.
            result = original(context, host, **kwargs)
            self.registrations.append((context, host, result))
            return result
        observer = patch.object(CanonicalFactoryContext, 'register_host', register)
        observer.start()
        self.addCleanup(observer.stop)

    def tearDown(self):
        for client in self.clients:
            client.owner.close()
        for name, guard in self.guards.items():
            self.assertEqual(guard.call_count, 0, name)
        output = os.environ.get('LOOMMODE_C5_A6_TEST_EVIDENCE')
        if output:
            body = {'origin': 'A6_ACTUAL_OPEN_CANONICAL_PUBLIC_ASSEMBLE_NO_MODEL_NO_CONNECTION',
                'test': self.id(), 'facts': self.facts,
                'forbidden_call_counts': {n:g.call_count for n,g in self.guards.items()},
                'synthetic_external_version_probes': self.version_probes,
                'actual_factory': self.factory.read_text(encoding='utf-8'),
                'factory_sha256': test_public_bootstrap.sha(self.factory),
                'bootstrap': self.fixture.value, 'binding': self.binding,
                'actual_registered_return_types': [{'input':type(h).__name__, 'result':type(s).__name__,
                    'registered_same_object':c.host is s} for c,h,s in self.registrations],
                'evidence_limit': 'Synthetic offline authority/Task and exact external --version response; original BinaryPolicy.inspect parser remains active. Python is a pinned unused binary file, not Codex compatibility evidence. No executable, app-server, Stage/model activity or Smoke is launched. Fixture is disposed after evidence capture.'}
            (Path(output)/(self._testMethodName+'.json')).write_text(json.dumps(body,indent=2),encoding='utf-8')

    def factory_for(self, lines, *, returned='supervisor'):
        source_root = Path(__file__).resolve().parents[1]
        # Load and import the actual public example through original _load_factory.
        # Its two reviewed config placeholders are the same public customization.
        template = (source_root/'tools/loommode_codex_factory.py').read_text(encoding='utf-8')
        template = template.replace('REPLACE_WITH_ABSOLUTE_APPROVED_BOOTSTRAP_JSON', self.fixture.config.as_posix())
        template = template.replace('REPLACE_WITH_EXACT_RAW_CONFIG_SHA256', test_public_bootstrap.sha(self.fixture.config))
        old = '    return supervisor\n'
        self.assertEqual(template.count(old),1)
        template = template.replace(old, ''.join('    '+line+'\n' for line in lines)+'    return '+returned+'\n')
        self.factory = self.root/'Inputs/canonical-relay-factory.py'
        self.factory.write_text(template,encoding='utf-8')
        self.binding = {'schema_version':1, 'project':'FX', 'stage_id':'FX-A1',
            'workspace':str(self.fixture.workspace), 'stage_authorization_ref':'owner',
            'stage_authorization_sha256':hashlib.sha256(self.fixture.authority.read_text(encoding='utf-8').encode()).hexdigest(),
            'decision_role':'Decision', 'grants':self.fixture.value['grants'],
            'runtime':{'kind':'development', 'source_root':str(source_root/'src'),
                       'approval_ref':'Synthetic A6 zero-connection actual canonical assembly test; no progress grant'},
            'factory':{'path':str(self.factory),'sha256':test_public_bootstrap.sha(self.factory)}}

    @staticmethod
    def wiring(*, task="'FX-A1-A1'", caller="'A6-offline-caller'", provider='lambda: None', target='supervisor.host'):
        return target+'.require_caller_relay(task_id='+task+', caller_id='+caller+', source_provider='+provider+')'

    def released(self, *, require_relay):
        self.assertEqual(len(self.registrations),1)
        context, decision, supervisor = self.registrations[0]
        self.assertIsInstance(decision,DecisionHost)
        self.assertIsInstance(supervisor,SupervisorHost)
        self.assertIs(supervisor,context.host)
        self.assertIs(supervisor.host,decision)
        engine = decision.engine
        self.assertIsNone(supervisor._thread)
        self.assertIsNone(supervisor._operation)
        self.assertFalse(context.writer_lease.held)
        self.assertTrue(engine._resources_closed)
        self.assertTrue(engine.roles.adapter._closed)
        self.assertFalse(engine.roles.adapter._connected)
        self.assertIsNone(engine.roles.adapter.client.process)
        self.assertEqual(engine.state.current_node,'STAGE_START')
        self.assertIsNone(engine.state.in_flight_activity)
        self.assertEqual(engine.state.artifact_refs,{})
        self.assertIsNone(supervisor._selection)
        if require_relay:
            relay = engine.caller_relay_verification
            self.assertIs(relay,engine.roles.caller_relay_verification)
            self.assertIs(relay.host,decision)
        probe = WorkspaceLease(self.fixture.workspace)
        self.assertTrue(probe.acquire())
        probe.release()
        self.facts.append({'actual_context_registered':True, 'original_owner_closed':True,
            'writer_released':not context.writer_lease.held, 'actual_lease_reacquired_and_released':True,
            'resources':engine.resource_health(), 'state':engine.state.as_dict(),
            'adapter_closed':engine.roles.adapter._closed, 'appserver_process':None})

    def test_actual_public_entry_configures_underlying_host_and_closes_original_owner(self):
        self.factory_for([self.wiring()])
        client = open_canonical(self.binding)
        self.clients.append(client)
        self.assertTrue(client.created)
        context, decision, supervisor = self.registrations[0]
        self.assertIs(client.supervisor,supervisor)
        self.assertIs(context.host,supervisor)
        self.assertTrue(context.writer_lease.held)
        self.assertIs(context.writer_lease.owner,decision.engine)
        self.assertIs(decision.engine._workspace_writer_lease,context.writer_lease)
        self.assertIs(supervisor._workspace_lease,context.writer_lease)
        relay = decision.engine.caller_relay_verification
        self.assertEqual(relay.task_id,'FX-A1-A1')
        self.assertEqual(relay.caller_id,'A6-offline-caller')
        self.assertEqual(relay._identity()['workspace'],str(self.fixture.workspace.resolve()))
        self.assertIsNone(relay.source_provider())
        self.assertIsNone(relay.receipt_ref)
        self.assertEqual(client.status()['facts']['node'],'STAGE_START')
        self.facts.append({'actual_public_return_type':type(supervisor).__name__,
            'configured_underlying_type':type(decision).__name__,
            'same_registered_returned_object':True,'same_engine_role_verifier':True,
            'Task':relay.task_id,'caller':relay.caller_id,'workspace':relay._identity()['workspace'],
            'writer_held_before_close':True,'connect_on_assembly':False})
        client.owner.close()
        self.facts.append({'original_owner_diagnostic_after_close':client.owner.diagnostic()})
        self.released(require_relay=True)

    def refused(self, lines, exception, message, *, returned='supervisor', require_relay=False):
        self.factory_for(lines,returned=returned)
        with self.assertRaisesRegex(exception,message) as caught:
            open_canonical(self.binding)
        self.facts.append({'actual_exception_type':type(caught.exception).__name__,
                           'actual_exception':str(caught.exception)})
        self.released(require_relay=require_relay)

    def test_wrong_task_is_rejected_by_original_relay_requirement(self):
        self.refused([self.wiring(task="'FX-A1-A9'")],WorkflowError,'initial idle Host')

    def test_empty_caller_is_rejected_by_original_relay_requirement(self):
        self.refused([self.wiring(caller="''")],WorkflowError,'initial idle Host')

    def test_plain_text_is_not_a_trusted_source_provider(self):
        self.refused([self.wiring(provider="'model claims verification'")],WorkflowError,'initial idle Host')

    def test_returning_underlying_host_is_rejected_and_original_owner_closed(self):
        self.refused([self.wiring()],WorkflowError,'return its registered canonical Host',
                     returned='supervisor.host',require_relay=True)

    def test_old_direct_supervisor_call_fails_and_cleans_without_proxy_interface(self):
        self.refused([self.wiring(target='supervisor')],AttributeError,'require_caller_relay')

    def test_duplicate_requirement_cannot_replace_original_live_binding(self):
        self.refused([self.wiring(),self.wiring(caller="'replacement'")],WorkflowError,
                     'initial idle Host',require_relay=True)

    def test_synthetic_version_response_still_faces_original_binary_policy(self):
        from loommode.codex.errors import LoomModeError
        self.version_response = '999.0.0'
        self.factory_for([self.wiring()])
        with self.assertRaisesRegex(LoomModeError,'outside the configured support policy') as caught:
            open_canonical(self.binding)
        self.assertEqual(self.registrations,[])
        probe = WorkspaceLease(self.fixture.workspace)
        self.assertTrue(probe.acquire())
        probe.release()
        self.facts.append({'original_binary_policy_rejected_synthetic_bad_version':True,
            'actual_exception':str(caught.exception),'actual_lease_reacquired_and_released':True,
            'registered_host_created':False})


if __name__ == '__main__':
    unittest.main()
