"""First-use protection, offline assembly and public closure; no model calls."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from loommode.host.bootstrap import create_host, inspect_config, preflight
from loommode.host.canonical import CanonicalFactoryContext, validate_binding, _check_host
from loommode.host.ownership import WorkspaceLease
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import StateStore
from loommode.codex.errors import LoomModeError


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class PublicBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loommode-public-bootstrap-')
        self.root = Path(self.temp.name)
        for name in ('business files', 'Records', 'Runtime', 'Inputs'):
            (self.root / name).mkdir()
        self.workspace = self.root / 'business files'
        (self.workspace / 'example.py').write_text('print(1)\n', encoding='utf-8')
        self.authority = self.root / 'Inputs' / 'owner.md'
        self.authority.write_text('Explicit synthetic offline assembly authority; no Task or model dispatch.', encoding='utf-8')
        self.roles = {}
        for role in ('Promoter', 'Constraint', 'Discussant', 'Decision'):
            path = self.root / 'Inputs' / (role + '.md')
            path.write_text(role + ' synthetic fixed role input', encoding='utf-8')
            self.roles[role] = {'path': str(path), 'sha256': sha(path)}
        policy = {'readable': ['example.py'], 'writable': ['example.py'], 'tests': []}
        self.value = {'schema_version': 1, 'project': 'FX', 'stage_id': 'FX-A1',
            'workspace': str(self.workspace), 'records_root': str(self.root / 'Records'),
            'runtime_root': str(self.root / 'Runtime'), 'records_tuple': ['FX', 'A', 'A1'],
            'stage_authorization_ref': 'owner',
            'authorities': {'owner': {'path': str(self.authority), 'sha256': sha(self.authority)}},
            'roles': self.roles,
            # Python stands in only for the offline --version subprocess. It is
            # never launched as app-server and proves no Codex compatibility.
            'codex': {'binary': {'path': sys.executable, 'sha256': sha(sys.executable)},
                      'supported_versions': ['.'.join(map(str, sys.version_info[:3]))]},
            'policy': policy, 'task_policies': {'FX-A1-A1': copy.deepcopy(policy)},
            'grants': {'allow_progress': False, 'allow_owner_events': False, 'local_commit_authorized': False}}
        self.config = self.root / 'Inputs' / 'bootstrap.json'
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        self.config.write_text(json.dumps(self.value), encoding='utf-8')
        return sha(self.config)

    def inspect(self):
        return inspect_config(self.config, expected_sha256=sha(self.config))

    def test_static_preflight_has_no_writes_or_live_readiness_claim(self):
        before = {str(p.relative_to(self.root)): sha(p) for p in self.root.rglob('*') if p.is_file()}
        facts = preflight(self.config, expected_sha256=sha(self.config))
        self.assertEqual(facts['status'], 'BOOTSTRAP_STATIC_READ_ONLY')
        self.assertEqual(facts['task_result_gate'], 'NOT_RUN')
        self.assertEqual(facts['codex_authentication'], 'NOT_TESTED')
        self.assertFalse(facts['factory_imported'])
        self.assertEqual(before, {str(p.relative_to(self.root)): sha(p) for p in self.root.rglob('*') if p.is_file()})

    def test_config_and_required_file_drift_rejected(self):
        old = sha(self.config)
        self.config.write_bytes(self.config.read_bytes() + b' ')
        with self.assertRaises(WorkflowError):
            inspect_config(self.config, expected_sha256=old)
        for path in (self.authority, Path(self.roles['Promoter']['path'])):
            raw = path.read_bytes()
            path.write_bytes(raw + b'changed')
            with self.assertRaises(WorkflowError):
                self.inspect()
            path.write_bytes(raw)

    def test_existing_state_and_registry_are_not_opened_or_replaced(self):
        state = StateStore(self.root / 'Runtime', 'FX', 'FX-A1').path
        state.parent.mkdir(parents=True)
        for path in (state, self.root / 'Runtime' / 'contexts.json'):
            path.write_bytes(b'protected deliberately invalid old data')
            with self.assertRaises(WorkflowError):
                self.inspect()
            self.assertEqual(path.read_bytes(), b'protected deliberately invalid old data')
            path.unlink()

    def test_occupied_records_tuple_refused(self):
        path = self.root / 'Records/Process/Reports/FX/A/A1/old.md'
        path.parent.mkdir(parents=True)
        path.write_text('protected history', encoding='utf-8')
        with self.assertRaises(WorkflowError):
            self.inspect()
        self.assertEqual(path.read_text(), 'protected history')

    def test_git_escape_and_task_policy_expansion_refused(self):
        for change in ('git', 'escape', 'task'):
            original = copy.deepcopy(self.value)
            if change == 'git':
                self.value['policy']['readable'].append('.git/config')
                self.value['policy']['writable'].append('.git/config')
            elif change == 'escape':
                self.value['policy']['readable'].append('../outside')
            else:
                self.value['task_policies']['FX-A1-A1']['readable'].append('another.py')
            self.save()
            with self.assertRaises((WorkflowError, LoomModeError)):
                self.inspect()
            self.value = original
        self.save()

    def test_store_overlap_tuple_and_git_grant_refused(self):
        for change in ('overlap', 'tuple', 'commit'):
            original = copy.deepcopy(self.value)
            if change == 'overlap':
                self.value['records_root'] = str(self.workspace)
            elif change == 'tuple':
                self.value['records_tuple'][2] = 'A2'
            else:
                self.value['grants']['local_commit_authorized'] = True
            self.save()
            with self.assertRaises(WorkflowError):
                self.inspect()
            self.value = original
        self.save()

    def test_no_private_instance_is_needed_and_optional_native_is_closed(self):
        from loommode.host.managed_native import ManagedNativeHost
        self.inspect()
        with self.assertRaisesRegex(WorkflowError, 'explicit pinned'):
            ManagedNativeHost.from_trusted_config(None)
        with self.assertRaisesRegex(WorkflowError, 'explicit pinned'):
            ManagedNativeHost(None).check(None, None, None)

    def test_named_credential_input_refused_without_opening_its_body(self):
        path = self.root / 'Inputs/auth.json'
        path.write_bytes(b'protected synthetic credential sentinel')
        self.value['authorities']['owner'] = {'path': str(path), 'sha256': sha(path)}
        self.save()
        with self.assertRaisesRegex(WorkflowError, 'credential'):
            self.inspect()
        self.assertEqual(path.read_bytes(), b'protected synthetic credential sentinel')

    def test_explicit_connection_requires_matching_progress_authorization(self):
        self.value['codex']['connect_on_assembly'] = True
        self.save()
        with self.assertRaisesRegex(WorkflowError, 'progress authorization'):
            self.inspect()

    def test_explicit_connection_occurs_after_original_lease_registration(self):
        from loommode.codex.adapter import ThinCodexAdapter
        self.value['codex']['connect_on_assembly'] = True
        self.value['grants']['allow_progress'] = True
        self.save()
        contexts = []
        original = CanonicalFactoryContext.register_host
        def register(context, host):
            value = original(context, host)
            contexts.append(context)
            return value
        def connect(adapter):
            self.assertTrue(contexts)
            context = contexts[-1]
            self.assertIs(context.host.host.engine.roles.adapter, adapter)
            self.assertTrue(context.writer_lease.held)
            self.assertIs(context.writer_lease.owner, context.host.host.engine)
            return {'synthetic': True, 'model_calls': 0}
        with patch.object(CanonicalFactoryContext, 'register_host', register), patch.object(ThinCodexAdapter, 'connect', connect):
            self.test_actual_canonical_context_retains_original_lease_no_connection()

    def test_connection_failure_uses_canonical_cleanup_before_writer_release(self):
        from loommode.codex.adapter import ThinCodexAdapter
        from loommode.host.canonical import open_canonical
        self.value['codex']['connect_on_assembly'] = True
        self.value['grants']['allow_progress'] = True
        self.save()
        factory = self.root / 'Inputs/factory.py'
        factory.write_text('# replaced by explicit test call to the public factory\n', encoding='utf-8')
        binding = {'schema_version': 1, 'project': 'FX', 'stage_id': 'FX-A1',
            'workspace': str(self.workspace), 'stage_authorization_ref': 'owner',
            'stage_authorization_sha256': hashlib.sha256(self.authority.read_text(encoding='utf-8').encode()).hexdigest(),
            'decision_role': 'Decision', 'grants': self.value['grants'],
            'runtime': {'kind': 'development', 'source_root': str(Path(__file__).resolve().parents[1] / 'src'),
                        'approval_ref': 'synthetic connection-failure cleanup test'},
            'factory': {'path': str(factory), 'sha256': sha(factory)}}
        registered = []
        def load(binding, context):
            try:
                return create_host(self.config, expected_sha256=sha(self.config), canonical_context=context)
            finally:
                registered.append(context)
        with patch('loommode.host.canonical._load_factory', load), patch.object(
                ThinCodexAdapter, 'connect', side_effect=RuntimeError('synthetic connection failure')):
            with self.assertRaisesRegex(RuntimeError, 'synthetic connection failure'):
                open_canonical(binding)
        self.assertTrue(registered)
        self.assertIsNotNone(registered[0].host)
        self.assertTrue(registered[0].host.host.engine.roles.adapter._closed)
        self.assertFalse(registered[0].writer_lease.held)
        probe = WorkspaceLease(self.workspace)
        self.assertTrue(probe.acquire())
        probe.release()

    def test_actual_canonical_context_retains_original_lease_no_connection(self):
        factory = self.root / 'Inputs/factory.py'
        factory.write_text('# offline assembly sentinel\n', encoding='utf-8')
        source = Path(__file__).resolve().parents[1] / 'src'
        binding = validate_binding({'schema_version': 1, 'project': 'FX', 'stage_id': 'FX-A1',
            'workspace': str(self.workspace), 'stage_authorization_ref': 'owner',
            'stage_authorization_sha256': hashlib.sha256(self.authority.read_text(encoding='utf-8').encode()).hexdigest(),
            'decision_role': 'Decision', 'grants': self.value['grants'],
            'runtime': {'kind': 'development', 'source_root': str(source), 'approval_ref': 'synthetic offline test'},
            'factory': {'path': str(factory), 'sha256': sha(factory)}})
        lease = WorkspaceLease(self.workspace)
        self.assertTrue(lease.acquire())
        host = None
        try:
            context = CanonicalFactoryContext(binding, lease)
            host = create_host(self.config, expected_sha256=sha(self.config), canonical_context=context)
            _check_host(host, binding)
            engine = host.host.engine
            self.assertIs(engine._workspace_writer_lease, lease)
            self.assertIs(host._workspace_lease, lease)
            self.assertEqual(engine.state.current_node, 'STAGE_START')
            self.assertIsNone(engine.roles.adapter.client.process)
            self.assertIsNone(engine.roles.model_router)
            self.assertIsNone(engine.executor.model_router)
            self.assertEqual(engine.executor.implementation_config.backend, 'codex_app_server')
        finally:
            if host is not None:
                host.close()
            lease.release()


class PublicWorkSetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loommode-work-set-')
        self.root = Path(self.temp.name)
        (self.root / 'src/loommode').mkdir(parents=True)
        self.paths = ['src/loommode/__init__.py', 'src/loommode/module.py', 'src/loommode_binding.py']
        for name in self.paths:
            (self.root / name).write_text('# synthetic public asset\n', encoding='utf-8')
        self.spec = self.root / 'set.json'
        self.save(self.paths)

    def tearDown(self):
        self.temp.cleanup()

    def save(self, names):
        self.spec.write_text(json.dumps({'format': 'LOOMMODE_NON_RELEASE_WORK_SET_V1',
            'files': [{'source': n, 'target': n} for n in names]}), encoding='utf-8')

    def test_missing_production_module_refused_before_output(self):
        from tools.loommode_work_package import build
        self.save(self.paths[:1] + self.paths[2:])
        with self.assertRaisesRegex(ValueError, 'closure'):
            build(self.root, self.spec, self.root / 'output')
        self.assertFalse((self.root / 'output').exists())

    def test_private_payload_signature_refused_before_output(self):
        from tools.loommode_work_package import build
        (self.root / self.paths[1]).write_text("path = 'C:/Users/synthetic_private/secret'\n", encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'private'):
            build(self.root, self.spec, self.root / 'output')
        self.assertFalse((self.root / 'output').exists())

    def test_non_release_inventory_and_existing_output_preservation(self):
        from tools.loommode_work_package import build
        target = self.root / 'output'
        facts = build(self.root, self.spec, target)
        self.assertFalse(facts['release'])
        self.assertFalse((target / 'release.json').exists())
        before = (target / 'NON_RELEASE_INVENTORY.json').read_bytes()
        with self.assertRaises(FileExistsError):
            build(self.root, self.spec, target)
        self.assertEqual(before, (target / 'NON_RELEASE_INVENTORY.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
