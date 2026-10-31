"""Directed offline candidate checks; no real model, app-server or provider calls.

Run in an ordinary Windows user session. Genuine OS ownership placement and
filesystem guards remain active. Only newly created fixture ownership roots are
removed after their original leases/threads are closed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT)]

BOOTSTRAP = [
    'tests.test_public_bootstrap.PublicBootstrapTests',
    'tests.test_public_bootstrap.PublicWorkSetTests',
    'tests.test_canonical_relay_factory.CanonicalRelayFactoryTests',
    'tests.test_bootstrap_namespace.BootstrapNamespaceTests',
]
SAFETY = [
    'tests.test_post_acceptance_stop.PostAcceptanceStopTests',
    'tests.test_agent_test_diagnostics.AgentTestDiagnosticsTests',
    'tests.test_caller_verification.CallerVerificationTests',
    'tests.test_caller_verification.CallerBootstrapIntegrationTests',
    'tests.test_caller_relay.CallerRelayTests',
    'tests.test_native_executor_admission.NativeExecutorAdmissionTests',
    'tests.test_native_executor_admission.PublicNativeAdmissionAssemblyTests',
    'tests.test_native_test_receipts.NativeTestReceiptTests',
    'tests.test_host_execution_handoff.HostExecutionHandoffTests',
    'tests.test_first_native_correction.FirstNativeCorrectionTests',
    'tests.test_native_permissions.NativePermissionsTests',
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True,
                        help='New, absent evidence directory outside candidate source')
    parser.add_argument('--subset', choices=('bootstrap', 'all'), default='all')
    parser.add_argument('--temporary-root', type=Path,
                        help='New short approved fixture directory outside source; avoids Windows path limits')
    parser.add_argument('--test',action='append',help='Exact selected class or method from the reviewed class allowlist')
    args = parser.parse_args(argv)
    output = args.evidence.absolute()
    if output.is_relative_to(ROOT) or output.exists():
        raise ValueError('new external evidence directory required')
    # Use the same no-follow namespace guard as the first-use product.
    from loommode.host.bootstrap import _output_path
    _output_path(output.parent, output)
    output.mkdir(parents=True)
    (output/'runner-source.py.txt').write_bytes(Path(__file__).read_bytes())
    temporary = args.temporary_root.absolute() if args.temporary_root else output / 't'
    if temporary.exists() or temporary.is_relative_to(ROOT):
        raise ValueError('new external fixture root required')
    _output_path(temporary.parent,temporary)
    temporary.mkdir()
    os.environ.update(TEMP=str(temporary), TMP=str(temporary), PYTHONDONTWRITEBYTECODE='1')
    tempfile.tempdir = str(temporary)
    for name in list(os.environ):
        if name.startswith('LOOMMODE_') and name.endswith('_TEST_EVIDENCE'):
            del os.environ[name]
    from loommode.host import ownership
    original_directory = ownership.runtime_directory
    owned = {}
    # Fail before tests if the actual OS known folder is unsupported. No injection.
    base = ownership._runtime_base()
    def observe_directory(workspace):
        key = ownership.workspace_identity(workspace)
        target = base / hashlib.sha256(key.encode('utf-8')).hexdigest()
        existed = target.exists()
        directory = original_directory(workspace)
        if not existed:
            if not Path(key).is_relative_to(temporary):
                raise AssertionError('test tried an unowned workspace')
            owned[directory] = key
        return directory
    selected = BOOTSTRAP + (SAFETY if args.subset == 'all' else [])
    optional = ROOT / 'tests/test_agent_test_package.py'
    if args.subset == 'all' and optional.exists():
        selected.append('tests.test_agent_test_package.AgentTestPackageTests')
    if args.test:
        if any(not any(value==c or value.startswith(c+'.test_') for c in selected) for value in args.test):
            raise ValueError('test outside reviewed directed class allowlist')
        selected=args.test
    suite = unittest.defaultTestLoader.loadTestsFromNames(selected)
    checked_sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                     for folder in ('src','tools','tests') for p in (ROOT/folder).rglob('*.py')}
    cleanup = []
    from loommode.codex.app_server import AppServerClient
    original_start, original_turn=AppServerClient.start,AppServerClient.run_turn
    peer=ROOT/'tests/fixtures/fake_app_server.py'
    peer_sha=hashlib.sha256(peer.read_bytes()).hexdigest() if peer.exists() else None
    peer_calls=[]
    def require_fake(client):
        if (client.command!=(sys.executable,str(peer)) or not peer_sha
                or hashlib.sha256(peer.read_bytes()).hexdigest()!=peer_sha
                or not client.cwd.is_relative_to(temporary)):
            raise AssertionError('real app-server/model launch forbidden; exact owned deterministic peer only')
    def start(client):
        require_fake(client);peer_calls.append({'operation':'start','command':list(client.command)})
        return original_start(client)
    def turn(client,*a,**kw):
        require_fake(client);peer_calls.append({'operation':'scripted_peer_turn','command':list(client.command)})
        return original_turn(client,*a,**kw)
    from loommode.workflow.artifacts import ArtifactStore
    original_publish=ArtifactStore._publish
    publication_errors=[]
    def observe_publish(store,path,data,**kw):
        try:return original_publish(store,path,data,**kw)
        except Exception as exc:
            cause=exc.__cause__
            publication_errors.append({'path':str(path),'path_characters':len(str(path)),
                'exception':type(exc).__name__,'cause':type(cause).__name__,
                'winerror':getattr(cause,'winerror',None),'errno':getattr(cause,'errno',None)})
            raise
    with patch.object(ownership, 'runtime_directory', observe_directory), \
         patch.object(AppServerClient,'start',start), \
         patch.object(AppServerClient,'run_turn',turn), \
         patch.object(ArtifactStore,'_publish',observe_publish), \
         patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('provider network forbidden')):
        with (output / 'tests.log').open('x', encoding='utf-8') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    if ownership._LEASES:
        raise AssertionError('test retained original Writer lease; do not remove its runtime')
    for directory, key in owned.items():
        # Check actual absolute target and ownership before recursive removal.
        if (not directory.resolve().is_relative_to(base.resolve())
                or directory.parent != base or not Path(key).is_relative_to(temporary)):
            raise AssertionError('runtime cleanup target escaped owned scope')
        ownership._check_namespace(directory)
        marker = json.loads((directory / 'owner.json').read_text(encoding='utf-8'))
        if marker != {'format': 'LOOMMODE_RUNTIME_V1', 'workspace': key}:
            raise AssertionError('runtime owner changed; no cleanup')
        shutil.rmtree(directory)
        cleanup.append({'directory': str(directory), 'workspace': key, 'removed': not directory.exists()})
    import loommode
    from loommode.version import __version__
    origins = {name: str(Path(module.__file__).resolve()) for name, module in tuple(sys.modules.items())
               if (name == 'loommode' or name.startswith('loommode.')) and getattr(module, '__file__', None)}
    if any(not Path(path).is_relative_to(ROOT / 'src') for path in origins.values()):
        raise AssertionError('candidate import escaped selected source')
    facts = {'utc': datetime.now(timezone.utc).isoformat(), 'argv': sys.argv, 'python': sys.version,
             'candidate_root': str(ROOT), 'version': __version__, 'tests': selected,
             'run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
             'skipped': result.skipped, 'success': result.wasSuccessful(),
             'actual_os_runtime_base': str(base), 'runtime_placement_injected': False,
             'temporary_root':str(temporary),'observed_publication_errors':publication_errors,
             'synthetic_peer_sha256':peer_sha,'synthetic_peer_operations':peer_calls,
             'owned_runtime_cleanup': cleanup, 'remaining_fixture_entries': [p.name for p in temporary.iterdir()],
             'module_origins': origins,
             'checked_python_sources':checked_sources,
             'source_drift_during_checks':[name for name,sha in checked_sources.items()
                 if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=sha],
             'limits': 'Offline synthetic Authority, transport and --version boundaries only. Real OS known-folder placement, original ownership/guards/canonical assembly/cleanup. No Codex authentication/protocol/model/cross-device or Task acceptance claim.'}
    (output / 'result.json').write_text(json.dumps(facts, indent=2), encoding='utf-8')
    print(json.dumps({k: facts[k] for k in ('run','failures','errors','skipped','success','runtime_placement_injected','version')}, indent=2))
    return 0 if result.wasSuccessful() and not facts['remaining_fixture_entries'] and not facts['source_drift_during_checks'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
