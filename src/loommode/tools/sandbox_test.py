"""Trusted zero-model MXC launcher; no workspace imports on the Host.

OwnedJob owns termination, the fixed CLI sandbox owns access boundaries.
Plans are derived from the original request, never workspace configuration.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import re
from pathlib import Path

PYTHON = Path('S:/Anaconda/python.exe')
PYTHON_SHA256 = '388fe2cffda8a134e7d7dc4e978f7c478857ece6b69694daecbed25e51ec633a'
PYTHON_RUNTIME = tuple('S:/Anaconda/' + p for p in (
    'python.exe', 'python313.dll', 'python3.dll', 'vcruntime140.dll',
    'vcruntime140_1.dll', 'Lib', 'DLLs', 'zlib.dll'))
RUNTIME_DENIED = ('S:/Anaconda/Lib/site-packages', 'S:/Anaconda/Lib/ensurepip')

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()

def runtime_denials(config):
    # Same fixed narrower runtime in Native tools and Host tests.
    return RUNTIME_DENIED if tuple(config.runtime_read_paths) == PYTHON_RUNTIME else ()

def _root_import_index(workspace, permissions):
    """Pure names only: derive a bounded index from trusted effective read intents."""
    workspace = Path(workspace)
    denied = tuple(Path(path) for path, mode in permissions.items() if mode == 'deny')
    names = set()
    for location, mode in permissions.items():
        if mode != 'read' or location.startswith(':'):
            continue
        path = Path(location)
        if not path.is_relative_to(workspace):
            continue
        relative = path.relative_to(workspace)
        if not relative.parts:
            raise RuntimeError('workspace root read is not a bounded import index')
        name = relative.parts[0]
        root_entry = workspace / name
        if any(root_entry == entry or root_entry.is_relative_to(entry) for entry in denied):
            continue
        if (name in ('.', '..') or any(c in name for c in '\\/\x00:')
                or len(name) > 255):
            raise RuntimeError('invalid bounded root import entry')
        names.add(name)
    entries = tuple(sorted(names, key=lambda name: (name.casefold(), name)))
    if not entries or len(entries) > 128 or sum(map(len, entries)) > 4096:
        raise RuntimeError('bounded root import index unavailable/too large; no fallback')
    return entries


def _root_import_bootstrap(workspace, entries):
    """Generate trusted code; neither inspect nor import workspace code on the Host."""
    payload = json.dumps({'workspace': str(workspace), 'entries': list(entries)},
                         sort_keys=True, separators=(',', ':'))
    return '''def _lm2_install_root_index(payload):
    import importlib.machinery as machinery
    import json
    import os
    import sys
    value = json.loads(payload)
    workspace, entries = value['workspace'], tuple(value['entries'])
    cwd = os.getcwd()
    if (os.name != 'nt' or not os.path.isabs(workspace)
            or os.path.normcase(os.path.abspath(cwd)) != os.path.normcase(workspace)):
        raise RuntimeError('fixed sandbox root-index cwd mismatch; no fallback')
    class RootIndexFileFinder(machinery.FileFinder):
        def _fill_cache(self):
            # Python 3.13 Windows FileFinder cache normalization, with trusted
            # declared names in place of the denied root os.listdir operation.
            self._path_cache = set()
            for item in entries:
                name, dot, suffix = item.partition('.')
                self._path_cache.add(name + '.' + suffix.lower() if dot else name)
            self._relaxed_path_cache = {item.lower() for item in entries}
    finder = RootIndexFileFinder(workspace,
        (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
        (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES),
        (machinery.SourcelessFileLoader, machinery.BYTECODE_SUFFIXES))
    # No relative cache key or meta_path/path_hooks changes. The explicit B3
    # child uses this same absolute workspace, not a process-wide path hook.
    for key in (workspace, cwd):
        sys.path_importer_cache[key] = finder
_lm2_install_root_index(''' + repr(payload) + ''')
del _lm2_install_root_index
'''


def _fixed_test_python_argv(spec, bootstrap):
    # Original TestSpec stays fixed; runpy gives unittest its ordinary __main__.
    main = ("import runpy as _lm2_runpy, sys as _lm2_sys\n"
            "_lm2_sys.argv[0] = 'unittest'\n"
            "_lm2_runpy.run_module('unittest', run_name='__main__', alter_sys=True)\n")
    return (*spec.argv[:4], '-c', bootstrap + main, *spec.argv[6:])

@dataclass(frozen=True)
class SandboxTestPlan:
    test_id: str
    spec_sha256: str
    request_fingerprint: str
    policy_sha256: str
    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...]
    binary_sha256: str
    python_sha256: str
    control_directory: Path
    host_identity_sha256: str
    root_import_index: tuple[str, ...]
    root_import_bootstrap: str
    root_import_bootstrap_sha256: str

    def evidence(self):
        value = asdict(self)
        # Trusted declared fields become stable JSON primitives at their origin.
        # The same values reach launch records, Host facts and saved verification.
        value['cwd'] = str(self.cwd)
        value['control_directory'] = str(self.control_directory)
        value['argv'] = list(self.argv)
        value['environment'] = [list(pair) for pair in self.environment]
        value['root_import_index'] = list(self.root_import_index)
        value['plan_sha256'] = _digest(value)
        value['isolation'] = 'FIXED_CODEX_MXC_SANDBOX_NO_NETWORK'
        return value

    def validate(self, spec, cwd):
        from loommode.host.managed_native import BINARY, BINARY_SHA256, ManagedNativeHost
        if (os.name != 'nt' or self.test_id != spec.test_id
                or self.spec_sha256 != _digest(asdict(spec)) or self.cwd != cwd
                or self.argv[0] != str(BINARY) or self.binary_sha256 != BINARY_SHA256
                or hashlib.sha256(BINARY.read_bytes()).hexdigest() != self.binary_sha256
                or hashlib.sha256(PYTHON.read_bytes()).hexdigest() != self.python_sha256
                or self.python_sha256 != PYTHON_SHA256):
            raise RuntimeError('fixed sandbox test launch identity unavailable/mismatched; no fallback')
        expected_bootstrap = _root_import_bootstrap(self.cwd, self.root_import_index)
        expected_python = _fixed_test_python_argv(spec, expected_bootstrap)
        if (self.root_import_bootstrap != expected_bootstrap
                or self.root_import_bootstrap_sha256 != hashlib.sha256(expected_bootstrap.encode()).hexdigest()
                or tuple(self.argv[-len(expected_python):]) != expected_python):
            raise RuntimeError('fixed sandbox root-index launch changed; no fallback')
        if self.host_identity_sha256 != _digest(ManagedNativeHost._identity()):
            raise RuntimeError('sandbox test Host source identity changed; no fallback')

def sandbox_test_plan(request, spec, *, working_root, records_root):
    from loommode.host.managed_native import BINARY, BINARY_SHA256, ManagedNativeHost
    from loommode.workflow.managed_cli import cli_argv, native_launch_plan
    config = request.config.managed
    if (config is None or config.cli_version != '0.162.1' or config.windows_sandbox != 'mxc'
            or Path(config.cli_path) != BINARY or tuple(config.runtime_read_paths) != PYTHON_RUNTIME
            or tuple(spec.argv[:4]) != (str(PYTHON).replace('\\', '/'), '-I', '-S', '-B')
            or tuple(spec.argv[4:8]) != ('-m', 'unittest', 'discover', '-s')
            or len(spec.argv) != 13 or spec.argv[8:12] != ('tests', '-t', '.', '-p')
            or not re.fullmatch(r'test_[A-Za-z0-9_.*?\[\]-]+\.py', spec.argv[12])
            or spec not in request.policy.test_specs
            or tuple(config.test_output_dirs) != ('artifacts',) or spec.cwd != '.'):
        raise RuntimeError('trusted fixed Python/unittest isolation capability absent; no fallback')
    workspace = request.policy.workspace.resolve(strict=True)
    working = Path(working_root).resolve(strict=True)
    records = Path(records_root).resolve(strict=True)
    home = Path(config.codex_home).resolve(strict=True)
    roots = [workspace, working, records, home]
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for i, a in enumerate(roots) for b in roots[i+1:]):
        raise RuntimeError('sandbox test roots overlap')
    # Bounded paths also work on ordinary Python installations without long-path opt-in.
    directory = working / 'ht' / request.fingerprint[:16] / _digest(asdict(spec))[:8]
    schema, result = directory / 'schema.json', directory / 'result.json'
    native = native_launch_plan(request, schema, result, records_root=records)
    argv = cli_argv(request, schema, result, records_root=records)
    prefix = argv[:argv.index('exec')]
    # Test code is read-only, including files writable by the model during implementation.
    # Only explicitly excluded outputs and the sandbox's own temporary path can write.
    position = next(i for i, item in enumerate(prefix)
                    if item.startswith('permissions.loommode_implementation.filesystem='))
    permissions = {':minimal': 'read', str(BINARY.resolve()): 'read'}
    permissions.update({str(Path(p).resolve()): 'read' for p in PYTHON_RUNTIME})
    permissions.update({str((workspace / p).resolve()): 'read'
                        for p in (*config.tool_read_dirs, *request.policy.readable_paths)})
    permissions.update({str((workspace / p).resolve()): 'write' for p in config.test_output_dirs})
    temporary = workspace / 'artifacts' / 'ht' / request.fingerprint[:16] / _digest(asdict(spec))[:8]
    permissions[str(temporary)] = 'write'
    denied = [records, home, working, directory, *[Path(p) for p in RUNTIME_DENIED]]
    if config.credential_file:
        denied.append(Path(config.credential_file))
    denied += [schema, result, directory / 'launch.json', workspace / '.git',
               workspace / '.env', workspace / 'credentials']
    from loommode.workflow.managed_cli import managed_tool_paths
    denied += [workspace / p for p in managed_tool_paths(request, records_root=records, working_root=working)]
    permissions.update({str(p.resolve()): 'deny' for p in denied})
    root_index = _root_import_index(workspace, permissions)
    bootstrap = _root_import_bootstrap(workspace, root_index)
    python_argv = _fixed_test_python_argv(spec, bootstrap)
    table = '{ ' + ', '.join(json.dumps(k)+' = '+json.dumps(v) for k,v in permissions.items()) + ' }'
    prefix[position] = 'permissions.loommode_implementation.filesystem=' + table
    command = prefix + ['sandbox', '--permission-profile', 'loommode_implementation',
        '--include-managed-config', '--sandbox-state-disable-network', '--cd', str(workspace), '--', *python_argv]
    env = dict(native.environment)
    env.update({'TEMP': str(temporary), 'TMP': str(temporary),
                'PSModuleAnalysisCachePath': str(temporary / 'ModuleAnalysisCache')})
    env.update({'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'})
    plan = SandboxTestPlan(spec.test_id, _digest(asdict(spec)), request.fingerprint,
        _digest({'policy': asdict(request.policy), 'permissions': permissions}), tuple(command),
        workspace, tuple(sorted(env.items())), BINARY_SHA256, PYTHON_SHA256, directory,
        _digest(ManagedNativeHost._identity()), root_index, bootstrap,
        hashlib.sha256(bootstrap.encode()).hexdigest())
    plan.validate(spec, workspace)
    return plan
