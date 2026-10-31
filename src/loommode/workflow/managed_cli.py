"""One Host-owned CLI lifecycle shared by explicit fixtures and future native proof.

Production remains closed at A1's trusted native preflight. Fixtures cannot be
selected by configuration or the Executor production route.
"""
from dataclasses import dataclass, replace
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import tempfile
from threading import Event, Lock, Thread
import time
from typing import Callable
from uuid import uuid4

from loommode.roles.contracts import empty_result, parse_result, result_schema, validate, obj, text, enum
from loommode.roles.runtime import Invocation
from loommode.tools.owned_job import OwnedJob
from loommode.tools.runtime import BoundedToolRuntime
from loommode.tools.task_proof import HostTaskProof
from .errors import WorkflowError
from .implementation import ImplementationRequest, MANAGED_CODEX_CLI
from .state import unique_json_object
from .transitions import Node


@dataclass(frozen=True)
class CliLimits:
    timeout_seconds: float = 60
    cleanup_seconds: float = 2
    stdin_bytes: int = 65536
    stream_bytes: int = 65536
    result_bytes: int = 65536

    def __post_init__(self):
        if (any(type(value) not in {int, float} or not math.isfinite(value) or value <= 0
                for value in (self.timeout_seconds, self.cleanup_seconds))
                or any(type(value) is not int or value <= 0 for value in
                       (self.stdin_bytes, self.stream_bytes, self.result_bytes))):
            raise WorkflowError("CLI limits must be explicit finite positive bounds")


@dataclass(frozen=True)
class SyntheticCliFixture:
    root: Path
    python: Path
    script: Path
    script_sha256: str
    case: str
    marker: str = "LOOMMODE_SYNTHETIC_NONSECRET_MARKER"

    def check(self, request):
        root = self.root.resolve(strict=True)
        if (not root.is_relative_to(Path(tempfile.gettempdir()).resolve()) or root == Path(tempfile.gettempdir()).resolve()
                or not request.policy.workspace.resolve(strict=True).is_relative_to(root)
                or not Path(request.config.managed.codex_home).resolve().is_relative_to(root)
                or not self.python.is_absolute() or not self.python.is_file()
                or not self.script.is_absolute() or not self.script.is_file()
                or hashlib.sha256(self.script.read_bytes()).hexdigest() != self.script_sha256
                or not self.marker.startswith("LOOMMODE_SYNTHETIC_") or not self.case.isidentifier()):
            raise WorkflowError("explicit disposable synthetic fixture identity required")


class ManagedCliFailure(WorkflowError):
    def __init__(self, reason, receipt):
        super().__init__("managed CLI stopped: " + reason)
        self.receipt = receipt


@dataclass(frozen=True)
class _Launch:
    argv: tuple[str, ...]
    environment: dict[str, str]
    redactions: tuple[str, ...]
    origin: str
    production_eligible: bool = False
    authority: dict | None = None


CONTROL_VERSION = "LM2_C1_MANAGED_WIRE_V1"
PARENT_HTTP_ROUTE = "REQWEST_0_12_28_DIRECT_NO_PROXY_NO_SYSTEM_FALLBACK"
TOOL_ENVIRONMENT = ("SystemDrive", "SystemRoot", "WINDIR", "HOME", "USERPROFILE", "APPDATA",
                    "LOCALAPPDATA", "TEMP", "TMP", "PSModuleAnalysisCachePath")


def managed_tool_paths(request, *, records_root=None, working_root=None):
    """Validate nonsecret intent; exact Native Grant still authorizes its use."""
    config, workspace = request.config.managed, request.policy.workspace.resolve(strict=True)
    names = {'.git', '.env', 'credentials'}
    if any(any(part.lower() in names for part in Path(p).parts) for p in request.policy.readable_paths):
        raise WorkflowError('managed file grant names a protected input')
    denied = {Path(p) for p in config.tool_denied_paths}
    denied.update(Path(name) for name in names)
    visited = set()
    def scan(path):
        relative = path.relative_to(workspace)
        if relative in visited:
            return
        visited.add(relative)
        if len(visited) > 4096:
            raise WorkflowError('managed directory safety scan exceeds bound')
        if path.is_symlink() or (path.exists() and getattr(path.lstat(), 'st_file_attributes', 0) & 0x400):
            raise WorkflowError('managed directory contains links/reparse')
        if path.name.lower() in names or relative in denied:
            denied.add(relative)
            return  # Never open/enumerate a protected input.
        if not path.exists():
            return
        if path.is_dir():
            for child in sorted(path.iterdir()):
                scan(child)
    for relative in (*config.tool_read_dirs, *config.tool_write_dirs):
        scan(workspace / relative)
        denied.update(Path(relative) / name for name in names)
    for relative in (*config.tool_read_dirs, *config.tool_write_dirs, *config.test_output_dirs, *config.tool_denied_paths):
        target = workspace / relative
        if not target.resolve().is_relative_to(workspace):
            raise WorkflowError('managed directory intent escapes workspace')
        for part in (target, *target.parents):
            if part == workspace:
                break
            if part.exists() and (part.is_symlink() or getattr(part.lstat(), 'st_file_attributes', 0) & 0x400):
                raise WorkflowError('managed directory intent links/reparse denied')
    # Intent scope includes AI-authored prose, not a directory ACL. Actual
    # directory permission requires the exact trusted Native Grant below the
    # Session boundary; Host checkpoint files still require literal Intent scope.
    for relative in config.tool_write_dirs:
        if (relative not in config.test_output_dirs and not any(
                Path(name).is_relative_to(Path(relative)) for name in request.policy.writable_paths)):
            raise WorkflowError('managed write directory unrelated to Host Task files or explicit test output')
    for relative in config.test_output_dirs:
        output = workspace / relative
        if any((workspace / p).resolve().is_relative_to(output.resolve()) for p in request.policy.readable_paths):
            raise WorkflowError('test output exclusion contains declared source/test input')
    protected = [workspace, Path(config.codex_home), Path.home(),
                 *([Path(config.credential_file)] if config.credential_file else []),
                 *([Path(records_root)] if records_root is not None else []),
                 *([Path(working_root)] if working_root is not None else [])]
    for value in config.runtime_read_paths:
        runtime = Path(value)
        if not runtime.exists():
            raise WorkflowError('declared runtime read path absent')
        for part in (runtime, *runtime.parents):
            if part.is_symlink() or getattr(part.lstat(), 'st_file_attributes', 0) & 0x400:
                raise WorkflowError('runtime read path links/reparse denied')
        if any(runtime.resolve() == p.resolve() or runtime.resolve().is_relative_to(p.resolve())
               or p.resolve().is_relative_to(runtime.resolve()) for p in protected):
            raise WorkflowError('runtime read overlaps protected project/home/Records/credential')
    return tuple(sorted(p.as_posix() for p in denied))


def cli_argv(request, schema_path, result_path, *, report_only=False, records_root=None):
    """Deterministic target argv, never shell text or a credential value."""
    config = request.config.managed
    options = {"model_provider": config.provider,
               f"model_providers.{config.provider}.name": config.provider,
               f"model_providers.{config.provider}.base_url": config.endpoint,
               f"model_providers.{config.provider}.wire_api": config.wire_api,
               f"model_providers.{config.provider}.env_key": config.credential_env,
               "windows.sandbox": config.windows_sandbox,
               "shell_environment_policy.exclude": [config.credential_env]}
    if config.reasoning_effort is not None:
        options["model_reasoning_effort"] = config.reasoning_effort
    filesystem = None
    if config.cli_version == "0.162.1":
        from loommode.host.managed_native import RECORDS, TRUSTED_RECORDS_ROOT
        protected_paths = managed_tool_paths(request, records_root=records_root or TRUSTED_RECORDS_ROOT,
                                             working_root=Path(schema_path).parent.parent)
        # exec --ignore-user-config skips both user and project layers. Supply
        # the named permission profile explicitly; passing
        # --sandbox would select Legacy and defeat this profile (fixed source
        # config/mod.rs resolve_permission_config_syntax).
        options.update({"default_permissions": "loommode_implementation",
            "cli_auth_credentials_store": "file", "project_root_markers": [".loommode-project-root"],
            "check_for_update_on_startup": False, "features.network_proxy": False,
            "features.respect_system_proxy": False, "features.system_proxy_fallback": False,
            "web_search": "disabled",
            "features.prefer_mxc": False, "analytics.enabled": False, "feedback.enabled": False,
            "otel.exporter": "none", "otel.trace_exporter": "none", "otel.metrics_exporter": "none",
            "shell_environment_policy.inherit": "all", "shell_environment_policy.ignore_default_excludes": False,
            "shell_environment_policy.include_only": list(TOOL_ENVIRONMENT),
            "permissions.loommode_implementation.network.enabled": False})
        filesystem = {":minimal": "read", str(Path(config.cli_path).resolve()): "read"}
        for path in config.runtime_read_paths:
            filesystem[str(Path(path).resolve())] = 'read'
        from loommode.tools.sandbox_test import runtime_denials
        for path in runtime_denials(config):
            filesystem[str(Path(path).resolve())] = 'deny'
        for relative in config.tool_read_dirs:
            filesystem[str((request.policy.workspace / relative).resolve())] = 'read'
        if not report_only:
            for relative in config.tool_write_dirs:
                filesystem[str((request.policy.workspace / relative).resolve())] = 'write'
        for relative in request.policy.readable_paths:
            filesystem[str((request.policy.workspace / relative).resolve())] = "read"
        for relative in (() if report_only else request.policy.writable_paths):
            filesystem[str((request.policy.workspace / relative).resolve())] = "write"
        filesystem[str(Path(schema_path).parent / "tool-tmp")] = "write"
        secret_paths = [request.policy.workspace / p for p in protected_paths]
        for denied in (str(TRUSTED_RECORDS_ROOT), str(RECORDS), records_root, config.codex_home, config.credential_file,
                       str(schema_path), str(result_path), *secret_paths):
            if denied is not None:
                filesystem[str(Path(denied).resolve())] = "deny"
    if report_only:
        options.update({'features.shell_tool': False, 'features.unified_exec': False,
                        'features.shell_snapshot': False})
    argv = [config.cli_path, "-a", config.approval_policy]
    for name, value in options.items():
        argv.extend(["-c", name + "=" + json.dumps(value)])
    if filesystem is not None:
        # Fixed CLI parses the RHS as TOML, but does not TOML-unquote segments
        # on the LHS. Keep path keys (including :minimal and dotted Windows
        # filenames) inside one TOML inline-table value, not dotted override keys.
        table = "{ " + ", ".join(json.dumps(path) + " = " + json.dumps(access)
                                  for path, access in filesystem.items()) + " }"
        argv.extend(["-c", "permissions.loommode_implementation.filesystem=" + table])
    sandbox = ["--sandbox", 'read-only' if report_only else config.sandbox_mode] if config.cli_version == "0.160.1" else []
    return argv + ["exec", "--ignore-user-config", "--json", *sandbox, "--cd", str(request.policy.workspace.resolve()),
                   "--model", config.model, "--output-schema", str(schema_path),
                   "--output-last-message", str(result_path), "-"]


@dataclass(frozen=True)
class NativeLaunchPlan:
    """Nonsecret launch intent only; no credential resolution or security proof."""
    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...]
    credential_env: str


def native_launch_plan(request, schema_path, result_path, *, records_root=None):
    home = Path(request.config.managed.codex_home)
    temporary = Path(schema_path).parent / "tool-tmp"
    environment = {"SystemDrive": "C:", "SystemRoot": "C:/Windows", "WINDIR": "C:/Windows",
        "CODEX_HOME": str(home), "HOME": str(home), "USERPROFILE": str(home),
        "APPDATA": str(home / "appdata"), "LOCALAPPDATA": str(home / "localappdata"),
        "TEMP": str(temporary), "TMP": str(temporary),
        "NO_PROXY": "*", "no_proxy": "*",
        "PSModuleAnalysisCachePath": str(temporary / "ModuleAnalysisCache")}
    return NativeLaunchPlan(tuple(cli_argv(request, schema_path, result_path, records_root=records_root)),
        request.policy.workspace.resolve(strict=True),
        tuple(sorted(environment.items())), request.config.managed.credential_env)


def _require_native_capability(host, request, working_root, limits):
    from loommode.host.managed_native import ManagedNativeHost
    from loommode.host.successor import SuccessorNativeHost
    if type(host) not in (ManagedNativeHost, SuccessorNativeHost):
        raise WorkflowError("managed native execution unavailable: concrete Host and exact V4 runtime grant required")
    return host.check(request, working_root, limits)


def cli_usage(events):
    """Reported CLI token counts only, never a provider billing estimate."""
    usage = events[-1].get('usage')
    if (not isinstance(usage, dict) or any(type(usage.get(key)) is not int or usage[key] < 0
            for key in ('input_tokens', 'output_tokens'))):
        return None
    result = {key: usage[key] for key in ('input_tokens', 'output_tokens')}
    if 'cached_input_tokens' in usage:
        if type(usage['cached_input_tokens']) is not int or not 0 <= usage['cached_input_tokens'] <= usage['input_tokens']:
            return None
        result['cached_input_tokens'] = usage['cached_input_tokens']
    return result


def completed_reply_matches(content, events):
    starts = [i for i, event in enumerate(events) if event.get('type') == 'thread.started']
    turns = [i for i, event in enumerate(events) if event.get('type') == 'turn.started']
    ends = [i for i, event in enumerate(events) if event.get('type') == 'turn.completed']
    messages = [i for i, event in enumerate(events) if event.get('type') == 'item.completed'
                and event.get('item', {}).get('type') == 'agent_message']
    return bool(len(starts) == len(turns) == len(ends) == 1 and messages
        and starts[0] < turns[0] < messages[-1] < ends[0] == len(events) - 1
        and all(event.get('type') not in {'error', 'turn.failed'} for event in events)
        and isinstance(events[messages[-1]]['item'].get('text'), str)
        and events[messages[-1]]['item']['text'].strip() == content.strip())


def managed_result_schema():
    return obj({'action': enum(['REPORT_READY', 'HUMAN_REQUIRED']),
                'report': text(), 'explanation': text()})


def _parse_managed_result(content):
    # Extract exactly one top-level control object, with the same ambiguity
    # and duplicate-key rejection as the original role contract.
    decoder = json.JSONDecoder(object_pairs_hook=unique_json_object)
    candidates, offset = [], 0
    def has_control(value):
        if isinstance(value, dict):
            return 'action' in value or any(has_control(item) for item in value.values())
        return isinstance(value, list) and any(has_control(item) for item in value)
    while (start := content.find('{', offset)) >= 0:
        try:
            value, offset = decoder.raw_decode(content, start)
        except (ValueError, TypeError) as exc:
            raise WorkflowError('malformed managed control object') from exc
        if isinstance(value, dict) and 'action' in value:
            if content[:start].rstrip().endswith('['):
                raise WorkflowError('array-wrapped managed control object')
            candidates.append(value)
        elif has_control(value):
            raise WorkflowError('nested managed control object')
    if len(candidates) != 1:
        raise WorkflowError('expected one unambiguous managed control object')
    value = candidates[0]
    if 'report' not in value:
        return parse_result(content, Node.EXECUTOR_IMPLEMENT)  # legacy full wire
    validate(value, managed_result_schema())
    result = empty_result(value['action'], value['explanation'])
    result['artifacts'] = [{'kind': 'EXECUTION_REPORT', 'content': value['report']}]
    return result  # No fabricated tests, quality judgments or authority.


def parse_completed_cli_result(raw, events):
    """Validate a final JSON object, including one bounded CLI prose preface.

    A preface is accepted only when the result file agrees with the last
    completed agent-message event from this same completed Turn. The JSON
    suffix still has to satisfy the full Executor schema.
    """
    content = raw.decode('utf-8', 'strict')
    try:
        json.loads(content, object_pairs_hook=unique_json_object)
        return _parse_managed_result(content), 'OUTPUT_LAST_MESSAGE_JSON'
    except (WorkflowError, json.JSONDecodeError) as strict_error:
        if not completed_reply_matches(content, events):
            raise WorkflowError('final reply lacks matching completed event') from strict_error
        try:
            result = _parse_managed_result(content)
        except WorkflowError:
            raise
        return result, 'COMPLETED_EVENT_JSON_SUFFIX'


class ManagedCliSession:
    def __init__(self, working_root: Path, host_preflight, reserve_dispatch: Callable, *, limits=CliLimits(), native_host=None):
        self.working_root = working_root.resolve(strict=True)
        self.host_preflight, self.reserve_dispatch, self.limits = host_preflight, reserve_dispatch, limits
        self.native_host = native_host
        self.tasks = {}
        self.implementation_receipts = {}
        self.generations = {}
        self.protected_paths = {}
        self.last_receipt = None
        self._dispatch_lock = Lock()
        self._state_lock = Lock()
        self._close_lock = Lock()
        self._cancel = Event()
        self._done = Event()
        self._done.set()
        self._closed = False
        self._degraded = []
        self._close_receipt = None
        self._usage_unproved = False

    def preflight(self, request, materials, *, fixture=None):
        if self._closed or not self.health()['healthy'] or self._cancel.is_set():
            raise WorkflowError("managed backend closed/unhealthy; later dispatch fenced")
        if fixture is None and self._usage_unproved:
            raise WorkflowError('native CLI usage unknown; later dispatch fenced without allowance reset')
        if request.config.backend != MANAGED_CODEX_CLI:
            raise WorkflowError("managed CLI selection mismatch")
        if self.host_preflight is None:
            raise WorkflowError("managed CLI lacks trusted Host preflight")
        self.host_preflight.check(request)
        binding = request.binding
        for ref, digest in ((binding["intent_ref"], request.intent_sha256), (binding["final_ref"], request.final_sha256)):
            if (ref not in materials or not isinstance(materials[ref], str)
                    or hashlib.sha256(materials[ref].encode()).hexdigest() != digest):
                raise WorkflowError("managed original material digest mismatch")
        payload = self._payload(request, materials, report_only=False)
        prior = self.tasks.get(binding["task_id"])
        if prior and prior[0] != request:
            raise WorkflowError("managed same-Task original configuration/input changed")
        if fixture is None:
            _require_native_capability(self.native_host, request, self.working_root, self.limits)
        else:
            fixture.check(request)
            if fixture.marker.encode() in payload:
                raise WorkflowError("synthetic credential must not enter prompt/materials")
        return payload

    def _payload(self, request, materials, *, report_only):
        binding = request.binding
        envelope = {"activity": 'REPORT_CORRECTION' if report_only else Node.EXECUTOR_IMPLEMENT.value,
                    "binding": binding, 'original_intent_ref': binding['intent_ref'],
                    'final_constraint_ref': binding['final_ref'], "materials": materials,
                    'result_schema': managed_result_schema()}
        if request.config.managed.cli_version == '0.162.1':
            # Host policy facts, not a rewrite of the AI's original Task or report.
            envelope['host_execution'] = {
                'workspace': str(request.policy.workspace),
                'readable_paths': list(request.policy.readable_paths),
                'writable_paths': list(request.policy.writable_paths),
                'readable_directories': list(request.config.managed.tool_read_dirs),
                'writable_directories': list(request.config.managed.tool_write_dirs),
                'runtime_read_paths': list(request.config.managed.runtime_read_paths),
                'host_test_ids': [spec.test_id for spec in request.policy.test_specs],
                'tool_environment': 'PATH is intentionally absent; use absolute executable and file paths supplied in the Task materials.',
                'filesystem': 'Only explicitly granted files/directories are accessible. The workspace .git is denied to model tools.',
                'git_responsibility': 'The trusted Host owns Git baseline/status/diff and checkpoint; do not probe Git from model tools.',
                'completion': 'Return the supplied small JSON schema: REPORT_READY, report and explanation, or HUMAN_REQUIRED with the actual finding. Report work and failures truthfully. Host fixed tests and role judgments are recorded separately; never invent evidence.'}
        if report_only:
            envelope['instruction'] = ('Correct only the saved report using original output and actual evidence. '
                                       'No tools, implementation, tests, Git or other side effects.')
        payload = json.dumps(envelope, ensure_ascii=False).encode()
        if len(payload) > self.limits.stdin_bytes:
            raise WorkflowError("managed stdin exceeds explicit bound")
        return payload

    def execute_native(self, request, materials, cancel_signal=None):
        payload = self.preflight(request, materials)
        return self._execute(request, payload, self._native_launch, "managed-cli:", cancel_signal)

    def _native_launch(self, request, schema_path, result_path, *, report_only=False):
        admission = _require_native_capability(self.native_host, request, self.working_root, self.limits)
        from loommode.host.managed_native import ManagedNativeHost, TRUSTED_RECORDS_ROOT
        # The original concrete Host has fixed Records and no locations property.
        records_root = (TRUSTED_RECORDS_ROOT if type(self.native_host) is ManagedNativeHost
                        else self.native_host.records_root)
        plan = native_launch_plan(request, schema_path, result_path, records_root=records_root)
        if report_only:
            plan = replace(plan, argv=tuple(cli_argv(request, schema_path, result_path, report_only=True,
                                                   records_root=records_root)))
        secret = self.native_host.resolve_credential(request, admission, self.working_root, self.limits)
        environment = dict(plan.environment)
        environment[plan.credential_env] = secret
        Path(environment['TEMP']).mkdir()
        return _Launch(plan.argv, environment, (secret,), admission.origin, admission.production_eligible,
            {'runtime_grant_sha256': admission.grant_sha256,
             'host_configuration_sha256': admission.grant['host_configuration_sha256'],
             'accepted_native_sha256': admission.grant.get('accepted_native_sha256')})

    def execute_fixture(self, request, materials, fixture: SyntheticCliFixture, cancel_signal=None) -> Invocation:
        payload = self.preflight(request, materials, fixture=fixture)
        return self._execute(request, payload, lambda r, s, o: self._fixture_launch(r, s, o, fixture),
                             "managed-fixture:", cancel_signal)

    def _fixture_launch(self, request, schema_path, result_path, fixture, *, report_only=False):
        target_argv = cli_argv(request, schema_path, result_path, report_only=report_only)
        argv = (str(fixture.python), "-B", str(fixture.script), "--fixture-case", fixture.case,
                "--fixture-root", str(fixture.root), *target_argv[1:])
        env = {name: os.environ[name] for name in ("SystemRoot", "WINDIR", "TEMP", "TMP") if name in os.environ}
        env.update({"PYTHONDONTWRITEBYTECODE": "1", "CODEX_HOME": request.config.managed.codex_home,
                    request.config.managed.credential_env: fixture.marker})
        return _Launch(argv, env, (fixture.marker,), "SYNTHETIC_CLI_FIXTURE")

    def correct_report(self, request, materials, *, fixture=None):
        # Same pinned request and exact current Grant; each extra call reserves
        # normal provider capacity. Never refund/replay the implementation.
        self.preflight(request, materials, fixture=fixture)
        if request.binding['task_id'] not in self.tasks:
            raise WorkflowError('report correction requires an existing implementation proof')
        payload = self._payload(request, materials, report_only=True)
        launch = ((lambda req, schema, result: self._fixture_launch(req, schema, result, fixture, report_only=True))
                  if fixture else (lambda req, schema, result: self._native_launch(req, schema, result, report_only=True)))
        return self._execute(request, payload, launch,
            'managed-fixture:' if fixture else 'managed-cli:', None, report_only=True)

    def _execute(self, request, payload, prepare_launch, context_prefix, cancel_signal, *, report_only=False):
        if not self._dispatch_lock.acquire(blocking=False):
            raise WorkflowError("managed implementation invocation already active")
        try:
            with self._state_lock:
                if self._closed or not self.health()['healthy'] or self._cancel.is_set():
                    raise WorkflowError("managed backend closed/unhealthy; dispatch fenced")
                if context_prefix == 'managed-cli:' and self._usage_unproved:
                    raise WorkflowError('native CLI usage unknown; dispatch fenced without allowance reset')
                self._done.clear()
            binding = request.binding
            # Preflight may have completed before another invocation pinned the
            # Task. Revalidate while owning dispatch, before any proof or launch
            # mutation, so the original request remains authoritative.
            prior = self.tasks.get(binding["task_id"])
            if prior and prior[0] != request:
                raise WorkflowError("managed same-Task original configuration/input changed")
            if context_prefix == "managed-cli:":
                _require_native_capability(self.native_host, request, self.working_root, self.limits)
            if binding["task_id"] not in self.tasks:
                runtime = BoundedToolRuntime(request.policy)
                runtime.configure_task(request.policy, task_binding=binding)
                proof = HostTaskProof(runtime, context_ref=context_prefix + str(uuid4()), backend=MANAGED_CODEX_CLI)
                self.tasks[binding["task_id"]] = (request, proof)
            proof = self.tasks[binding["task_id"]][1]
            if not report_only:
                current_protected = managed_tool_paths(request)
                pinned_protected = self.protected_paths.setdefault(binding['task_id'], current_protected)
                if current_protected != pinned_protected:
                    raise WorkflowError('managed protected directory set changed; inspect without replay')
                proof.runtime.configure_task(request.policy, task_binding=binding)
                self.generations[binding['task_id']] = self.generations.get(binding['task_id'], 0) + 1
                proof.clear_managed_tests()
            try:
                return self._run(request, payload, prepare_launch, proof, cancel_signal)
            finally:
                if not report_only and self.last_receipt:
                    self.implementation_receipts[binding['task_id']] = copy.deepcopy(self.last_receipt)
        finally:
            self._done.set()
            self._dispatch_lock.release()

    def _run(self, request, payload, prepare_launch, proof, cancel_signal):
        attempt = str(uuid4())
        directory = result_path = None
        receipt = {"attempt_id": attempt, "origin": "UNVERIFIED_LAUNCH", "production_eligible": False,
                   "request_fingerprint": request.fingerprint, "context_ref": proof.context_ref,
                   "pid": None, "exit_code": None, "may_have_dev_effects": False,
                   "stdout": "", "stderr": "", "stdin_complete": False, "truncated": False,
                   "cleanup": None, "reservation_ref": None, "outcome": None}
        job, process, workers = None, None, {}
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        stream_lock = Lock()
        excess, io_error, stdin_done = Event(), Event(), Event()
        reason, structured, session_ref = None, None, None
        output_problem = False
        started = time.monotonic()
        launch = None
        def redact(value):
            for marker in launch.redactions if launch else ():
                value = value.replace(marker, "[REDACTED]")
            return value

        def contains_secret(value):
            return any(marker.encode() in value for marker in (launch.redactions if launch else ()))
        try:
            directory = Path(tempfile.mkdtemp(prefix="managed-" + attempt + "-", dir=self.working_root))
            schema_path, result_path = directory / "schema.json", directory / "result.json"
            schema_path.write_text(json.dumps(managed_result_schema()), encoding="utf-8")
            launch = prepare_launch(request, schema_path, result_path)
            receipt["origin"] = launch.origin
            receipt['production_eligible'] = launch.production_eligible
            receipt['native_authority'] = launch.authority
            receipt['parent_http_route'] = PARENT_HTTP_ROUTE if launch.origin.startswith('NATIVE_MXC_') else 'SYNTHETIC_ONLY'
            if any(marker in " ".join(launch.argv) for marker in launch.redactions):
                raise WorkflowError("credential in argv")
            if result_path.exists():
                raise WorkflowError("attempt result already exists")
            if self._cancel.is_set() or (cancel_signal and cancel_signal.is_set()):
                raise WorkflowError("cancelled before reservation")
            if launch.origin in {"NATIVE_MXC_V4_BOUNDED_VALIDATION", "NATIVE_MXC_ACCEPTED_PRODUCTION", "NATIVE_MXC_BOUNDED_CANDIDATE_VALIDATION"}:
                if contains_secret(payload):
                    raise WorkflowError("credential must not enter prompt/materials")
                self.native_host.reserve(request, attempt, self.working_root, self.limits)
            # Reservation is a launch-side mutation, never called by preflight.
            reservation = self.reserve_dispatch(request, attempt)
            if not isinstance(reservation, str) or not reservation.strip():
                raise WorkflowError("trusted dispatch reservation missing")
            receipt["reservation_ref"] = reservation
            job = OwnedJob()
            process = job.launch(launch.argv, cwd=request.policy.workspace, env=launch.environment)
            receipt["pid"], receipt["may_have_dev_effects"] = process.pid, True

            def read_stream(name, pipe):
                try:
                    while block := pipe.read(8192):
                        with stream_lock:
                            remaining = self.limits.stream_bytes - sum(len(value) for value in buffers.values())
                            buffers[name].extend(block[:max(0, remaining)])
                            if len(block) > remaining:
                                excess.set()
                except OSError:
                    io_error.set()
                finally:
                    pipe.close()

            def write_stdin():
                try:
                    view = memoryview(payload)
                    while view:
                        written = process.stdin.write(view[:8192])
                        if not written:
                            raise OSError("stdin closed")
                        view = view[written:]
                    stdin_done.set()
                except OSError:
                    io_error.set()
                finally:
                    process.stdin.close()

            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                workers[name] = Thread(target=read_stream, args=(name, pipe), name="managed-" + name, daemon=True)
            workers["stdin"] = Thread(target=write_stdin, name="managed-stdin", daemon=True)
            for thread in workers.values():
                thread.start()
            while process.poll() is None:
                if self._cancel.is_set() or (cancel_signal and cancel_signal.is_set()):
                    reason = "cancelled"
                    break
                if excess.is_set():
                    reason = "stream output exceeded bound"
                    break
                if time.monotonic() - started >= self.limits.timeout_seconds:
                    reason = "timeout"
                    break
                time.sleep(.01)
        except Exception as exc:
            reason = "launch/reservation failure: " + type(exc).__name__
        finally:
            if job:
                receipt["cleanup"] = job.stop(self.limits.cleanup_seconds)
                if job.process and receipt["pid"] is None:
                    receipt["pid"] = job.process.pid
                    receipt["may_have_dev_effects"] = job.assigned
                process = job.process
            else:
                receipt["cleanup"] = {"root_terminated": True, "tree_terminated_confirmed": True,
                                      "job_handle_closed": True, "unknown_side_effect": False}
            deadline = time.monotonic() + self.limits.cleanup_seconds
            for thread in workers.values():
                if thread.ident is not None:  # Thread.start itself may have failed.
                    thread.join(timeout=max(0, deadline - time.monotonic()))
            receipt["cleanup"]["io_threads_joined"] = all(not thread.is_alive() for thread in workers.values())
            receipt["stdin_complete"] = stdin_done.is_set()
            receipt["truncated"] = excess.is_set()
            if process:
                receipt["exit_code"] = process.poll()
                # Close only pipes whose worker is absent or joined. This also
                # handles a partial Thread.start failure without blocking close
                # against a worker that is still using its pipe.
                for name in ("stdin", "stdout", "stderr"):
                    pipe, worker = getattr(process, name), workers.get(name)
                    if pipe and (worker is None or not worker.is_alive()):
                        try:
                            pipe.close()
                        except OSError:
                            pass  # pipes_closed below retains the unknown fact.
                receipt["cleanup"]["pipes_closed"] = all(pipe.closed for pipe in
                    (process.stdin, process.stdout, process.stderr))
                if receipt["cleanup"]["root_terminated"]:
                    try:
                        process._handle.Close()
                        receipt["cleanup"]["process_handle_closed"] = True
                    except OSError:
                        receipt["cleanup"]["process_handle_closed"] = False
                else:
                    receipt["cleanup"]["process_handle_closed"] = False
            else:
                receipt["cleanup"].update(pipes_closed=True, process_handle_closed=True)
            receipt["cleanup"]["unknown_side_effect"] |= not all(receipt["cleanup"][key] for key in
                ("io_threads_joined", "pipes_closed", "process_handle_closed"))
            if receipt["cleanup"]["unknown_side_effect"]:
                self._degraded.append("owned resource cleanup unproved")
                reason = reason or "owned resource cleanup unproved"
            proof.runtime.suspend_mutations()
        try:
            for name, raw in buffers.items():
                receipt[name] = redact(bytes(raw).decode("utf-8", "strict"))
            if any(contains_secret(raw) for raw in buffers.values()):
                raise WorkflowError("credential leaked into CLI output")
            if reason:
                raise WorkflowError(reason)
            if self._cancel.is_set() or (cancel_signal and cancel_signal.is_set()):
                raise WorkflowError("cancelled")
            if excess.is_set() or io_error.is_set() or not stdin_done.is_set():
                raise WorkflowError("incomplete/bounded CLI IO")
            if receipt["exit_code"] != 0:
                raise WorkflowError("nonzero CLI exit")
            stdout = bytes(buffers["stdout"]).decode("utf-8")
            if not stdout.endswith("\n"):
                raise WorkflowError("incomplete JSONL output")
            events = [json.loads(line, object_pairs_hook=unique_json_object) for line in stdout.splitlines()]
            if any(not isinstance(event, dict) or not isinstance(event.get("type"), str) for event in events):
                raise WorkflowError("malformed CLI event")
            starts = [event for event in events if event["type"] == "thread.started"]
            if (len(starts) != 1 or not isinstance(starts[0].get("thread_id"), str) or not starts[0]["thread_id"]
                    or sum(event["type"] == "turn.completed" for event in events) != 1
                    or events[-1]["type"] != "turn.completed"
                    or any(event["type"] in {"error", "turn.failed"} for event in events)):
                raise WorkflowError("CLI events do not establish a complete current session")
            session_ref = starts[0]["thread_id"]
            receipt['usage'] = cli_usage(events)
            receipt['usage_known'] = receipt['usage'] is not None
            receipt['usage_origin'] = 'CLI_TURN_COMPLETED_NOT_PROVIDER_BILLING'
            info = result_path.lstat()
            if not stat.S_ISREG(info.st_mode) or result_path.is_symlink() or info.st_nlink != 1:
                raise WorkflowError("final result is not a unique attempt regular file")
            with result_path.open("rb") as stream:
                raw = stream.read(self.limits.result_bytes + 1)
            if len(raw) > self.limits.result_bytes:
                raise WorkflowError("final result exceeded bound")
            if contains_secret(raw):
                raise WorkflowError("credential leaked into final result")
            receipt['raw_output'] = raw.decode('utf-8', 'strict')
            if not completed_reply_matches(receipt['raw_output'], events):
                raise WorkflowError('final reply lacks matching completed event')
            receipt['terminal_status'] = 'completed'
            try:
                structured, result_origin = parse_completed_cli_result(raw, events)
            except WorkflowError:
                # Only format of a proven current reply is correctable. Event/
                # result disagreement remains an execution-evidence failure.
                output_problem = completed_reply_matches(receipt['raw_output'], events)
                raise
            receipt['structured_result_origin'] = result_origin
            if structured['action'] == 'HUMAN_REQUIRED' and structured['escalation'] is None:
                structured['escalation'] = {'origin_role': 'Executor',
                    'origin_activity': Node.EXECUTOR_IMPLEMENT.value,
                    'stage_id': request.binding['stage_id'], 'task_id': request.binding['task_id'],
                    'category': 'INTERNAL_FINDING', 'reason': structured['explanation'],
                    'evidence_refs': [], 'requested_treatment': 'PLANNER_ADJUSTMENT'}
            receipt["outcome"] = "INVOCATION_READY"
            receipt["external_session_ref"] = session_ref
        except Exception as exc:
            reason = redact(str(exc))[:256]
            receipt["outcome"] = "FAILED"
            receipt["error"] = reason
        finally:
            if launch and launch.origin.startswith('NATIVE_MXC_') and not receipt.get('usage_known'):
                self._usage_unproved = True
            receipt["elapsed_ms"] = round((time.monotonic() - started) * 1000)
            try:
                if directory is None:
                    receipt["working_files_removed"] = True
                elif receipt["cleanup"]["unknown_side_effect"]:
                    receipt["working_files_removed"] = False
                    receipt["retained_working_directory"] = str(directory)
                else:
                    resolved = directory.resolve(strict=True)
                    if resolved == self.working_root or not resolved.is_relative_to(self.working_root):
                        raise OSError("attempt cleanup target escaped owned working root")
                    shutil.rmtree(directory)  # Unique Host-created attempt directory only.
                    receipt["working_files_removed"] = True
            except OSError:
                receipt["working_files_removed"] = False
                self._degraded.append("owned attempt files cleanup unproved")
                reason = reason or "owned attempt files cleanup unproved"
            if reason:
                receipt["outcome"], receipt["error"] = "FAILED", reason
            self.last_receipt = copy.deepcopy(receipt)
        if reason:
            if output_problem and not receipt['cleanup']['unknown_side_effect'] and receipt['working_files_removed']:
                from .errors import OutputProblem
                raise OutputProblem(reason, receipt['raw_output'], proof.context_ref, receipt)
            raise ManagedCliFailure(reason, receipt)
        return Invocation(structured, proof.context_ref, metadata=receipt)

    def run_host_tests(self, task_id):
        """Extend the same session's ownership through its fixed Host tests."""
        if not self._dispatch_lock.acquire(blocking=False):
            raise WorkflowError('managed invocation/tests already active')
        try:
            with self._state_lock:
                if self._closed or self._cancel.is_set() or not self.health()['healthy']:
                    raise WorkflowError('managed Host tests closed/unhealthy')
                self._done.clear()
            request, proof = self.tasks[task_id]
            from loommode.host.managed_native import TRUSTED_RECORDS_ROOT
            if managed_tool_paths(request) != self.protected_paths[task_id]:
                raise WorkflowError('managed worker created/removed a protected path; inspect before tests')
            proof.record_managed_tests(request, self.generations[task_id],
                                       self.implementation_receipts.get(task_id), self._cancel,
                                       working_root=self.working_root,
                                       records_root=getattr(self.native_host, 'records_root', TRUSTED_RECORDS_ROOT))
        finally:
            self._done.set()
            self._dispatch_lock.release()

    def cancel(self):
        self._cancel.set()

    def health(self):
        reasons = list(self._degraded)
        if any((proof.runtime.timeout_termination or {}).get('unknown_side_effect')
               for _, proof in tuple(self.tasks.values())):
            reasons.append("managed Host fixed-test cleanup unproved")
        eligible = bool((self.last_receipt or {}).get('production_eligible'))
        return {"healthy": not reasons, "closed": self._closed, "running": not self._done.is_set(),
                "production_eligible": eligible, "native_execute_available": eligible and not self._closed
                and not reasons and not self._usage_unproved,
                "dispatch_fenced_usage_unknown": self._usage_unproved,
                "reasons": reasons, "last_receipt": copy.deepcopy(self.last_receipt)}

    def close(self):
        with self._close_lock:
            if self._close_receipt is not None:
                return copy.deepcopy(self._close_receipt)
            with self._state_lock:
                self._closed = True
                self.cancel()
            done = self._done.wait(timeout=self.limits.cleanup_seconds * 3 + 1)
            if not done:
                self._degraded.append("active invocation did not join before close bound")
            health = self.health()
            self._close_receipt = {"closed": done, "healthy": health['healthy'],
                                   "unknown_side_effect": not health['healthy'], "last_receipt": self.last_receipt}
            return copy.deepcopy(self._close_receipt)
