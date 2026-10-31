"""Concrete, Records-bound admission for one fixed managed Codex preset.

V2 proves three assertions, not general Host admission. Only a new Owner runtime
grant at the fixed trusted Records path can authorize this exact exec combination.
There is no configurable proof lookup, secret callback or native fixture switch.
"""
from dataclasses import asdict, dataclass
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
from threading import RLock

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object

from .private_instance import private_value, require_private_instance

RECORDS = None  # Explicit Host private bootstrap only.
TRUSTED_RECORDS_ROOT = None  # Explicit Host private bootstrap only.
HOST_CONFIGURATION = None  # Explicit Host private bootstrap only.
ACCEPTED_NATIVE = None  # Explicit Host private bootstrap only.
V2_REVIEW = None  # Explicit Host private bootstrap only.
V2_SHA256 = None  # Explicit Host private bootstrap only.
RUNTIME_GRANT = None  # Explicit Host private bootstrap only.
OWNER_GRANT = None  # Explicit Host private bootstrap only.
CONTINUATION_RUNTIME_GRANT = None  # Explicit Host private bootstrap only.
CONTINUATION_OWNER_GRANT = None  # Explicit Host private bootstrap only.
F3_RUNTIME_GRANT = None  # Explicit Host private bootstrap only.
F3_OWNER_GRANT = None  # Explicit Host private bootstrap only.
F4_RUNTIME_GRANT = None  # Explicit Host private bootstrap only.
F4_OWNER_GRANT = None  # Explicit Host private bootstrap only.
F4_FIXTURE = None  # Explicit Host private bootstrap only.
F3_FIXTURE = None  # Explicit Host private bootstrap only.
F3_PRIOR_FIXTURE = None  # Explicit Host private bootstrap only.
F3_SECOND_FIXTURE = None  # Explicit Host private bootstrap only.
F3_THIRD_FIXTURE = None  # Explicit Host private bootstrap only.
F3_RETRY_EVIDENCE = None  # Explicit Host private bootstrap only.
_CONTINUATION_CHAIN = None  # Explicit Host private bootstrap only.
BINARY = None  # Explicit Host private bootstrap only.
BINARY_SHA256 = None  # Explicit Host private bootstrap only.
SOURCE_ROOT = Path(__file__).resolve().parents[3]
def source_files():
    # The trusted closure includes the Engine, Adapter, policy, process and
    # artifact dependencies, not just the five historical facade files. Rewalk
    # at checks so a newly added executable module changes the identity too.
    if (SOURCE_ROOT / 'src/loommode/host/managed_native.py').resolve() != Path(__file__).resolve():
        raise WorkflowError('Native source closure requires this exact checkout layout')
    paths = tuple(p.relative_to(SOURCE_ROOT).as_posix()
                  for p in sorted((SOURCE_ROOT / 'src/loommode').rglob('*.py')))
    if not paths or len(paths) > 512:
        raise WorkflowError('Native source closure absent/over bound')
    return paths


# Historical checkout harnesses consume this snapshot. Installed wheels have no
# reviewed checkout closure: importing this optional module is harmless, while
# actual admission still calls source_files() afresh and fails closed there.
_CHECKOUT_MODULE = SOURCE_ROOT / 'src/loommode/host/managed_native.py'
SOURCE_FILES = source_files() if _CHECKOUT_MODULE.resolve() == Path(__file__).resolve() else ()
_RESERVATIONS = RLock()
TASK_BINDING_MODE = 'ENGINE_SAVED_TASK_V1'


def task_template_sha256(request):
    """Pin fixed Host policy/config/identity before role-generated Intent exists.

    Intent.scope is natural-language content unavailable at Grant creation.
    Its actual bytes remain bound later by request fingerprint and the saved
    Intent/Final Task binding ledger; only Host policy grants write access.
    """
    value = {'config': asdict(request.config), 'policy': asdict(request.policy),
             'binding': {key: request.binding[key] for key in ('project', 'stage_id', 'task_id')}}
    value['binding']['scope'] = list(request.policy.writable_paths)
    value['policy']['workspace'] = str(request.policy.workspace.resolve(strict=True))
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _regular(path, maximum):
    """Bound reads and reject links/reparse components, including parent dirs."""
    from .materials import material_path
    path=material_path(path)
    try:
        for component in (path, *path.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise WorkflowError("native trusted input is linked/reparse")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise WorkflowError("native trusted input is not a bounded unique regular file")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise WorkflowError("native trusted input exceeds bound")
        return data
    except OSError as exc:
        raise WorkflowError("managed native execution unavailable: required trusted input absent/unreadable") from exc


def _sha(path):
    # Binary is large; stream it without a large allocation or executing it.
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def control_sha256(request, working_root, *, records_root=None):
    from loommode.workflow.managed_cli import CONTROL_VERSION, PARENT_HTTP_ROUTE, native_launch_plan
    plan = native_launch_plan(request, working_root / "ATTEMPT" / "schema.json",
                              working_root / "ATTEMPT" / "result.json", records_root=records_root)
    value = {"version": CONTROL_VERSION, "argv": plan.argv, "environment": plan.environment,
             "request": request.fingerprint, "parent_http_route": PARENT_HTTP_ROUTE}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def runtime_plan_sha256(grant):
    # The independently recorded Owner authorization binds all nonsecret plan
    # fields, including accepted source hashes. Exclude only its own reference
    # map to avoid a circular digest.
    value = {key: value for key, value in grant.items() if key != 'runtime_authorities'}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def capability_plan_sha256(request, working_root, *, records_root):
    """Independent candidate review binds capabilities before Intent exists."""
    from loommode.workflow.managed_cli import native_launch_plan
    plan = native_launch_plan(request, working_root / 'ATTEMPT/schema.json',
                              working_root / 'ATTEMPT/result.json', records_root=records_root)
    value = {'template_sha256': task_template_sha256(request), 'working_root': str(working_root.resolve()),
             'argv': plan.argv, 'environment': plan.environment}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _check_f3_retry_evidence(retry):
    """Bind the next F3 dispatch to all unchanged spent predecessors."""
    expected = {name: digest for name, (_, digest) in F3_RETRY_EVIDENCE.items()}
    if retry != expected:
        raise WorkflowError('F3 retry missing exact previous-attempt evidence')
    for name, (path, digest) in F3_RETRY_EVIDENCE.items():
        if hashlib.sha256(_regular(path, 65536)).hexdigest() != digest:
            raise WorkflowError('F3 retry predecessor evidence changed: ' + name)
    predecessors = (
        ('prior', private_value('managed_native', 'value_0'),
         private_value('managed_native', 'value_1')),
        ('second', private_value('managed_native', 'value_2'),
         private_value('managed_native', 'value_3')),
        ('third', private_value('managed_native', 'value_4'),
         private_value('managed_native', 'value_5')),
    )
    try:
        for prefix, attempt, fingerprint in predecessors:
            rows = _regular(F3_RETRY_EVIDENCE[prefix + '_dispatch_ledger'][0], 65536).splitlines()
            receipt = json.loads(_regular(F3_RETRY_EVIDENCE[prefix + '_actual_receipt'][0], 65536),
                                 object_pairs_hook=unique_json_object)
            expected_row = {'attempt': attempt, 'cost_units_reserved': 1,
                'currency': 'DISPATCH_UNIT', 'dispatch': 1,
                'grant_sha256': expected[prefix + '_runtime_grant'],
                'request_fingerprint': fingerprint}
            if (len(rows) != 1 or json.loads(rows[0], object_pairs_hook=unique_json_object) != expected_row
                    or receipt['outcome'] != 'FAILED'
                    or receipt['request_fingerprint'] != fingerprint
                    or receipt['invocation']['attempt_id'] != attempt
                    or receipt['invocation']['cleanup']['unknown_side_effect'] is not False
                    or receipt['fixture_writer_released'] is not True
                    or receipt['failure_report_sha256'] != expected[prefix + '_failure_report']):
                raise ValueError('F3 dispatch or cleanup not established')
        recovered = json.loads(_regular(F3_RETRY_EVIDENCE['third_recovery_receipt'][0], 65536),
                               object_pairs_hook=unique_json_object)
        if (recovered['outcome'] != 'RECOVERED_EVIDENCE_READY_FOR_CODEX_REVIEW'
                or recovered['original_receipt_sha256'] != expected['third_actual_receipt']
                or recovered['original_dispatch_ledger_sha256'] != expected['third_dispatch_ledger']
                or recovered['report_sha256'] != expected['third_recovered_report']
                or recovered['additional_model_dispatches'] != 0
                or recovered['fixture_writer_released'] is not True):
            raise ValueError('F3 third recovery provenance changed')
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkflowError('F3 retry predecessor consumption/cleanup unknown') from exc


@dataclass(frozen=True)
class _Admission:
    grant_sha256: str
    grant: dict
    origin: str = 'NATIVE_MXC_V4_BOUNDED_VALIDATION'
    production_eligible: bool = False
    task_binding_sha256: str | None = None


@dataclass(frozen=True)
class NativeHostLocations:
    """Trusted pinned-factory input. Never accepted from project/model JSON.

    candidate_review selects a safety-reviewed, non-production first validation;
    it does not provide any Owner run, credential or provider permission.
    """
    records_root: Path
    configuration: Path
    accepted_native: Path
    candidate_review: Path | None = None

    def __post_init__(self):
        for name in ('records_root', 'configuration', 'accepted_native', 'candidate_review'):
            value = getattr(self, name)
            if value is not None:
                if not isinstance(value, (str, Path)):
                    raise WorkflowError('trusted Native locations require paths')
                object.__setattr__(self, name, Path(value))
        root = Path(self.records_root)
        if not root.is_absolute() or not root.is_dir():
            raise WorkflowError('trusted Native Records root must exist')
        for value in (self.configuration, self.accepted_native, self.candidate_review):
            if value is not None and (not Path(value).is_absolute()
                    or Path(value).resolve() == root.resolve() or not Path(value).resolve().is_relative_to(root.resolve())):
                raise WorkflowError('trusted Native location escapes Records root')


class ManagedNativeHost:
    def __init__(self, writer_lease, *, locations=None):
        # Retain the original Host lease. Never acquire, steal or release one.
        self.writer_lease = writer_lease
        if locations is not None and type(locations) is not NativeHostLocations:
            raise WorkflowError('Native locations require trusted typed bootstrap input')
        self.locations = locations
        self._candidate_capability_plans = None
        self._configuration_sha256 = None
        self._v4_continuation = False
        self._v4_continuation_sha256 = None
        self._f3_validation_sha256 = None
        self._f4_validation_sha256 = None

    @classmethod
    def from_f3_validation(cls, writer_lease):
        """Fixed one-task validation only; no production configuration or Engine recovery."""
        require_private_instance()
        host = cls(writer_lease)
        host._f3_validation_sha256 = tuple(
            hashlib.sha256(_regular(RECORDS / name, 65536)).hexdigest()
            for name in (F3_RUNTIME_GRANT, F3_OWNER_GRANT))
        return host

    @classmethod
    def from_f4_validation(cls, writer_lease):
        """One fresh Engine Task; requires new exact grants and an independent ledger."""
        require_private_instance()
        host = cls(writer_lease)
        host._f4_validation_sha256 = tuple(
            hashlib.sha256(_regular(RECORDS / name, 65536)).hexdigest()
            for name in (F4_RUNTIME_GRANT, F4_OWNER_GRANT))
        return host

    @classmethod
    def from_v4_continuation(cls, writer_lease):
        """One fixed bounded-V4 forward grant; never production acceptance.

        The original ledger is retained. An old/unknown grant's consumption is
        not transferable; this deliberately supplies no ledger migration.
        """
        require_private_instance()
        host = cls(writer_lease)
        ledger = RECORDS / (RUNTIME_GRANT + '.dispatch.jsonl')
        owner_raw = _regular(RECORDS / CONTINUATION_OWNER_GRANT, 65536)
        owner = json.loads(owner_raw,
                           object_pairs_hook=unique_json_object)
        expected = {**_CONTINUATION_CHAIN, 'dispatch_ledger': str(ledger)}
        if not isinstance(owner, dict) or owner.get('continuation') != expected:
            raise WorkflowError('fixed V4 continuation chain absent/unmatched')
        originals = []
        for name, key in ((RUNTIME_GRANT, 'legacy_runtime_grant_sha256'),
                          (OWNER_GRANT, 'legacy_owner_grant_sha256')):
            original = _regular(RECORDS / name, 65536)
            if hashlib.sha256(original).hexdigest() != expected[key]:
                raise WorkflowError('immutable original V4 authorization changed')
            originals.append(json.loads(original, object_pairs_hook=unique_json_object))
        grant_raw = _regular(RECORDS / CONTINUATION_RUNTIME_GRANT, 65536)
        grant = json.loads(grant_raw, object_pairs_hook=unique_json_object)
        if (not isinstance(grant, dict) or not isinstance(owner, dict)
                or {k: v for k, v in grant.items() if k not in {'source_sha256', 'runtime_authorities'}}
                != {k: v for k, v in originals[0].items() if k not in {'source_sha256', 'runtime_authorities'}}
                or {k: v for k, v in owner.items() if k not in {'runtime_plan_sha256', 'continuation'}}
                != {k: v for k, v in originals[1].items() if k != 'runtime_plan_sha256'}):
            raise WorkflowError('V4 continuation changes original protected authorization')
        digest = hashlib.sha256(grant_raw).hexdigest()
        for path, field in ((ledger, 'grant_sha256'), (Path(str(ledger) + '.tasks.jsonl'), 'run_grant_sha256')):
            if path.exists():
                try:
                    rows = [json.loads(raw, object_pairs_hook=unique_json_object)
                            for raw in _regular(path, 65536).splitlines()]
                    if any(not isinstance(row, dict) or row.get(field) != digest for row in rows):
                        raise ValueError('old or unknown consumption')
                except (ValueError, TypeError) as exc:
                    raise WorkflowError('original V4 ledger cannot be reset or transferred') from exc
        host._v4_continuation = True
        host._v4_continuation_sha256 = (digest, hashlib.sha256(owner_raw).hexdigest())
        return host

    @classmethod
    def from_trusted_config(cls, writer_lease, *, locations=None):
        """Formal opt-in: no caller-selected certificate/config path or boolean.

        The trusted Host operator saves this configuration only after independent
        acceptance. Missing capability records keep this factory closed.
        """
        require_private_instance()
        host = cls(writer_lease, locations=locations)
        raw = _regular(host.configuration_path, 65536)
        host._configuration_sha256 = hashlib.sha256(raw).hexdigest()
        configuration = host._configuration()
        host._accepted_native(configuration)
        return host

    @property
    def records_root(self):
        return self.locations.records_root if self.locations else TRUSTED_RECORDS_ROOT

    @property
    def configuration_path(self):
        return self.locations.configuration if self.locations else HOST_CONFIGURATION

    @property
    def acceptance_path(self):
        return (self.locations.candidate_review or self.locations.accepted_native) if self.locations else ACCEPTED_NATIVE

    @property
    def candidate_validation(self):
        return bool(self.locations and self.locations.candidate_review is not None)

    def _trusted_path(self, value):
        path = Path(value)
        if (not path.is_absolute() or path.resolve(strict=False) == self.records_root.resolve(strict=True)
                or not path.resolve(strict=False).is_relative_to(self.records_root.resolve(strict=True))):
            raise WorkflowError('native Host path escapes fixed trusted Records root')
        return path

    def _configuration(self):
        if self._configuration_sha256 is None:
            return None
        raw = _regular(self.configuration_path, 65536)
        if hashlib.sha256(raw).hexdigest() != self._configuration_sha256:
            raise WorkflowError('native Host configuration changed during retained session')
        try:
            config = json.loads(raw, object_pairs_hook=unique_json_object)
            if (not isinstance(config, dict) or set(config) not in (
                    {'preset', 'workspace', 'runtime_grant', 'owner_grant', 'ledger', 'accepted_native_sha256'},
                    {'preset', 'workspace', 'runtime_grant', 'owner_grant', 'ledger', 'accepted_native_sha256', 'consumption_chain'})
                    or config['preset'] != 'codex_0.162.1_mxc_deepseek_responses'
                    or not Path(config['workspace']).is_absolute()):
                raise ValueError('Host configuration')
            if 'consumption_chain' in config:
                chain=config['consumption_chain']
                if not isinstance(chain,dict) or set(chain)!={'path','sha256'}:
                    raise ValueError('explicit pinned consumption chain required')
                self._trusted_path(chain['path'])
                if _sha(Path(chain['path']))!=chain['sha256']:
                    raise ValueError('consumption chain changed')
            for key in ('runtime_grant', 'owner_grant', 'ledger'):
                self._trusted_path(config[key])
            paths = {self._trusted_path(config[key]).resolve(strict=False)
                     for key in ('runtime_grant', 'owner_grant', 'ledger')}
            if len(paths) != 3 or paths & {self.configuration_path.resolve(), self.acceptance_path.resolve()}:
                raise ValueError('distinct Host records')
            return config
        except (ValueError, TypeError, KeyError) as exc:
            raise WorkflowError('invalid fixed native Host configuration') from exc

    @staticmethod
    def _identity():
        from loommode.workflow.managed_cli import CONTROL_VERSION, PARENT_HTTP_ROUTE
        return {'preset': 'codex_0.162.1_mxc_deepseek_responses', 'binary_sha256': BINARY_SHA256,
                'control_version': CONTROL_VERSION, 'parent_http_route': PARENT_HTTP_ROUTE,
                'source_sha256': {path: _sha(SOURCE_ROOT / path) for path in source_files()}}

    def _accepted_native(self, configuration):
        raw = _regular(self.acceptance_path, 65536)
        try:
            accepted = json.loads(raw, object_pairs_hook=unique_json_object)
            identity = self._identity()
            if self.candidate_validation:
                if (hashlib.sha256(raw).hexdigest() != configuration['accepted_native_sha256']
                        or accepted.get('purpose') != 'MANAGED_CODEX_CANDIDATE_SAFETY_REVIEW'
                        or accepted.get('verdict') != 'BOUNDED_VALIDATION_ALLOWED'
                        or accepted.get('reviewer_role') != 'Decision'
                        or accepted.get('production_eligible') is not False
                        or accepted.get('workspace') != configuration['workspace']
                        or accepted.get('identity') != identity):
                    raise ValueError('candidate independent safety applicability')
                plans = accepted.get('capability_plans')
                if (not isinstance(plans, dict) or not 1 <= len(plans) <= 2
                        or any(not isinstance(v, str) or len(v) != 64 or set(v) - set('0123456789abcdef')
                               for v in plans.values())):
                    raise ValueError('candidate reviewed capability plans absent')
                for key in ('code_review', 'tool_probe'):
                    ref = accepted[key]
                    data = _regular(self._trusted_path(ref['path']), 262144)
                    if not data.strip() or hashlib.sha256(data).hexdigest() != ref['sha256']:
                        raise ValueError('candidate safety evidence changed')
                self._candidate_capability_plans = plans
                return
            if (hashlib.sha256(raw).hexdigest() != configuration['accepted_native_sha256']
                    or not isinstance(accepted, dict) or accepted.get('purpose') != 'MANAGED_CODEX_NATIVE_CAPABILITY'
                    or accepted.get('verdict') != 'ACCEPTED' or accepted.get('reviewer_role') != 'Decision'
                    or accepted.get('identity') != identity):
                raise ValueError('independent capability identity')
            # A separate accepted index is insufficient: verify the actual native
            # evidence AND the existing formal Acceptance artifact it reviews.
            references = {}
            for key in ('native_report', 'formal_acceptance'):
                ref = accepted[key]
                path = self._trusted_path(ref['path'])
                data = _regular(path, 262144)
                if not data.strip() or hashlib.sha256(data).hexdigest() != ref['sha256']:
                    raise ValueError('native evidence/Acceptance digest')
                references[key] = (path, data, ref['sha256'])
            import re
            binding = accepted.get('binding')
            if (not isinstance(binding, dict) or set(binding) != {'project', 'stage_id', 'task_id'}
                    or any(not isinstance(value, str) or not value.strip() for value in binding.values())
                    or not re.fullmatch(re.escape(binding['task_id']) + r'_ACCEPTANCE_v[0-9]{3,}\.md',
                                        references['formal_acceptance'][0].name)):
                raise ValueError('not an original formal Acceptance artifact')
            report = json.loads(references['native_report'][1], object_pairs_hook=unique_json_object)
            checks = {'tool_filesystem', 'tool_network', 'credential_environment', 'credential_source',
                      'model_api', 'structured_result', 'formal_loop', 'cleanup'}
            if (not isinstance(report, dict) or report.get('purpose') != 'MANAGED_CODEX_NATIVE_EXECUTION_EVIDENCE'
                    or report.get('synthetic') is not False or report.get('verdict') != 'PASS'
                    or report.get('identity') != identity
                    or report.get('binding') != binding
                    or report.get('formal_acceptance_sha256') != references['formal_acceptance'][2]
                    or report.get('assertions') != dict.fromkeys(checks, 'PASS')):
                raise ValueError('actual native assertions and formal Acceptance binding')
        except (ValueError, TypeError, KeyError) as exc:
            raise WorkflowError('managed native execution unavailable: independent Accepted native evidence absent/unmatched') from exc

    def _paths(self):
        if self._f4_validation_sha256 is not None:
            for name, digest in zip((F4_RUNTIME_GRANT, F4_OWNER_GRANT), self._f4_validation_sha256):
                if hashlib.sha256(_regular(RECORDS / name, 65536)).hexdigest() != digest:
                    raise WorkflowError('fixed F4 validation grant changed during session')
            return (RECORDS / F4_RUNTIME_GRANT, RECORDS / F4_OWNER_GRANT,
                    RECORDS / (F4_RUNTIME_GRANT + '.dispatch.jsonl'), None)
        if self._f3_validation_sha256 is not None:
            for name, digest in zip((F3_RUNTIME_GRANT, F3_OWNER_GRANT), self._f3_validation_sha256):
                if hashlib.sha256(_regular(RECORDS / name, 65536)).hexdigest() != digest:
                    raise WorkflowError('fixed F3 validation grant changed during session')
            # F3 must not silently discard consumption on the original V4 line.
            old = RECORDS / (RUNTIME_GRANT + '.dispatch.jsonl')
            if old.exists() or Path(str(old) + '.tasks.jsonl').exists():
                raise WorkflowError('V4 consumption changed; reconcile before F3, without reset')
            return (RECORDS / F3_RUNTIME_GRANT, RECORDS / F3_OWNER_GRANT,
                    RECORDS / (F3_RUNTIME_GRANT + '.dispatch.jsonl'), None)
        if self._v4_continuation:
            for name, digest in zip((CONTINUATION_RUNTIME_GRANT, CONTINUATION_OWNER_GRANT),
                                    self._v4_continuation_sha256):
                if hashlib.sha256(_regular(RECORDS / name, 65536)).hexdigest() != digest:
                    raise WorkflowError('fixed V4 continuation authorization changed during session')
            return (RECORDS / CONTINUATION_RUNTIME_GRANT, RECORDS / CONTINUATION_OWNER_GRANT,
                    RECORDS / (RUNTIME_GRANT + '.dispatch.jsonl'), None)
        configuration = self._configuration()
        if configuration is None:
            return (RECORDS / RUNTIME_GRANT, RECORDS / OWNER_GRANT,
                    RECORDS / (RUNTIME_GRANT + '.dispatch.jsonl'), None)
        self._accepted_native(configuration)
        return tuple(Path(configuration[key]) for key in ('runtime_grant', 'owner_grant', 'ledger')) + (configuration,)

    def _writer(self, request):
        from .ownership import WorkspaceLease, _LEASES, workspace_identity
        lease = self.writer_lease
        identity = workspace_identity(request.policy.workspace)
        if (type(lease) is not WorkspaceLease or not lease.held or lease.workspace != identity
                or _LEASES.get(identity) is not lease or lease._stream is None or lease._stream.closed
                or lease.owner is None):
            raise WorkflowError("native dispatch requires the original Host's retained live Writer lease")

    def check(self, request, working_root, limits):
        require_private_instance()
        return self._check(request, working_root, limits)

    def _check(self, request, working_root, limits, *, binding_engine=None):
        # FIRST: an absent V4 grant must not cause any other privileged read.
        grant_path, owner_path, ledger_path, host_configuration = self._paths()
        configured = host_configuration is not None
        candidate = configured and self.candidate_validation
        production = configured and not candidate
        raw = _regular(grant_path, 65536)
        try:
            grant = json.loads(raw, object_pairs_hook=unique_json_object)
            required = {"purpose", "owner_authorized", "requests", "endpoint",
                        "credential_file", "credential_env", "expires_at", "workspace", "working_root",
                        "source_sha256", "binary_sha256",
                        "dispatch_limit", "cost_units_per_dispatch", "cost_units_limit", "currency",
                        "timeout_seconds", "cleanup_seconds", "io_bytes", "runtime_authorities",
                        "parent_http_route", "host_configuration_sha256"}
            required.update({'accepted_native_sha256'} if configured else {'fixture_root', 'v2_sha256'})
            extended_limits = 'io_limits' in grant
            if extended_limits:
                required.remove('io_bytes')
                required.add('io_limits')
            f3 = self._f3_validation_sha256 is not None
            f4 = self._f4_validation_sha256 is not None
            if f3:
                required.add('retry')
            dynamic = grant.get('request_binding_mode') == TASK_BINDING_MODE
            if dynamic:
                required.add('request_binding_mode')
            if not isinstance(grant, dict) or set(grant) != required:
                raise ValueError("grant schema")
            if f3:
                _check_f3_retry_evidence(grant['retry'])
            expiry = datetime.fromisoformat(grant['expires_at'])
            config = request.config.managed
            requests = grant['requests']
            request_keys = {'template_sha256', 'predecessor_task_id'} if dynamic else {'task_id', 'control_sha256'}
            if (not isinstance(requests, dict) or not 1 <= len(requests) <= (256 if production else 2)
                    or any(not isinstance(value, dict) or set(value) != request_keys
                           for value in requests.values())):
                raise ValueError('exact bounded Task requests')
            if dynamic:
                from loommode.workflow.state import identity
                for task, template in requests.items():
                    identity(task)
                    predecessor = template['predecessor_task_id']
                    if predecessor is not None and (predecessor not in requests or predecessor == task):
                        raise ValueError('bounded Task predecessor')
                template = requests.get(request.binding['task_id'], {})
                if template.get('template_sha256') != task_template_sha256(request):
                    raise ValueError('Owner Task template changed')
                bindings = self._task_bindings(grant, hashlib.sha256(raw).hexdigest(), ledger_path)
                selected = bindings.get(request.fingerprint, {})
                if not selected and binding_engine is not None:
                    # Only bind_actual_task calls this after inspecting the real
                    # current Engine and original saved Constraint artifacts.
                    selected = {'task_id': request.binding['task_id'],
                                'control_sha256': control_sha256(request, working_root, records_root=self.records_root)}
            else:
                bindings = None
                selected = requests.get(request.fingerprint, {})
            from loommode.workflow.managed_cli import PARENT_HTTP_ROUTE
            purpose = (private_value('managed_native', 'value_6') if f3 else
                       private_value('managed_native', 'value_7') if f4 else
                       'MANAGED_CODEX_CANDIDATE_VALIDATION_RUN' if candidate else
                       'MANAGED_CODEX_PRODUCTION_RUN' if production else private_value('managed_native', 'value_10'))
            if f3 and (dynamic or len(requests) != 1 or grant['dispatch_limit'] != 1
                    or grant['cost_units_limit'] != grant['cost_units_per_dispatch']
                    or request.binding['task_id'] != private_value('managed_native', 'value_8')
                    or Path(grant['fixture_root']) != F3_FIXTURE
                    or Path(grant['workspace']) != F3_FIXTURE / 'workspace'
                    or Path(grant['working_root']) != F3_FIXTURE / 'working'
                    or Path(config.codex_home) != F3_FIXTURE / 'home'):
                raise ValueError('fixed F3 single validation boundary')
            if f4 and (not dynamic or len(requests) != 1 or grant['dispatch_limit'] != 1
                    or grant['cost_units_limit'] != grant['cost_units_per_dispatch']
                    or set(requests) != {private_value('managed_native', 'value_11')}
                    or Path(grant['fixture_root']) != F4_FIXTURE
                    or Path(grant['workspace']) != F4_FIXTURE / 'workspace'
                    or Path(grant['working_root']) != F4_FIXTURE / 'working'
                    or Path(config.codex_home) != F4_FIXTURE / 'home'):
                raise ValueError('fixed F4 Engine Task boundary')
            if (grant['purpose'] != purpose or grant['owner_authorized'] is not True
                    or grant['parent_http_route'] != PARENT_HTTP_ROUTE
                    or grant['host_configuration_sha256'] != self._configuration_sha256
                    or expiry.tzinfo is None or expiry <= datetime.now(timezone.utc)
                    or selected.get('task_id') != request.binding['task_id']
                    or grant['endpoint'] != config.endpoint or grant['credential_env'] != config.credential_env
                    or grant['credential_file'] != config.credential_file
                    or (config.cli_version, config.windows_sandbox) != ("0.162.1", "mxc")
                    or config.credential_env != 'DEEPSEEK_API_KEY'
                    or config.approval_policy != 'never' or config.unattended is not True
                    or (not configured and Path(config.cli_path) != BINARY) or config.credential_file is None
                    or (not configured and grant['v2_sha256'] != V2_SHA256)
                    or (configured and grant['accepted_native_sha256'] != host_configuration['accepted_native_sha256'])
                    or grant['binary_sha256'] != BINARY_SHA256
                    or selected.get('control_sha256') != control_sha256(request, working_root, records_root=self.records_root)):
                raise ValueError("grant binding")
            # Validation is explicitly limited to the two disposable V4 Tasks;
            # the grant cannot turn V2 into general production eligibility.
            root = Path(grant['fixture_root']).resolve(strict=True) if not configured else None
            workspace = request.policy.workspace.resolve(strict=True)
            home = Path(config.codex_home).resolve(strict=True)
            credential = Path(config.credential_file).resolve(strict=False)
            import tempfile
            if not configured and (root == Path(tempfile.gettempdir()).resolve() or not root.is_relative_to(Path(tempfile.gettempdir()).resolve())
                    or root == workspace or not workspace.is_relative_to(root) or not home.is_relative_to(root)
                    or not working_root.is_relative_to(root)):
                raise ValueError('V4 disposable fixture boundary')
            if (str(workspace) != grant['workspace']
                    or str(working_root) != grant['working_root']
                    or any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
                           for a, b in ((workspace, home), (workspace, working_root),
                                        (home, working_root), (workspace, self.records_root.resolve(strict=True)),
                                        (home, self.records_root.resolve(strict=True)),
                                        (working_root, self.records_root.resolve(strict=True))))
                    or (not configured and not (workspace / '.loommode-project-root').is_file())
                    or credential.is_relative_to(workspace) or credential.is_relative_to(working_root)
                    or credential == Path(config.cli_path).resolve() or credential == home
                    or (configured and str(workspace) != host_configuration['workspace'])):
                raise ValueError("fixture/home/credential scope")
            if (type(grant['dispatch_limit']) is not int or grant['dispatch_limit'] <= 0
                    or (not production and grant['dispatch_limit'] > 3)
                    or any(type(grant[key]) is not int or grant[key] <= 0 for key in
                           ('cost_units_limit', 'cost_units_per_dispatch'))
                    or not isinstance(grant['currency'], str) or not grant['currency']
                    or grant['timeout_seconds'] != limits.timeout_seconds
                    or grant['cleanup_seconds'] != limits.cleanup_seconds or limits.cleanup_seconds > 2
                    or (extended_limits and (not configured or grant['io_limits'] !=
                        {'stdin_bytes': limits.stdin_bytes, 'stream_bytes': limits.stream_bytes, 'result_bytes': limits.result_bytes}))
                    or (not extended_limits and (type(grant['io_bytes']) is not int or grant['io_bytes'] <= 0
                        or grant['io_bytes'] != min(limits.stdin_bytes, limits.stream_bytes, limits.result_bytes)
                        or max(limits.stdin_bytes, limits.stream_bytes, limits.result_bytes) > 65536 or limits.timeout_seconds > 120))):
                raise ValueError("grant bounds")
            authorities = grant['runtime_authorities']
            if (not isinstance(authorities, dict) or set(authorities) !=
                    {'model_api', 'credential_read', 'mxc_exec', 'provider_budget'}
                    or any(not isinstance(ref, dict) or set(ref) != {'file', 'sha256'}
                           or ref['file'] != (str(owner_path) if configured else owner_path.name) for ref in authorities.values())):
                raise ValueError("exact runtime authority references")
            owner_raw = _regular(owner_path, 65536)
            owner = json.loads(owner_raw, object_pairs_hook=unique_json_object)
            if (not isinstance(owner, dict)
                    or any(ref['sha256'] != hashlib.sha256(owner_raw).hexdigest() for ref in authorities.values())
                    or owner.get('purpose') != (private_value('managed_native', 'value_9') if f3 else
                        private_value('managed_native', 'value_12') if f4 else
                        'MANAGED_CODEX_CANDIDATE_OWNER_AUTHORIZATION' if candidate else
                        'MANAGED_CODEX_RUN_OWNER_AUTHORIZATION' if production else private_value('managed_native', 'value_13'))
                    or owner.get('runtime_plan_sha256') != runtime_plan_sha256(grant)
                    or set(owner.get('capabilities', [])) != set(authorities)
                    or any(owner.get(key) != grant[key] for key in ('requests', 'workspace', 'working_root', 'endpoint',
                        'credential_file', 'credential_env', 'expires_at', 'dispatch_limit',
                        'cost_units_limit', 'cost_units_per_dispatch', 'currency'))):
                raise ValueError("Owner authorization does not bind runtime plan")
        except (ValueError, TypeError, KeyError, OSError) as exc:
            raise WorkflowError("managed native execution unavailable: unmatched/expired exact V4 runtime grant") from exc
        self._writer(request)
        if candidate and (self._candidate_capability_plans or {}).get(request.binding['task_id']) != capability_plan_sha256(
                request, working_root, records_root=self.records_root):
            raise WorkflowError('candidate capabilities differ from independent safety review')
        if not configured:
            review_raw = _regular(RECORDS / V2_REVIEW, 65536)
            if hashlib.sha256(review_raw).hexdigest() != V2_SHA256:
                raise WorkflowError("accepted V2 review changed")
            review = json.loads(review_raw, object_pairs_hook=unique_json_object)
            if (review['verdict'] != 'V2_THREE_ASSERTIONS_PASS' or review['native_used'] != 7
                    or review['review_kind'] != 'INDEPENDENT_READONLY_V2_ACTUAL_EVIDENCE_NOT_HOST_OR_A4_ACCEPTANCE'):
                raise WorkflowError("V2 is not the fixed accepted evidence")
            for reference, digest in review['sha256'].items():
                if _sha(Path(reference)) != digest:
                    raise WorkflowError("V2 evidence dependency changed")
        sources = source_files()
        expected_sources = ((*sources, 'tools/single_managed_task.py') if f3 else
                            (*sources, 'tools/f4_engine_task.py', 'tools/f4_engine_factory.py') if f4 else sources)
        if (_sha(Path(config.cli_path)) != BINARY_SHA256 or not isinstance(grant['source_sha256'], dict)
                or set(grant['source_sha256']) != set(expected_sources)
                or any(_sha(SOURCE_ROOT / path) != digest for path, digest in grant['source_sha256'].items())):
            raise WorkflowError("fixed native binary/accepted source changed")
        # These known Windows managed layers are never bypassed or silently
        # overridden. A new machine policy requires separate reconciliation.
        for path in (Path('C:/ProgramData/OpenAI/Codex/requirements.toml'),
                     Path('C:/ProgramData/OpenAI/Codex/config.toml'), home / 'managed_config.toml',
                     home / '.env', home / 'auth.json'):
            if path.exists():
                raise WorkflowError("native managed/auth/dotenv input requires new explicit review")
        with _RESERVATIONS:
            self._runtime_budget(grant, hashlib.sha256(raw).hexdigest(), ledger_path, bindings, task=request.binding['task_id'])
        return _Admission(hashlib.sha256(raw).hexdigest(), grant,
            'NATIVE_MXC_BOUNDED_CANDIDATE_VALIDATION' if candidate else
            'NATIVE_MXC_ACCEPTED_PRODUCTION' if production else 'NATIVE_MXC_V4_BOUNDED_VALIDATION', production,
            selected.get('binding_sha256'))

    @staticmethod
    def _task_bindings(grant, grant_sha256, ledger):
        path = Path(str(ledger) + '.tasks.jsonl')
        result, tasks, previous = {}, set(), None
        if not path.exists():
            return result
        try:
            rows = _regular(path, 65536).splitlines()
            for index, raw in enumerate(rows):
                row = json.loads(raw, object_pairs_hook=unique_json_object)
                required = {'ordinal', 'run_grant_sha256', 'task_id', 'request_fingerprint', 'template_sha256',
                    'control_sha256', 'intent_ref', 'final_ref', 'predecessor_report_ref',
                    'predecessor_checkpoint_ref', 'previous_binding_sha256'}
                task = row['task_id']
                template = grant['requests'][task]
                if (set(row) != required or row['ordinal'] != index + 1 or row['run_grant_sha256'] != grant_sha256
                        or row['previous_binding_sha256'] != previous or task in tasks
                        or row['request_fingerprint'] in result or row['template_sha256'] != template['template_sha256']
                        or any(not isinstance(row[key], str) or len(row[key]) != 64
                               or any(c not in '0123456789abcdef' for c in row[key])
                               for key in ('request_fingerprint', 'template_sha256', 'control_sha256'))
                        or not row['intent_ref'] or not row['final_ref']):
                    raise ValueError('binding chain')
                predecessor = template['predecessor_task_id']
                if ((predecessor is None and (row['predecessor_report_ref'] is not None
                                             or row['predecessor_checkpoint_ref'] is not None))
                        or (predecessor is not None and (predecessor not in tasks
                            or not row['predecessor_report_ref'] or not row['predecessor_checkpoint_ref']))):
                    raise ValueError('binding predecessor')
                previous = hashlib.sha256(raw).hexdigest()
                result[row['request_fingerprint']] = {**row, 'binding_sha256': previous}
                tasks.add(task)
            return result
        except (ValueError, TypeError, KeyError) as exc:
            raise WorkflowError('native actual Task binding ledger unknown; preserve without reset') from exc

    def bind_actual_task(self, engine):
        """Trusted Host hook before Engine.step, never Executor-supplied proof.

        Appends one actual Task binding under the retained Writer. Pure request
        preflight/check cannot append it or consume either existing allowance.
        """
        from loommode.workflow.engine import WorkflowEngine
        from loommode.workflow.implementation import ImplementationRequest
        from loommode.workflow.transitions import Node
        from loommode.roles.contracts import INTENT_SCHEMA, validate
        if (type(engine) is not WorkflowEngine or self.writer_lease.owner is not engine
                or getattr(engine, '_workspace_writer_lease', None) is not self.writer_lease
                or engine._busy or engine.state.in_flight_activity
                or engine.state.current_node != Node.EXECUTOR_IMPLEMENT.value):
            raise WorkflowError('actual Task binding requires the original quiescent Engine boundary')
        state, executor = engine.state, engine.executor
        session = executor._managed_session
        if session is None or session.native_host is not self or session.host_preflight is not executor.managed_backend.host_preflight:
            raise WorkflowError('actual Task binding requires the original managed Session')
        engine.preflight_task(state.task_id)
        intent_ref, final_ref = state.formal_task_intent_ref, state.formal_constraint_ref
        for ref, kind in ((intent_ref, 'TASK_INTENT'), (final_ref, 'FINAL_TASK_CONSTRAINT')):
            if ref not in state.artifact_refs.get(kind, []):
                raise WorkflowError('actual Task original artifact is not registered')
            engine.artifacts.assert_task_reference(ref, kind, state.task_id)
        intent_text, final_text = engine.artifacts.read(intent_ref), engine.artifacts.read(final_ref)
        intent = json.loads(intent_text, object_pairs_hook=unique_json_object)
        validate(intent, INTENT_SCHEMA)
        if intent['task_id'] != state.task_id or intent['workflow_path'] != 'NORMAL':
            raise WorkflowError('actual Constraint binding requires original NORMAL Task')
        # Confirm the original Constraint's saved FINAL_READY result carried
        # these exact final bytes; an arbitrary path/ref is insufficient.
        final_results = []
        for ref in state.artifact_refs.get('DECISION', []):
            try:
                engine.artifacts.assert_task_reference(ref, 'DECISION', state.task_id)
            except WorkflowError:
                continue
            result = engine.artifacts.read_json(ref)
            if result.get('action') == 'FINAL_READY':
                final_results.extend(a['content'] for a in result['artifacts'] if a['kind'] == 'FINAL_TASK_CONSTRAINT')
        if final_results != [final_text]:
            raise WorkflowError('original saved Constraint FINAL_READY missing/unmatched')
        binding = {'project': state.project, 'stage_id': state.stage_id, 'task_id': state.task_id,
                   'intent_ref': intent_ref, 'final_ref': final_ref, 'scope': intent['scope']}
        request = executor._implementation_request(state.as_dict(), {intent_ref: intent_text, final_ref: final_text},
                                                  executor._task_policy(state.task_id), binding)
        admission = self._check(request, session.working_root, session.limits, binding_engine=engine)
        if admission.grant.get('request_binding_mode') != TASK_BINDING_MODE:
            raise WorkflowError('immutable run grant does not delegate actual Task binding')
        predecessor = admission.grant['requests'][state.task_id]['predecessor_task_id']
        report_ref = checkpoint_ref = None
        if predecessor is not None:
            # Original closeout verifier expects a fully settled list. The
            # current Task legitimately has no checkpoint yet; verify the
            # actual prior history without pretending this Task is complete.
            prior = copy.deepcopy(state)
            prior.used_task_ids = [task for task in state.used_task_ids if task != state.task_id]
            engine._checkpoint_records(prior)
            checkpoint_ref = state.task_checkpoint_refs.get(predecessor)
            for ref in state.artifact_refs.get('EXECUTION_REPORT', []):
                try:
                    engine.artifacts.assert_task_reference(ref, 'EXECUTION_REPORT', predecessor)
                    report_ref = ref
                except WorkflowError:
                    continue
            if not checkpoint_ref or not report_ref or not {report_ref, checkpoint_ref}.issubset(intent['authority_refs']):
                raise WorkflowError('actual successor lacks explicit accepted predecessor Report/checkpoint handoff')
            engine.artifacts.read(report_ref)
            engine.artifacts.read(checkpoint_ref)
        with _RESERVATIONS:
            grant_path, _, ledger, _ = self._paths()
            if hashlib.sha256(_regular(grant_path, 65536)).hexdigest() != admission.grant_sha256:
                raise WorkflowError('immutable run grant changed before actual Task binding')
            bindings = self._task_bindings(admission.grant, admission.grant_sha256, ledger)
            old = bindings.get(request.fingerprint)
            if old:
                return old['binding_sha256']
            if any(row['task_id'] == state.task_id for row in bindings.values()):
                raise WorkflowError('actual Task original request changed; same Final Repair only')
            self._runtime_budget(admission.grant, admission.grant_sha256, ledger, bindings, task=state.task_id)
            row = {'ordinal': len(bindings) + 1, 'run_grant_sha256': admission.grant_sha256,
                   'task_id': state.task_id, 'request_fingerprint': request.fingerprint,
                   'template_sha256': task_template_sha256(request), 'control_sha256': control_sha256(request, session.working_root, records_root=self.records_root),
                   'intent_ref': intent_ref, 'final_ref': final_ref, 'predecessor_report_ref': report_ref,
                   'predecessor_checkpoint_ref': checkpoint_ref,
                   'previous_binding_sha256': next(reversed(bindings.values()))['binding_sha256'] if bindings else None}
            raw = json.dumps(row, sort_keys=True, separators=(',', ':')).encode()
            config=self._configuration()
            if config and 'consumption_chain' in config:
                from .forward import ConsumptionChain
                ConsumptionChain(config['consumption_chain']).append_current('bindings',raw+b'\n',writer_lease=self.writer_lease)
            else:
                with Path(str(ledger) + '.tasks.jsonl').open('ab' if bindings else 'xb') as stream:
                    stream.write(raw + b'\n')
                    stream.flush()
                    os.fsync(stream.fileno())
            return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _budget_entries(grant, grant_sha256, ledger, bindings=None):
        entries = []
        if ledger.exists():
            try:
                entries = [json.loads(line, object_pairs_hook=unique_json_object)
                           for line in _regular(ledger, 65536).splitlines()]
                if any(not isinstance(entry, dict) for entry in entries):
                    raise ValueError('invalid ledger entry')
            except (ValueError, TypeError) as exc:
                raise WorkflowError('native durable allowance ledger is unknown; preserve without reset') from exc
        allowed = bindings if bindings is not None else grant['requests']
        if (any(entry.get('request_fingerprint') not in allowed
                or entry.get('grant_sha256') != grant_sha256
                or (bindings is not None and entry.get('task_binding_sha256') !=
                    bindings.get(entry.get('request_fingerprint'), {}).get('binding_sha256'))
                or entry.get('dispatch') != index + 1
                or entry.get('cost_units_reserved') != grant['cost_units_per_dispatch']
                or entry.get('currency') != grant['currency'] for index, entry in enumerate(entries))):
            raise WorkflowError("native exact runtime allowance exhausted/unmatched; no reset")
        return ledger, entries

    @staticmethod
    def _budget(grant, grant_sha256, ledger, bindings=None):
        ledger, entries = ManagedNativeHost._budget_entries(grant, grant_sha256, ledger, bindings)
        if (len(entries) >= grant['dispatch_limit'] or
                (len(entries)+1)*grant['cost_units_per_dispatch'] > grant['cost_units_limit']):
            raise WorkflowError('native exact runtime allowance exhausted/unmatched; no reset')
        return ledger, entries

    def _runtime_budget(self, grant, grant_sha256, ledger, bindings=None, *, task=None):
        result=self._budget(grant,grant_sha256,ledger,bindings)
        config=self._configuration()
        if config and 'consumption_chain' in config:
            from .forward import ConsumptionChain
            chain=ConsumptionChain(config['consumption_chain'])
            chain.before_native(grant,grant_sha256,ledger,task)
        return result

    def resolve_credential(self, request, admission, working_root, limits):
        # Re-check the complete grant before touching its independently granted
        # file. No ambient env, keyring, auth.json, resolver callback or fallback.
        current = self.check(request, working_root, limits)
        if current.grant_sha256 != admission.grant_sha256:
            raise WorkflowError("native runtime grant changed before credential resolution")
        self._writer(request)
        try:
            secret = _regular(Path(current.grant['credential_file']), 8192).decode('utf-8')
            if not secret or secret != secret.strip() or any(char.isspace() for char in secret) or '\x00' in secret:
                raise ValueError("credential format")
            return secret
        except (UnicodeError, ValueError) as exc:
            raise WorkflowError("authorized credential file has invalid format") from exc

    def reserve(self, request, attempt, working_root, limits):
        admission = self.check(request, working_root, limits)
        with _RESERVATIONS:
            grant_path, _, ledger_path, _ = self._paths()
            if hashlib.sha256(_regular(grant_path, 65536)).hexdigest() != admission.grant_sha256:
                raise WorkflowError('immutable run grant changed before reservation')
            bindings = (self._task_bindings(admission.grant, admission.grant_sha256, ledger_path)
                        if admission.grant.get('request_binding_mode') == TASK_BINDING_MODE else None)
            ledger, entries = self._runtime_budget(admission.grant, admission.grant_sha256, ledger_path, bindings, task=request.binding['task_id'])
            entry = {'attempt': attempt, 'request_fingerprint': request.fingerprint,
                     'grant_sha256': admission.grant_sha256, 'dispatch': len(entries) + 1,
                     'cost_units_reserved': admission.grant['cost_units_per_dispatch'],
                     'currency': admission.grant['currency']}
            if bindings is not None:
                selected = bindings.get(request.fingerprint)
                if not selected or selected['binding_sha256'] != admission.task_binding_sha256:
                    raise WorkflowError('actual Task binding changed before reservation')
                entry['task_binding_sha256'] = selected['binding_sha256']
            # Existing Writer lease serializes cross-process access. Reserve
            # durably BEFORE OwnedJob launch, consuming even failed attempts.
            raw=json.dumps(entry,sort_keys=True).encode()+b'\n'
            config=self._configuration()
            if config and 'consumption_chain' in config:
                from .forward import ConsumptionChain
                ConsumptionChain(config['consumption_chain']).append_current('native',raw,writer_lease=self.writer_lease)
            else:
                with ledger.open('ab' if entries else 'xb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
