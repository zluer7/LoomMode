"""Small explicit first-use Codex-only assembly; no installation or migration.

The reviewed factory pins this configuration. Static inspection never imports a
factory, opens old State, reads credentials, runs Codex or creates directories.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import stat

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import identity, unique_json_object
from loommode.tools.filesystem import normalize_relative


def _regular(path):
    from .materials import LocalMaterials
    path = Path(path)
    if not path.is_absolute():
        raise WorkflowError('bootstrap paths must be absolute')
    if (any(part.casefold() in {'.git', '.ssh', '.aws'} for part in path.parts)
            or path.name.casefold() in {'state.json', 'contexts.json', 'auth.json', 'credentials', 'credentials.json'}
            or path.suffix.casefold() in {'.key', '.pem', '.pfx'}):
        raise WorkflowError('credential, saved State or protected Git input refused')
    LocalMaterials._regular(path)
    return path


def _pinned(reference):
    if not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}:
        raise WorkflowError('explicit file and raw-byte SHA256 required')
    path = _regular(reference['path'])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise WorkflowError('bootstrap input bytes changed')
    return path, raw


def _directory(value):
    from .materials import LocalMaterials
    path = Path(value)
    if not path.is_absolute():
        raise WorkflowError('absolute approved directory required')
    if any(part.casefold() in {'.git', '.ssh', '.aws'} for part in path.parts):
        raise WorkflowError('protected directory is not a first-use store')
    LocalMaterials._regular(path, directory=True)
    return path.resolve(strict=True)


def _output_path(root, path):
    """First-use stores only: check existing components before following any.

    Rechecked at actual store operations; this does not promise atomic defense
    against an adversary concurrently replacing directories during a write.
    """
    root, path = Path(root), Path(path)
    if not root.is_absolute() or not path.is_absolute() or '..' in path.parts or not path.is_relative_to(root):
        raise WorkflowError('bootstrap output escapes its approved root')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break  # The remaining suffix does not exist; do not create it here.
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise WorkflowError('bootstrap linked output namespace refused')
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise WorkflowError('bootstrap output ancestor is not a directory')
        if current == path and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise WorkflowError('bootstrap hardlinked output file refused')
    if not path.resolve(strict=False).is_relative_to(root):
        raise WorkflowError('bootstrap output escapes its approved root')
    return path


def _state_store(root, project, stage):
    from loommode.workflow.state import StateStore
    _output_path(root, root / 'workflow' / project / stage / 'state.json')
    class FirstUseStateStore(StateStore):
        _written = False

        def save(self, state):
            _output_path(root, self.path)
            if not self._written and self.path.exists():
                raise WorkflowError('first-use State appeared before initial write')
            super().save(state)
            self._written = True
    return FirstUseStateStore(root, project, stage)


def _registry(root, path):
    from loommode.codex.context import ContextRegistry
    _output_path(root, path)
    _output_path(root, path.with_suffix(path.suffix + '.tmp'))
    if path.exists() or path.with_suffix(path.suffix + '.tmp').exists():
        raise WorkflowError('first-use Registry appeared before assembly')
    class FirstUseRegistry(ContextRegistry):
        def _save(self):
            _output_path(root, self.persistence_path)
            _output_path(root, self.persistence_path.with_suffix(self.persistence_path.suffix + '.tmp'))
            super()._save()
    return FirstUseRegistry(path)


def _binary(reference):
    if not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}:
        raise WorkflowError('explicit pinned binary required')
    path = Path(reference['path'])
    if not path.is_absolute():
        raise WorkflowError('absolute binary path required')
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise WorkflowError('linked binary namespace refused')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1024 * 1024 * 1024:
        raise WorkflowError('bounded regular binary required')
    # Installed executables may have package-manager hardlinks. They are never
    # written, and raw bytes are pinned rather than treating the alias as a grant.
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != reference['sha256']:
        raise WorkflowError('Codex binary pin changed')
    return path


def inspect_config(path, *, expected_sha256):
    """Read only, with explicit pins; no writes, factory import or subprocess."""
    _, raw = _pinned({'path': str(path), 'sha256': expected_sha256})
    value = json.loads(raw, object_pairs_hook=unique_json_object)
    required = {'schema_version', 'project', 'stage_id', 'workspace', 'records_root',
                'runtime_root', 'records_tuple', 'stage_authorization_ref',
                'authorities', 'roles', 'codex', 'policy', 'task_policies', 'grants'}
    if (not isinstance(value, dict) or set(value) not in (required, required | {'caller_verification_ref'})
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise WorkflowError('explicit Codex-only bootstrap schema required')
    for key in ('project', 'stage_id'):
        identity(value[key])
    roots = {key: _directory(value[key]) for key in ('workspace', 'records_root', 'runtime_root')}
    if len(set(roots.values())) != 3:
        raise WorkflowError('workspace, Records and runtime roots must differ')
    # Store paths cannot alias a business workspace. A common parent is legal.
    for key in ('records_root', 'runtime_root'):
        if roots['workspace'].is_relative_to(roots[key]) or roots[key].is_relative_to(roots['workspace']):
            raise WorkflowError('business workspace and management stores must be disjoint')
    if roots['records_root'].is_relative_to(roots['runtime_root']) or roots['runtime_root'].is_relative_to(roots['records_root']):
        raise WorkflowError('Records and runtime stores must be disjoint')
    parts = value['records_tuple']
    if not isinstance(parts, list) or len(parts) != 3:
        raise WorkflowError('explicit Records cycle/group/stage tuple required')
    parts = tuple(identity(part) for part in parts)
    if value['stage_id'] != parts[0] + '-' + parts[2]:
        raise WorkflowError('Stage identity and explicit Records tuple disagree')
    from .cli import _process_store
    store = _state_store(roots['runtime_root'], value['project'], value['stage_id'])
    registry_path = roots['runtime_root'] / 'contexts.json'
    registry_temp = registry_path.with_suffix(registry_path.suffix + '.tmp')
    _output_path(roots['runtime_root'], registry_path)
    _output_path(roots['runtime_root'], registry_temp)
    if store.path.exists() or registry_path.exists() or registry_temp.exists():
        raise WorkflowError('first-use bootstrap refuses existing State or Registry; directed upgrade/recovery required')
    # Reject occupied tuple buckets without opening any old documents.
    for bucket in ('Process/Constraints', 'Process/Working', 'Process/Reports', 'Stage-Records', 'Issue-Ledger'):
        target = roots['records_root'] / bucket / Path(*parts)
        _output_path(roots['records_root'], target)
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise WorkflowError('first-use bootstrap refuses existing Records tuple')
    authorities = {}
    if not isinstance(value['authorities'], dict) or not value['authorities']:
        raise WorkflowError('explicit pinned Authority inputs required')
    for ref, entry in value['authorities'].items():
        if not isinstance(ref, str) or not ref.strip():
            raise WorkflowError('invalid Authority reference')
        _, body = _pinned(entry)
        authorities[ref] = body.decode('utf-8-sig')
    if value['stage_authorization_ref'] not in authorities:
        raise WorkflowError('approved Stage Authority is missing')
    roles = value['roles']
    if not isinstance(roles, dict) or set(roles) != {'Promoter', 'Constraint', 'Discussant', 'Decision'}:
        raise WorkflowError('four explicit fixed role files required')
    role_paths = {role: _pinned(ref)[0] for role, ref in roles.items()}
    codex = value['codex']
    if (not isinstance(codex, dict) or set(codex) not in ({'binary', 'supported_versions'}, {'binary', 'supported_versions', 'connect_on_assembly'})
            or not isinstance(codex['supported_versions'], list) or not codex['supported_versions']
            or any(not isinstance(v, str) or not v.strip() for v in codex['supported_versions'])):
        raise WorkflowError('explicit pinned Codex binary and allowed versions required')
    binary = _binary(codex['binary'])
    grants = value['grants']
    if (not isinstance(grants, dict) or set(grants) != {'allow_progress', 'allow_owner_events', 'local_commit_authorized'}
            or any(type(v) is not bool for v in grants.values()) or grants['local_commit_authorized']):
        raise WorkflowError('bootstrap requires explicit grants and no automatic Git authorization')
    connect = codex.get('connect_on_assembly', False)
    if type(connect) is not bool or connect and not grants['allow_progress']:
        raise WorkflowError('explicit connection requires actual progress authorization in the canonical binding')
    stage_policy = _policy(value['policy'], roots['workspace'])
    if not isinstance(value['task_policies'], dict) or not value['task_policies']:
        raise WorkflowError('explicit finite task policies required')
    task_policies = {}
    for task, policy in value['task_policies'].items():
        identity(task)
        task_policy = _policy(policy, roots['workspace'])
        task_policy.preflight(bound=stage_policy, check_tests=False)
        task_policies[task] = task_policy
    verification = None
    if 'caller_verification_ref' in value:
        verification = CallerVerification(value, authorities, task_policies)
    return {'value': value, 'roots': roots, 'parts': parts, 'authorities': authorities,
            'role_paths': role_paths, 'binary': binary, 'stage_policy': stage_policy,
            'task_policies': task_policies, 'state_store': store, 'registry_path': registry_path,
            'caller_verification': verification}


class CallerVerification:
    """Recheck selected pinned caller facts, not a new permission or budget grant.

    The reviewed bootstrap pin selects the actual approval envelope. Original
    Owner/preparation bytes remain Host-only; only required resource/supplement
    bodies and a derived projection are delivered at the relevant activities.
    """
    activities = frozenset({'TASK_SELECTION', 'CONSTRAINT_DRAFT', 'DISCUSS_NORMAL',
                            'CONSTRAINT_FINALIZE', 'DECISION_MEDIATION'})
    limits = frozenset({'max_run_turns', 'per_turn_seconds', 'total_seconds',
                        'max_additional_charge'})

    def __init__(self, config, authorities, task_policies):
        self._pins = dict(config['authorities'])
        self._originals = dict(authorities)
        self._ref = config['caller_verification_ref']
        if not isinstance(self._ref, str) or self._ref not in authorities:
            raise WorkflowError('explicit pinned caller verification input required')
        self._input = self._json(authorities[self._ref])
        value = self._input
        fields = {'origin', 'project', 'stage_id', 'task_id', 'workspace', 'caller_id',
                  'resource_ref', 'preparation_ref', 'owner_source_ref', 'supplement_ref',
                  'approved_limits', 'scope'}
        if set(value) != fields or value['origin'] != 'CALLER_VERIFICATION_INPUT':
            raise WorkflowError('explicit caller verification input schema required')
        self._identity = (config['project'], config['stage_id'], value['task_id'],
                          str(Path(config['workspace']).resolve()))
        if value['task_id'] not in task_policies:
            raise WorkflowError('caller verification Task has no current Host policy')
        if (not isinstance(value['caller_id'], str) or not value['caller_id'].strip()
                or not isinstance(value['scope'], list) or not value['scope']
                or any(not isinstance(p, str) for p in value['scope'])
                or len(set(value['scope'])) != len(value['scope'])
                or set(value['scope']) != set(task_policies[value['task_id']].writable_paths)):
            raise WorkflowError('caller verification scope differs from current Host Task policy')
        approved = value['approved_limits']
        if (not isinstance(approved, dict) or set(approved) != self.limits
                or any(type(approved[k]) is not int or approved[k] <= 0
                       for k in self.limits - {'max_additional_charge'})
                or type(approved['max_additional_charge']) is not int
                or approved['max_additional_charge'] != 0):
            raise WorkflowError('caller requires explicit subscription-only bounded approval')
        self._refs = [self._ref] + [value[k] for k in
            ('resource_ref', 'preparation_ref', 'owner_source_ref', 'supplement_ref')]
        if (any(not isinstance(ref, str) or ref.startswith('HOST_') or ref not in authorities or ref not in self._pins
                for ref in self._refs) or len(set(self._refs)) != len(self._refs)):
            raise WorkflowError('caller sources require distinct existing formal Authority refs')
        self._required = [value['resource_ref'], value['supplement_ref']]
        self._checked_at = datetime.now(timezone.utc).isoformat()
        self._check(authorities)

    @staticmethod
    def _json(raw):
        try:
            value = json.loads(raw, object_pairs_hook=unique_json_object)
        except (TypeError, ValueError) as exc:
            raise WorkflowError('invalid caller source JSON') from exc
        if not isinstance(value, dict):
            raise WorkflowError('caller source must be an object')
        return value

    def _same_identity(self, value):
        if ((value.get('project'), value.get('stage_id'), value.get('task_id'), value.get('workspace'))
                != self._identity or value.get('caller_id') != self._input['caller_id']):
            raise WorkflowError('caller verification Project/Stage/Task/workspace/caller mismatch')

    def _check(self, authorities):
        for ref in self._refs:
            _, raw = _pinned(self._pins[ref])
            if (raw.decode('utf-8-sig') != self._originals[ref]
                    or authorities.get(ref) != self._originals[ref]):
                raise WorkflowError('caller original Authority bytes changed')
        value = self._input
        self._same_identity(value)
        resource = self._json(authorities[value['resource_ref']])
        fields = {'origin', 'project', 'stage_id', 'task_id', 'workspace', 'caller_id',
                  'owner_source_ref', 'supplement_ref', 'preparation_ref', 'limits',
                  'authorized_at_utc', 'valid_until_utc', 'route'}
        if set(resource) != fields or resource['origin'] != 'OWNER_APPROVED_RESOURCE_AUTHORIZATION':
            raise WorkflowError('actual pinned Owner resource authorization required')
        self._same_identity(resource)
        if (not isinstance(resource['limits'], dict) or set(resource['limits']) != self.limits
                or any(type(resource['limits'][key]) is not int for key in self.limits)
                or any(resource[k] != value[k] for k in ('owner_source_ref', 'supplement_ref', 'preparation_ref'))
                or resource['limits'] != value['approved_limits']
                or resource['route'] != 'existing_chatgpt_subscription_codex_app_server'):
            raise WorkflowError('caller resource sources, approved limits or route mismatch')
        try:
            began = datetime.fromisoformat(resource['authorized_at_utc'])
            until = datetime.fromisoformat(resource['valid_until_utc'])
            now = datetime.now(timezone.utc)
            valid = (began.tzinfo is not None and until.tzinfo is not None and began <= now < until
                     and (until - began).total_seconds() <= value['approved_limits']['total_seconds'])
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise WorkflowError('caller resource approval expired or has an invalid fixed window')
        preparation = self._json(authorities[value['preparation_ref']])
        if (set(preparation) != {'origin', 'project', 'stage_id', 'task_id', 'workspace',
                                'caller_id', 'scope', 'pins'}
                or preparation['origin'] != 'CALLER_PREPARATION_MANIFEST'
                or preparation['scope'] != value['scope']
                or not isinstance(preparation['pins'], dict) or not preparation['pins']
                or len(preparation['pins']) > 256):
            raise WorkflowError('bounded current caller preparation manifest required')
        self._same_identity(preparation)
        for pin in preparation['pins'].values():
            _pinned(pin)
        return resource, preparation

    def materials(self, state, activity, materials, authorities, *, native=False):
        if native and activity != 'EXECUTOR_IMPLEMENT':
            raise WorkflowError('native caller facts apply only to implementation')
        resource, preparation = self._check(authorities)
        project, stage, task, workspace = self._identity
        if (state.get('project') != project or state.get('stage_id') != stage
                or state.get('task_id') not in (None, task)):
            raise WorkflowError('caller verification differs from current workflow identity')
        result = {key: raw for key, raw in materials.items() if key not in self._refs}
        intent_ref = state.get('formal_task_intent_ref')
        if state.get('task_id') is not None:
            if not intent_ref or intent_ref not in materials:
                raise WorkflowError('caller verification missing original Task Intent')
            intent = self._json(materials[intent_ref])
            if (intent.get('task_id') != task or intent.get('scope') != self._input['scope']
                    or not set(self._required).issubset(intent.get('authority_refs', []))):
                raise WorkflowError('caller verification Task Intent/scope/source binding mismatch')
        if activity in self.activities or state.get('task_id') is not None:
            for ref in self._required:
                result[ref] = authorities[ref]  # Preserve required original Intent sources downstream too.
        if activity not in self.activities and not native:
            return result
        result['HOST_CALLER_VERIFICATION'] = json.dumps({
            'origin': 'HOST_CALLER_VERIFICATION', 'source': 'DERIVED_HOST_REVALIDATION_NOT_A_NEW_GRANT',
            'project': project, 'stage_id': stage, 'task_id': task, 'workspace': workspace,
            'caller_id': self._input['caller_id'], 'intent_ref': intent_ref,
            'context_ref': None, 'approved_limits': resource['limits'], 'scope': self._input['scope'],
            'valid_until_utc': resource['valid_until_utc'], 'admitted_at_utc': self._checked_at,
            'preparation_pins_verified': len(preparation['pins']),
            'legal_evidence_refs': self._required,
            'host_only_source_pins': {ref: self._pins[ref]['sha256'] for ref in self._refs
                                      if ref not in self._required},
            'limits': 'Source pins and scope/expiry were rechecked by Host. Included-usage permission, '
                      'durable resource consumption, Writer, actual tools, Human and Result Gates remain '
                      'separate caller/Host checks. Host-only bodies were not given to this role; '
                      'cite only exact supplied original refs, never this dynamic label.'}, ensure_ascii=False)
        return result

    def bind_context(self, state, activity, materials, authorities, context_ref, registry):
        expected = self.materials(state, activity, materials, authorities)
        if activity not in self.activities:
            return expected
        if materials.get('HOST_CALLER_VERIFICATION') != expected['HOST_CALLER_VERIFICATION']:
            raise WorkflowError('caller verification projection is forged or belongs to an old Context')
        record = registry.get(context_ref)
        from loommode.codex.context import ContextPurpose, FreshnessState
        from loommode.workflow.transitions import Node, TABLE
        metadata = record.activity_metadata or {}
        if (record.thread_id != context_ref or record.purpose != ContextPurpose.READ_ONLY_ROLE
                or record.freshness != FreshnessState.READ_ONLY_ROLE
                or record.tool_profile != 'READ_ONLY_REVIEW'
                or str(Path(record.workspace).resolve()) != self._identity[3]
                or metadata.get('stage') != self._identity[1]
                or metadata.get('role') != TABLE[Node(activity)][0].value):
            raise WorkflowError('caller recipient Context identity/purpose/role mismatch')
        projection = self._json(expected['HOST_CALLER_VERIFICATION'])
        projection['context_ref'] = context_ref
        expected['HOST_CALLER_VERIFICATION'] = json.dumps(projection, ensure_ascii=False)
        return expected


def _policy(value, workspace):
    from loommode.tools.runtime import ToolPolicy, ToolProfile
    from loommode.tools.test_runner import TestSpec
    if not isinstance(value, dict) or set(value) != {'readable', 'writable', 'tests'}:
        raise WorkflowError('bounded policy fields required')
    if any(not isinstance(value[key], list) for key in ('readable', 'writable', 'tests')):
        raise WorkflowError('explicit bounded policy lists required')
    readable = tuple(normalize_relative(p) for p in value['readable'])
    writable = tuple(normalize_relative(p) for p in value['writable'])
    tests = []
    for row in value['tests']:
        if not isinstance(row, dict) or set(row) != {'test_id', 'argv', 'cwd', 'timeout_seconds'}:
            raise WorkflowError('fixed TestSpec fields required')
        if (not isinstance(row['argv'], list) or not row['argv']
                or any(not isinstance(v, str) or not v for v in row['argv'])
                or type(row['timeout_seconds']) not in (int, float) or not 0 < row['timeout_seconds'] <= 600):
            raise WorkflowError('bounded fixed test command required')
        tests.append(TestSpec(identity(row['test_id']), tuple(row['argv']), row['cwd'], row['timeout_seconds']))
    policy = ToolPolicy(workspace, ToolProfile.BOUNDED_DEVELOPMENT, readable, writable,
                        test_specs=tuple(tests))
    policy.preflight(check_tests=False)
    return policy


def preflight(path, *, expected_sha256):
    facts = inspect_config(path, expected_sha256=expected_sha256)
    return {'status': 'BOOTSTRAP_STATIC_READ_ONLY', 'project': facts['value']['project'],
            'stage_id': facts['value']['stage_id'], 'third_party_api': 'NOT_CONFIGURED',
            'factory_imported': False, 'state_opened': False, 'writes': 0,
            'codex_authentication': 'NOT_TESTED', 'app_server_protocol': 'NOT_TESTED',
            'models': 'NOT_TESTED', 'writability': 'NOT_TESTED_READ_ONLY',
            'task_result_gate': 'NOT_RUN', 'runtime_host': 'NOT_ASSEMBLED'}


def create_host(path, *, expected_sha256, canonical_context):
    """Called only by the reviewed hash-pinned factory under its original lease."""
    from loommode.codex.adapter import AdapterConfig, ThinCodexAdapter
    from loommode.codex.app_server import BinaryPolicy
    from loommode.codex.context import ContextRegistry
    from loommode.tools.runtime import ToolPolicy, ToolProfile
    from loommode.roles.runtime import RoleRuntime, current_verified_profiles
    from loommode.workflow.executor import ExecutorRuntime
    from loommode.workflow.engine import WorkflowEngine
    from loommode.workflow.state import WorkflowState
    from loommode.workflow.transitions import Role
    from .cli import _process_store
    from .decision import DecisionEntry
    from .driver import DecisionHost
    from .state_view import StateProjection
    facts = inspect_config(path, expected_sha256=expected_sha256)
    value, roots = facts['value'], facts['roots']
    binding = canonical_context._binding
    authority_text = facts['authorities'][value['stage_authorization_ref']]
    if (binding['project'] != value['project'] or binding['stage_id'] != value['stage_id']
            or Path(binding['workspace']).resolve() != roots['workspace']
            or binding['stage_authorization_ref'] != value['stage_authorization_ref']
            or binding['stage_authorization_sha256'] != hashlib.sha256(authority_text.encode('utf-8')).hexdigest()
            or binding['grants'] != value['grants']):
        raise WorkflowError('factory configuration and canonical Authority binding disagree')
    adapter = engine = None
    try:
        registry = _registry(roots['runtime_root'], facts['registry_path'])
        adapter = ThinCodexAdapter.from_binary(
            binary_policy=BinaryPolicy(facts['binary'], tuple(value['codex']['supported_versions'])),
            process_cwd=roots['workspace'], allowed_workspace_roots=(roots['workspace'],), registry=registry,
            config=AdapterConfig(executor_workspace_development=True), without_app_tools_bridge=True)
        profiles = current_verified_profiles()
        role_policy = ToolPolicy(roots['workspace'], ToolProfile.READ_ONLY_REVIEW,
                                 facts['stage_policy'].readable_paths, test_specs=facts['stage_policy'].test_specs)
        roles = RoleRuntime(adapter, {Role(k): v for k, v in facts['role_paths'].items()},
                            role_policy, profiles, value['stage_id'])
        executor = ExecutorRuntime(adapter, facts['stage_policy'], facts['task_policies'], profiles)
        artifacts = _process_store(roots['records_root'], value['project'], value['stage_id'], facts['parts'],
                                   namespace_guard=lambda path: _output_path(roots['records_root'], path))
        engine = WorkflowEngine(WorkflowState(value['project'], value['stage_id']), facts['state_store'],
                                artifacts, roles, executor, facts['authorities'],
                                stage_authorization_ref=value['stage_authorization_ref'], local_commit_authorized=False)
        engine.caller_verification = facts['caller_verification']
        roles.caller_verification = facts['caller_verification']
        roles.caller_verification_authorities = engine.authority
        entry = DecisionEntry(StateProjection(project=value['project'], stage_id=value['stage_id'],
            workspace=roots['workspace'], artifacts=artifacts, registry=registry,
            state_provider=lambda: engine.state, source_ref=str(facts['state_store'].path),
            authority_materials=engine.authority, is_busy=lambda: engine._busy))
        host = canonical_context.register_host(DecisionHost(entry, engine,
            allow_progress=value['grants']['allow_progress'], allow_owner_events=value['grants']['allow_owner_events']))
        if value['codex'].get('connect_on_assembly', False):
            # Ownership and cleanup registration precede any app-server launch.
            # The explicit flag selects behavior; actual Stage/Task authority and
            # canonical grants remain the source of permission.
            adapter.connect()
        return host
    except BaseException:
        if canonical_context.host is not None:
            # Original canonical failure cleanup now owns the registered Host;
            # it retains the Writer lease if closure cannot be proved.
            raise
        if engine is not None:
            engine.close_resources()
        elif adapter is not None:
            adapter.close()
        raise
