"""One stateless DeepSeek review transport, with Host-owned grants and ledger.

No tools, local execution, redirects, proxies, retries or provider fallback.
Provider response JSON is untrusted; normal role schemas remain authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import os
import time
from pathlib import Path
from threading import RLock
import urllib.request
import urllib.error
from uuid import uuid4

from loommode.codex.context import ContextPurpose, ResourceState
from loommode.roles.contracts import parse_result, result_schema, obj, text, validate
from loommode.roles.model_routing import digest, scenario
from loommode.tools.filesystem import BoundedFileSystem
from loommode.tools.runtime import ToolProfile, ToolPolicy
from loommode.workflow.errors import WorkflowError, OutputProblem
from loommode.workflow.transitions import FRESH_NODES, Node, TABLE
from loommode.workflow.state import unique_json_object


ENDPOINT = 'https://api.deepseek.com/chat/completions'


@dataclass(frozen=True)
class ApiRolePrompt:
    source: str
    source_sha256: str
    text: str

    @classmethod
    def from_file(cls, path: Path):
        path = path.resolve(strict=True)
        with path.open('rb') as stream:
            raw = stream.read(128001)
        if len(raw) > 128000:
            raise WorkflowError('API role source exceeds bounded size')
        return cls(str(path), hashlib.sha256(raw).hexdigest(),
                   raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n'))

    @classmethod
    def from_text(cls, source: str, text: str):
        return cls(source, hashlib.sha256(text.encode('utf-8')).hexdigest(), text)

    def authorization(self):
        return (self.source, self.source_sha256, hashlib.sha256(self.text.encode('utf-8')).hexdigest())

    def manifest(self):
        source, raw, text = self.authorization()
        return {'source': source, 'source_sha256': raw, 'text_sha256': text}


API_PROTOCOL = ApiRolePrompt.from_text('builtin:loommode-api-protocol-v1',
    'LoomMode read-only invocation. The packet supplies the actual activity, role duties, objective inputs '
    'and result_schema. You have no tools, filesystem, shell, network or write permissions. '
    'Use only this explicit packet; never pretend to execute tests/tools. Return exactly one JSON object '
    'satisfying result_schema, with the authorized activity action and substantive required artifact. '
    'Facts and permissions are Host-owned; findings grant no repair, acceptance or execution authority. '
    'Fresh reviews receive no prior conversation, developer verdict or experience; discussion advises '
    'the existing Constraint/Decision route.')
API_FRESH_REVIEW = ApiRolePrompt.from_text('builtin:loommode-fresh-review-v1',
    'Read current objective code and authority. Review actual evidence; no developer history or verdicts.')
API_FRESH_CORRECTION = ApiRolePrompt.from_text('builtin:loommode-fresh-correction-v1',
    'Correct original review report only; no tools or re-execution. Preserve actual evidence and failures.')
API_ROLE_CORRECTION = ApiRolePrompt.from_text('builtin:loommode-role-correction-v1',
    'Correct original role report only; no implementation or tools. Preserve actual evidence and failures.')
API_INDEPENDENT_OPINION = ApiRolePrompt.from_text('builtin:loommode-independent-opinion-v1',
    'Provide your independent opinion on the approved objective question in this packet.')


class ApiDecisionActivity(StrEnum):
    MODEL_SELECTION = 'MODEL_SELECTION'
    ADVISORY_SYNTHESIS = 'ADVISORY_SYNTHESIS'


API_DECISION_PROTOCOL = ApiRolePrompt.from_text('builtin:loommode-api-decision-protocol-v1',
    'You are a bounded LoomMode Decision metadata worker. You have no tools, files or write permissions. '
    'Use only the explicitly approved input packet. Return exactly one JSON object satisfying its '
    'fixed result_schema. You cannot issue task actions, accept work, create authorization, change '
    'permissions or invoke another model. Host validates every result independently.')
API_MODEL_SELECTION = ApiRolePrompt.from_text('builtin:loommode-api-model-selection-v2',
    'Interpret the original natural-language preferences and actual task nature. Choose one profile_id '
    'from the ordered catalog and explain why. Ordinal is independent of priority and role authority. '
    'For an explicitly requested unavailable third AI, return unavailable-third-ai with the reason, '
    'never silently substitute. For an explicitly requested incapable configured profile, name that '
    'profile and explain the mismatch; Host will reject it. Set applies_to_activity true when the '
    'preference addresses this scenario. Otherwise set it false and return the first Codex profile '
    'to retain the current Host route, including any independently configured implementation backend. '
    'No provider brand or preference creates capability, grants or permission. '
    'MODEL_SELECTION output contract: return one JSON object with exactly these three keys: '
    '"profile_id", "reason", "applies_to_activity". profile_id is a nonempty string of at most '
    '160 characters naming your chosen profile as instructed above. reason is a nonempty string '
    'of at most 4000 characters; normally give one or two short sentences. applies_to_activity '
    'is the JSON boolean true or false, never a quoted string, number, null or explanation. '
    'Do not return the input packet, catalog, result_schema, a task action, extra keys, arrays, '
    'Markdown, code fences or prose outside the JSON object. Choose the values from the actual '
    'activity and original preference; this output format never supplies a model choice.')
API_ADVISORY_SYNTHESIS = ApiRolePrompt.from_text('builtin:loommode-api-advisory-synthesis-v1',
    'Synthesize the supplied attributed independent opinions and direct evidence. Explain disagreements '
    'and limitations; model brand or ranking confers no authority. The judgment is advisory only and '
    'cannot accept a task, grant permission or move an Engine node.')


def api_decision_schema(activity):
    if activity == ApiDecisionActivity.MODEL_SELECTION:
        return obj({'profile_id': {**text(), 'maxLength': 160}, 'reason': {**text(), 'maxLength': 4000},
                    'applies_to_activity': {'type': 'boolean'}})
    if activity == ApiDecisionActivity.ADVISORY_SYNTHESIS:
        return obj({'judgment': {**text(), 'maxLength': 8000}, 'reason': {**text(), 'maxLength': 4000}})
    raise WorkflowError('unsupported finite API Decision metadata activity')


@dataclass(frozen=True)
class PreparedDecisionInput:
    activity: ApiDecisionActivity
    material_text: str
    role_prompts: tuple[ApiRolePrompt, ...]

    @property
    def material_ref(self):
        return self.activity.value + '_REQUEST'

    @property
    def state(self):
        value = json.loads(self.material_text)
        return {key: value[key] for key in ('project', 'stage_id', 'task_id')}

    def manifests(self):
        return [prompt.manifest() for prompt in self.role_prompts]


def prepare_decision_metadata(activity, request):
    """Pure exact-input preparation for prior Host approval; no files/keys/I/O."""
    from loommode.roles.model_routing import ModelCatalog
    if not isinstance(activity, ApiDecisionActivity) or not isinstance(request, dict):
        raise WorkflowError('explicit finite Decision metadata activity and request required')
    scope = {'project', 'stage_id', 'task_id'}
    expected = (scope | {'activity', 'scenario', 'task_nature', 'preferences', 'catalog'}
                if activity == ApiDecisionActivity.MODEL_SELECTION else scope | {'question', 'opinions'})
    if (set(request) != expected or any(not isinstance(request[k], str) or not request[k].strip()
            for k in ('project', 'stage_id'))
            or (request['task_id'] is not None and (not isinstance(request['task_id'], str) or not request['task_id'].strip()))):
        raise WorkflowError('invalid exact API Decision metadata request')
    if activity == ApiDecisionActivity.MODEL_SELECTION:
        try:
            node = Node(request['activity'])
            profiles = []
            for index, profile in enumerate(request['catalog']):
                if type(profile['ordinal']) is not int or profile['ordinal'] != index + 1:
                    raise ValueError('ordinal')
                item = {k: v for k, v in profile.items() if k != 'ordinal'}
                if isinstance(item.get('capabilities'), tuple):
                    item['capabilities'] = list(item['capabilities'])
                profiles.append(item)
            ModelCatalog({'schema_version': 1, 'preferences': request['preferences'], 'profiles': profiles})
            nature = request['task_nature']
            if (request['scenario'] != scenario(node) or (nature != '' and
                    (not isinstance(nature, dict) or set(nature) != {'goal', 'expected_result', 'acceptance_intent'}
                     or any(not isinstance(v, str) for v in nature.values())))):
                raise ValueError('task nature')
        except (ValueError, TypeError, KeyError, AttributeError):
            raise WorkflowError('invalid credential-free selection catalog/task request') from None
        instruction = API_MODEL_SELECTION
    else:
        if (not isinstance(request['question'], str) or not request['question'].strip()
                or not isinstance(request['opinions'], list) or not 2 <= len(request['opinions']) <= 4
                or any(not isinstance(opinion, dict) or set(opinion) != {'profile_id', 'context_ref', 'result', 'invocation'}
                       or not isinstance(opinion['invocation'], dict) or not isinstance(opinion['result'], dict)
                       or not isinstance(opinion['profile_id'], str) or not isinstance(opinion['context_ref'], str)
                       for opinion in request['opinions'])):
            raise WorkflowError('invalid bounded attributed advisory-synthesis request')
        instruction = API_ADVISORY_SYNTHESIS
    try:
        body = json.dumps(request, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    except (ValueError, TypeError):
        raise WorkflowError('Decision metadata input is not bounded JSON') from None
    source = 'input:loommode-' + activity.value.lower().replace('_', '-') + '-request-v1'
    return PreparedDecisionInput(activity, body, (API_DECISION_PROTOCOL, instruction, ApiRolePrompt.from_text(source, body)))


@dataclass(frozen=True)
class ApiReviewGrant:
    grant_id: str
    source_ref: str
    project: str
    stage_id: str
    task_ids: tuple[str | None, ...]
    profile_ids: tuple[str, ...]
    activities: tuple[str, ...]
    material_refs: tuple[str, ...]
    readable_paths: tuple[str, ...]
    expires_at: str
    max_calls: int
    max_total_tokens: int
    max_input_bytes: int
    max_output_tokens: int
    provider: str = 'deepseek'
    transport: str = 'deepseek_chat'
    model: str = 'deepseek-flash'
    reasoning_effort: str = 'none'
    endpoint: str = ENDPOINT
    workspace: str = ''
    purposes: tuple[str, ...] = ('WORKFLOW',)
    role_sources: tuple[tuple[str, str, str], ...] = ()

    @classmethod
    def from_dict(cls, value):
        # Governance artifacts may include non-executable source explanations.
        fields = cls.__dataclass_fields__
        selected = {k: v for k, v in value.items() if k in fields}
        for key in ('task_ids', 'profile_ids', 'activities', 'material_refs', 'readable_paths', 'purposes'):
            if key in selected:
                selected[key] = tuple(selected[key])
        if 'role_sources' in selected:
            try:
                selected['role_sources'] = tuple((item['source'], item['source_sha256'], item['text_sha256'])
                                                 for item in selected['role_sources'])
            except (KeyError, TypeError):
                raise WorkflowError('invalid approved API role-source manifest') from None
        return cls(**selected)

    def check(self, profile, node, state, materials, policy, now):
        if not isinstance(materials, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                 for k, v in materials.items()):
            raise WorkflowError('API review materials must be explicit text references')
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            expired = expiry.tzinfo is None or now >= expiry
        except (ValueError, TypeError):
            expired = True
        if (expired or not self.grant_id or not self.source_ref
                or state.get('project') != self.project or state.get('stage_id') != self.stage_id
                or state.get('task_id') not in self.task_ids or node.value not in self.activities
                or profile.profile_id not in self.profile_ids
                or (profile.provider, profile.transport, profile.model, profile.reasoning_effort)
                != (self.provider, self.transport, self.model, self.reasoning_effort)
                or self.endpoint != ENDPOINT
                or not self.workspace or policy.workspace.resolve() != Path(self.workspace).resolve()
                or not set(materials).issubset(self.material_refs)
                or not set(policy.readable_paths).issubset(self.readable_paths)
                or any(type(n) is not int or n <= 0 for n in
                       (self.max_calls, self.max_total_tokens, self.max_input_bytes, self.max_output_tokens))
                or self.max_calls > 100 or self.max_input_bytes > 512000 or self.max_output_tokens > 8192):
            raise WorkflowError('API review Grant rejected scope, identity, limits or expiry')
        metadata = isinstance(node, ApiDecisionActivity)
        if metadata and (node.value not in self.purposes or policy.readable_paths or policy.writable_paths
                         or policy.stageable_paths or policy.test_specs or policy.commit_messages):
            raise WorkflowError('API Decision metadata requires explicit purpose and zero file/tool grants')
        if (not metadata and scenario(node) not in {'discussion', 'fresh_review'}) or policy.profile != ToolProfile.READ_ONLY_REVIEW:
            raise WorkflowError('API review is read-only and has no implementation permissions')
        policy.preflight(check_tests=False)


class ReviewLedger:
    """Durable append-only reservations. Incomplete/UNKNOWN entries hold dispatch.

    Lifetime lock is intentionally process-local: the existing Host single writer
    lease is required for assembly. This is not a distributed budget service.
    """
    def __init__(self, path: Path, grant: ApiReviewGrant):
        self.path, self.grant, self.lock = Path(path), grant, RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self):
        if not self.path.exists():
            return []
        try:
            values = [json.loads(line) for line in self.path.read_text(encoding='utf-8').splitlines()]
            if any(v.get('grant_id') != self.grant.grant_id for v in values):
                raise ValueError('different grant')
            reservations, settled = set(), set()
            for value in values:
                event = value.get('event')
                if event == 'MODEL_SELECTION':
                    if not isinstance(value.get('selection'), dict):
                        raise ValueError('invalid selection')
                elif event == 'RESERVED':
                    attempt = value.get('attempt_id')
                    if (not isinstance(attempt, str) or not attempt or attempt in reservations
                            or not isinstance(value.get('dispatch_key'), str)
                            or type(value.get('reserved_tokens')) is not int or value['reserved_tokens'] <= 0):
                        raise ValueError('invalid reservation')
                    reservations.add(attempt)
                elif event == 'SETTLED':
                    attempt = value.get('attempt_id')
                    if (attempt not in reservations or attempt in settled or value.get('outcome') not in
                            {'NOT_SENT', 'COMPLETED', 'INCOMPLETE', 'UNKNOWN'}):
                        raise ValueError('invalid settlement')
                    settled.add(attempt)
                else:
                    raise ValueError('unknown event')
            return values
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            raise WorkflowError('API ledger is unreadable; dispatch held') from None

    def append(self, event):
        value = {'grant_id': self.grant.grant_id, 'at': datetime.now(timezone.utc).isoformat(), **event}
        try:
            with self.path.open('a', encoding='utf-8', newline='\n') as stream:
                stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            raise WorkflowError('API ledger durability failed; dispatch held') from None

    def reserve(self, key, tokens, evidence):
        with self.lock:
            events = self._read()
            reserved = [v for v in events if v.get('event') == 'RESERVED']
            settled = {v['attempt_id']: v for v in events if v.get('event') == 'SETTLED'}
            if any(value.get('continuation_hold') is True or (value.get('outcome') == 'COMPLETED'
                    and (not value.get('requested_model') or not value.get('returned_model')
                         or value['requested_model'] != value['returned_model'])) for value in settled.values()):
                raise WorkflowError('API ledger has unverified model identity; paid continuation held')
            if any(v['attempt_id'] not in settled or settled[v['attempt_id']]['outcome'] == 'UNKNOWN'
                   for v in reserved):
                raise WorkflowError('API ledger has UNKNOWN or incomplete dispatch; paid continuation held')
            if any(v['dispatch_key'] == key for v in reserved):
                raise WorkflowError('API dispatch already reserved; automatic replay denied')
            if (len(reserved) >= self.grant.max_calls
                    or sum(v['reserved_tokens'] for v in reserved) + tokens > self.grant.max_total_tokens):
                raise WorkflowError('API review call/token allowance exhausted')
            attempt = str(uuid4())
            self.append({'event': 'RESERVED', 'attempt_id': attempt, 'dispatch_key': key,
                         'reserved_tokens': tokens, **evidence})
            return attempt

    def settle(self, attempt, outcome, **evidence):
        with self.lock:
            self.append({'event': 'SETTLED', 'attempt_id': attempt, 'outcome': outcome, **evidence})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def deepseek_request(payload: bytes, credential: str, timeout: float, max_bytes: int):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(ENDPOINT, data=payload, method='POST', headers={
        'Content-Type': 'application/json', 'Authorization': 'Bearer ' + credential})
    deadline = time.monotonic() + timeout
    try:
        with opener.open(request, timeout=timeout) as reply:
            # A redirect/error is never followed or read into diagnostic text.
            if reply.status != 200:
                return reply.status, b''
            chunks, size = [], 0
            while reply.length != 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkflowError('API transport deadline exceeded')
                # urllib's HTTPResponse keeps the live TLS socket here. Fail
                # closed if this runtime cannot apply the remaining read bound.
                reply.fp.raw._sock.settimeout(remaining)
                chunk = reply.read1(min(4096, max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    raise WorkflowError('API response exceeds byte limit')
            if time.monotonic() > deadline:
                raise WorkflowError('API transport deadline exceeded')
            return reply.status, b''.join(chunks)
    except urllib.error.HTTPError as exc:
        # Never retain/echo a provider body, headers or request object.
        return exc.code, b''


def _usage(value):
    if (not isinstance(value, dict) or any(type(value.get(k)) is not int or value[k] < 0
            for k in ('prompt_tokens', 'completion_tokens', 'total_tokens'))
            or value['prompt_tokens'] + value['completion_tokens'] != value['total_tokens']):
        raise WorkflowError('API usage missing or invalid')
    result = {k: value[k] for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')}
    for key in ('prompt_cache_hit_tokens', 'prompt_cache_miss_tokens'):
        if key in value:
            if type(value[key]) is not int or value[key] < 0:
                raise WorkflowError('API cache usage invalid')
            result[key] = value[key]
    if (all(k in result for k in ('prompt_cache_hit_tokens', 'prompt_cache_miss_tokens'))
            and result['prompt_cache_hit_tokens'] + result['prompt_cache_miss_tokens'] != result['prompt_tokens']):
        raise WorkflowError('API cache usage inconsistent')
    return result


class ApiReviewDriver:
    def __init__(self, registry, grant: ApiReviewGrant, credential_loader, ledger_path: Path,
                 *, transport=deepseek_request, timeout=45.0, max_response_bytes=256000,
                 clock=lambda: datetime.now(timezone.utc)):
        if not 0 < timeout <= 60 or not 1000 <= max_response_bytes <= 512000:
            raise WorkflowError('bounded API transport limits required')
        self.registry, self.grant, self.credential_loader = registry, grant, credential_loader
        self.ledger = ReviewLedger(ledger_path, grant)
        self.transport, self.timeout, self.max_response_bytes, self.clock = transport, timeout, max_response_bytes, clock
        self.lock = RLock()
        self.pending_correction_refs = {record.thread_id for record in self.registry.all()
            if record.owner_id == grant.grant_id and record.resource_state != ResourceState.RELEASED
            and (record.activity_metadata or {}).get('temporary_correction') == 'true'}

    def record_selection(self, evidence):
        with self.ledger.lock:
            self.ledger.append({'event': 'MODEL_SELECTION', 'selection': evidence})

    def owns(self, context_ref):
        if not context_ref:
            return False
        return (self.registry.get(context_ref).activity_metadata or {}).get('transport') == 'deepseek_chat'

    def release(self, context_ref, reason):
        receipt = {'released': True, 'reason': reason, 'proof': 'STATELESS_API_NO_NATIVE_RESOURCES'}
        self.registry.resource(context_ref, ResourceState.RELEASED, receipt=receipt)
        self.pending_correction_refs.discard(context_ref)
        return receipt

    def ensure_dispatch_ready(self, profile_id=None):
        if self.pending_correction_refs:
            raise WorkflowError('API correction context cleanup is unverified; new dispatch held')

    def _authorize_prompts(self, prompts):
        try:
            allowed_roles = set(self.grant.role_sources)
            if any(len(item) != 3 or not all(isinstance(v, str) for v in item)
                   or any(len(h) != 64 or any(c not in '0123456789abcdef' for c in h) for h in item[1:])
                   for item in allowed_roles):
                raise ValueError('invalid approved hashes')
        except (TypeError, ValueError):
            raise WorkflowError('invalid approved API role-source manifest') from None
        if not prompts or any(not isinstance(prompt, ApiRolePrompt) or prompt.authorization() not in allowed_roles
                                   for prompt in prompts):
            raise WorkflowError('outbound API role source/content is not explicitly approved')
        return allowed_roles

    def packet(self, *, node, state, materials, policy, role_prompts=(), purpose='WORKFLOW', question=None):
        if (purpose not in {'WORKFLOW', 'INDEPENDENT_OPINION', 'REPORT_CORRECTION'}
                or purpose not in self.grant.purposes
                or (purpose == 'INDEPENDENT_OPINION' and
                    (not isinstance(question, str) or not question.strip() or len(question) > 4000))
                or (purpose != 'INDEPENDENT_OPINION' and question is not None)):
            raise WorkflowError('explicit API invocation purpose/question lacks current Grant')
        prompts = (API_PROTOCOL, *role_prompts)
        if not role_prompts:
            raise WorkflowError('explicit API role prompts required')
        allowed_roles = self._authorize_prompts(prompts)
        if purpose == 'INDEPENDENT_OPINION':
            question_prompt = ApiRolePrompt.from_text('input:consultation-question', question)
            if question_prompt.authorization() not in allowed_roles:
                raise WorkflowError('outbound consultation question is not explicitly approved')
            prompts = (*prompts, question_prompt)
        fs = BoundedFileSystem(policy.workspace, readable=policy.readable_paths, writable=(),
                               max_read_bytes=self.grant.max_input_bytes)
        files = []
        present = fs.list_allowed()['files']
        if set(present) != set(policy.readable_paths):
            raise WorkflowError('approved review packet contains missing files; partial review denied')
        for path in present:
            if any(part.lower() in {'.git', '.aws', '.ssh', '.codex'} or part.lower().startswith('.env')
                   or any(word in part.lower() for word in ('credential', 'secret', 'api-key', 'api_key'))
                   for part in Path(path).parts):
                raise WorkflowError('sensitive review file rejected')
            content = fs.read_text(path)
            from loommode.tools.filesystem import WorkspaceGuard
            _, target = WorkspaceGuard.target(policy.workspace.resolve(), path, must_exist=True)
            with target.open('rb') as stream:
                raw_bytes = stream.read(self.grant.max_input_bytes + 1)
            if len(raw_bytes) > self.grant.max_input_bytes:
                raise WorkflowError('review file exceeds approved bytes')
            text_bytes = content['text'].encode('utf-8')
            if raw_bytes.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n') != content['text']:
                raise WorkflowError('review file changed during packet read')
            files.append({'path': path, 'text': content['text'],
                          'sha256': hashlib.sha256(raw_bytes).hexdigest(),
                          'text_sha256': hashlib.sha256(text_bytes).hexdigest()})
        # Fresh state is explicitly small; no conversation/report/reference history.
        packet_state = {k: state.get(k) for k in ('project', 'stage_id', 'task_id')}
        packet = {'activity': node.value, 'role': TABLE[node][0].value, 'invocation_purpose': purpose, 'question': question,
                  'state': packet_state, 'materials': materials,
                  'files': files, 'role_prompts': [{**p.manifest(), 'text': p.text} for p in prompts],
                  'result_schema': result_schema(node, state)}
        return packet


    def invoke(self, **kwargs):
        # A correction owns every temporary context it creates, including a
        # second schema failure. Cleanup preserves the original exception.
        self.ensure_dispatch_ready()
        if not kwargs.get('correction'):
            return self._invoke(**kwargs)
        return self._temporary_call(lambda refs: self._invoke(**kwargs, context_refs=refs))

    def _temporary_call(self, execute):
        self.ensure_dispatch_ready()
        refs, original = [], None
        try:
            return execute(refs)
        except BaseException as exc:
            original = exc
            raise
        finally:
            self.pending_correction_refs.update(refs)
            for ref in refs:
                try:
                    record = self.registry.get(ref)
                    if record.resource_state != ResourceState.RELEASED:
                        self.release(ref, 'TEMPORARY_API_REPORT_CORRECTION_COMPLETE')
                    else:
                        self.pending_correction_refs.discard(ref)
                except Exception:
                    if original is not None:
                        original.api_correction_cleanup = 'UNVERIFIED'
                        if isinstance(getattr(original, 'metadata', None), dict):
                            original.metadata['correction_cleanup'] = {'status': 'UNVERIFIED', 'context_refs': list(refs)}
                    else:
                        raise WorkflowError('API report correction cleanup is unverified') from None

    def _invoke(self, *, selection, node, state, materials, role_prompts, policy, correction=False,
                purpose='WORKFLOW', question=None, context_refs=None):
        from loommode.roles.runtime import Invocation
        with self.lock:
            profile = selection.profile
            self.grant.check(profile, node, state, materials, policy, self.clock())
            purpose = 'REPORT_CORRECTION' if correction else purpose
            packet = self.packet(node=node, state=state, materials=materials, policy=policy,
                                 role_prompts=role_prompts, purpose=purpose, question=question)
            content, context_ref, metadata = self._complete(profile=profile, packet=packet, policy=policy,
                evidence=selection.evidence, role=TABLE[node][0].value, fresh=node in FRESH_NODES,
                temporary=correction, context_refs=context_refs)
            try:
                result = parse_result(content, node, state)
            except WorkflowError:
                problem = OutputProblem('API role result schema rejected', content, context_ref, metadata)
                problem.safe_observation = metadata['safe_observation']
                raise problem from None
            return Invocation(result, context_ref, metadata=metadata)

    def decision_metadata(self, *, activity, request, profile, workspace):
        """Only two fixed metadata schemas; never a caller-supplied agent/schema."""
        prepared = prepare_decision_metadata(activity, request)
        return self._temporary_call(lambda refs: self._decision_metadata(prepared, profile, workspace, refs))

    def _decision_metadata(self, prepared, profile, workspace, refs):
        from loommode.roles.runtime import Invocation
        with self.lock:
            policy = ToolPolicy(Path(workspace), ToolProfile.READ_ONLY_REVIEW, ())
            materials = {prepared.material_ref: prepared.material_text}
            self.grant.check(profile, prepared.activity, prepared.state, materials, policy, self.clock())
            self._authorize_prompts(prepared.role_prompts)
            schema = api_decision_schema(prepared.activity)
            packet = {'activity': prepared.activity.value, 'role': 'Decision',
                      'invocation_purpose': prepared.activity.value, 'state': prepared.state,
                      'materials': materials, 'files': [],
                      'role_prompts': [{**p.manifest(), 'text': p.text} for p in prepared.role_prompts],
                      'result_schema': schema}
            evidence = {'origin': 'HOST_EXPLICIT_API_DECISION_BACKEND', 'profile_id': profile.profile_id,
                        'activity': prepared.activity.value, 'request_sha256': digest(json.loads(prepared.material_text))}
            content, context_ref, metadata = self._complete(profile=profile, packet=packet, policy=policy,
                evidence=evidence, role='Decision', temporary=True, context_refs=refs)
            rejection_stage = 'JSON_PARSE'
            try:
                result = json.loads(content, object_pairs_hook=unique_json_object)
                rejection_stage = 'SCHEMA_VALIDATION'
                validate(result, schema)
                rejection_stage = 'FIELD_LENGTH'
                if any(isinstance(value, str) and len(value) > schema['properties'][key].get('maxLength', len(value))
                       for key, value in result.items()):
                    raise WorkflowError('Decision metadata text exceeds fixed bounds')
            except (ValueError, TypeError):
                # _complete has already bounded the successful response and
                # validated completion, model identity and usage. Preserve the
                # rejected model message, never an HTTP error body or headers.
                raw_bytes = content.encode('utf-8')
                self.record_selection({'origin': 'API_DECISION_METADATA_SCHEMA_REJECTED',
                    'activity': prepared.activity.value, 'context_ref': context_ref,
                    'rejection_stage': rejection_stage,
                    'raw_output_source': 'MODEL_MESSAGE_CONTENT', 'raw_output': content,
                    'raw_output_sha256': hashlib.sha256(raw_bytes).hexdigest(),
                    'raw_output_bytes': len(raw_bytes),
                    'invocation': {k: v for k, v in metadata.items() if k != 'raw_output'}})
                raise OutputProblem('API Decision metadata schema rejected', content, context_ref, metadata) from None
            self.record_selection({'origin': 'API_DECISION_METADATA_RESULT', 'activity': prepared.activity.value,
                                   'context_ref': context_ref, 'result': result, 'invocation': metadata})
            return Invocation(result, context_ref, metadata=metadata)

    def _complete(self, *, profile, packet, policy, evidence, role, fresh=False, temporary=False, context_refs=None):
        if (profile.verification != 'VERIFIED' or profile.transport != 'deepseek_chat' or profile.provider != 'deepseek'
                or profile.model not in {'deepseek-flash', 'deepseek-v4-pro'}
                or profile.reasoning_effort not in {'none', 'low', 'high', 'max'}):
            raise WorkflowError('unsupported DeepSeek review interface/model/reasoning')
        files = packet['files']
        state = packet['state']
        activity = packet['activity']
        purpose = packet['invocation_purpose']
        system = packet['role_prompts'][0]['text']
        if activity == ApiDecisionActivity.MODEL_SELECTION.value:
            # Both fixed prompts have passed the existing exact-source Grant
            # check. Task/preferences stay in the user packet, never the system.
            system += '\n\n' + packet['role_prompts'][1]['text']
        payload = json.dumps({'model': profile.model, 'reasoning_effort': profile.reasoning_effort,
                              'messages': [{'role': 'system', 'content': system},
                                           {'role': 'user', 'content': json.dumps(packet, ensure_ascii=False)}],
                              'response_format': {'type': 'json_object'}, 'stream': False,
                              'max_tokens': self.grant.max_output_tokens}, ensure_ascii=False).encode('utf-8')
        if len(payload) > self.grant.max_input_bytes:
            raise WorkflowError('complete API request exceeds approved input bytes')
        reserved = len(payload) + self.grant.max_output_tokens + 1024
        packet_hash = digest(packet)
        key = digest({'profile': profile.profile_id, 'packet': packet_hash, 'correction': purpose == 'REPORT_CORRECTION'})
        attempt = self.ledger.reserve(key, reserved, {'profile_id': profile.profile_id,
            'provider': profile.provider, 'model': profile.model, 'activity': activity,
            'invocation_purpose': purpose,
            'project': state['project'], 'stage_id': state['stage_id'], 'task_id': state.get('task_id'),
            'packet_sha256': packet_hash, 'request_sha256': hashlib.sha256(payload).hexdigest(),
            'file_manifest': [{k: v for k, v in f.items() if k != 'text'} for f in files],
            'role_source_manifest': [{k: v for k, v in p.items() if k != 'text'} for p in packet['role_prompts']],
            'selection': evidence, 'grant_source_ref': self.grant.source_ref})
        context_ref = 'api-review-' + attempt
        if context_refs is not None:
            context_refs.append(context_ref)
        self.registry.create(thread_id=context_ref,
            purpose=ContextPurpose.FRESH_REVIEW if fresh else ContextPurpose.READ_ONLY_ROLE,
            workspace=policy.workspace.resolve(), model=profile.model, reasoning_effort=profile.reasoning_effort,
            tool_profile=ToolProfile.READ_ONLY_REVIEW.value, codex_version='NOT_CODEX',
            owner_id=self.grant.grant_id, activity_metadata={'transport': 'deepseek_chat',
                'stage': state['stage_id'], 'role': role, 'activity': activity,
                'temporary_correction': 'true' if temporary else 'false',
                'profile_id': profile.profile_id, 'packet_sha256': packet_hash})
        # Reservation precedes credential access and send. Failure cannot replenish it.
        try:
            credential = self.credential_loader(profile.profile_id)
            if not isinstance(credential, str) or not credential.strip() or '\n' in credential or '\r' in credential:
                raise ValueError('invalid credential')
        except Exception:
            self.ledger.settle(attempt, 'NOT_SENT', reason_code='CREDENTIAL_UNAVAILABLE')
            self.registry.record_turn(context_ref, attempt, 'failed')
            self.release(context_ref, 'CREDENTIAL_UNAVAILABLE')
            raise WorkflowError('approved API credential unavailable') from None
        status, usage = None, None
        try:
            status, body = self.transport(payload, credential, self.timeout, self.max_response_bytes)
            credential = None
            if status != 200:
                raise WorkflowError('API HTTP response rejected')
            if not isinstance(body, bytes) or len(body) > self.max_response_bytes:
                raise WorkflowError('API response exceeds byte limit')
            response = json.loads(body, object_pairs_hook=unique_json_object)
            usage = _usage(response.get('usage'))
            if usage['total_tokens'] > reserved or usage['completion_tokens'] > self.grant.max_output_tokens:
                raise WorkflowError('API usage exceeds reservation')
            requested_model, returned_model = profile.model, response.get('model')
            if not isinstance(returned_model, str) or not returned_model.strip():
                raise WorkflowError('API response model identity missing')
            choices = response.get('choices')
            if not isinstance(choices, list) or len(choices) != 1:
                raise WorkflowError('API response choice invalid')
            choice = choices[0]
            message = choice.get('message', {})
            content = message.get('content')
            finish = choice.get('finish_reason')
            if finish != 'stop' or message.get('tool_calls') or not isinstance(content, str):
                self.ledger.settle(attempt, 'INCOMPLETE', usage=usage, finish_reason=str(finish)[:32],
                                   requested_model=requested_model, returned_model=returned_model,
                                   continuation_hold=returned_model != requested_model)
                self.registry.record_turn(context_ref, attempt, 'incomplete')
                self.release(context_ref, 'INCOMPLETE_API_RESPONSE')
                raise _KnownIncomplete()
        except _KnownIncomplete:
            raise WorkflowError('API review did not complete; no automatic retry') from None
        except Exception:
            self.ledger.settle(attempt, 'UNKNOWN', reason_code='HTTP_TRANSPORT_USAGE_OR_IDENTITY_UNCERTAIN',
                               http_status=status if type(status) is int and 100 <= status <= 599 else None,
                               usage=usage, usage_status='VALID_REPORTED' if usage else 'INVALID_OR_UNAVAILABLE')
            self.registry.record_turn(context_ref, attempt, 'unknown')
            self.release(context_ref, 'UNKNOWN_API_RESPONSE')
            raise WorkflowError('API outcome or usage UNKNOWN; paid continuation held') from None
        metadata = {'origin': ('HOST_STATELESS_API_DECISION_METADATA' if activity in {'MODEL_SELECTION', 'ADVISORY_SYNTHESIS'} else 'HOST_STATELESS_API_REVIEW'), 'provider': profile.provider,
                    'model': requested_model, 'returned_model': returned_model,
                    'model_identity_status': 'EXACT' if returned_model == requested_model else 'UNVERIFIED',
                    'reasoning_effort': profile.reasoning_effort, 'turn_id': attempt,
                    'usage': usage, 'selection': evidence, 'packet_sha256': packet_hash,
                    'ledger_path': str(self.ledger.path.resolve()), 'raw_output': content,
                    'safe_observation': {'stage': 'parser_schema'}}
        self.registry.record_turn(context_ref, attempt, 'completed')
        # Provider completion and actual usage remain recorded even if role JSON is invalid.
        self.ledger.settle(attempt, 'COMPLETED', usage=usage, requested_model=requested_model,
                           returned_model=returned_model, response_sha256=hashlib.sha256(body).hexdigest(),
                           model_identity_status='EXACT' if returned_model == requested_model else 'UNVERIFIED',
                           continuation_hold=returned_model != requested_model)
        if returned_model != requested_model:
            self.release(context_ref, 'UNVERIFIED_API_MODEL_IDENTITY')
            raise WorkflowError('API completed with unverified model identity; result withheld and continuation held')
        return content, context_ref, metadata



class _KnownIncomplete(Exception):
    pass
