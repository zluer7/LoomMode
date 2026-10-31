"""Opt-in Host assembly and real Codex Decision interpretation of model preferences."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from uuid import uuid4
from pathlib import Path
from threading import Lock

from loommode.codex.context import ContextPurpose
from loommode.roles.runtime import Invocation
from loommode.roles.api_review import (ApiReviewDriver, ApiReviewGrant, API_INDEPENDENT_OPINION,
                                      ApiDecisionActivity)
from loommode.roles.contracts import obj, text, validate
from loommode.roles.model_routing import ModelCatalog, ModelRouter, digest
from loommode.tools.runtime import ToolPolicy, ToolProfile
from loommode.workflow.errors import WorkflowError, OutputProblem


@dataclass(frozen=True)
class HostModelRouting:
    """Explicit trusted assembly inputs; declarations never create authorization.

    The ordinary DecisionHost binds these before any role context starts. Loader
    and optional test transport remain Host callables, never model inputs.
    """
    config: Path | dict
    grant: object
    credential_loader: object = field(repr=False)
    ledger_path: Path
    decision_selector: object = field(default=None, repr=False)
    decision_selector_profile: str | None = None
    transport: object = field(default=None, repr=False)

    def bind(self, roles, executor):
        options = {'transport': self.transport} if self.transport is not None else {}
        return bind_model_routing(roles, executor, self.config, self.grant,
            self.credential_loader, self.ledger_path, self.decision_selector,
            decision_selector_profile=self.decision_selector_profile, **options)


class CodexDecisionSelector:
    """An actual no-tools AI call; no regex or engine semantic arbitration.

    Existing Adapter catalog, account permission, model checks and deadline apply.
    Each choice/synthesis is isolated; no developer transcript is resumed.
    """
    selection_origin = 'DECISION_AI'
    def __init__(self, adapter, workspace, stage_id, profiles, *, receipt_observer=None):
        self.adapter, self.workspace, self.stage_id, self.profiles = adapter, workspace, stage_id, profiles
        self.lock = Lock()
        self.calls = 0
        self.receipt_observer, self.last_receipt = receipt_observer, None

    def _call(self, prompt, schema, *, purpose=ContextPurpose.READ_ONLY_ROLE, role='Decision', invocation=False):
        from loommode.codex.errors import LoomModeError
        if not self.lock.acquire(blocking=False):
            raise WorkflowError('Decision model selection already in flight')
        started = time.monotonic()
        context, value, failed = None, None, False
        receipt = {'attempt_id': str(uuid4()), 'context_ref': None, 'turn_id': None,
                   'requested_model': None, 'requested_effort': None,
                   'effective_model': None, 'effective_effort': None,
                   'terminal_status': 'NOT_STARTED', 'turn_dispatch_attempted': False,
                   'success': False, 'error_category': None, 'cleanup_status': 'NOT_ALLOCATED',
                   'cleanup_category': None}
        try:
            try:
                model, effort = self.profiles.resolve_explanation()
                receipt.update(requested_model=model, requested_effort=effort)
                policy = ToolPolicy(self.workspace, ToolProfile.READ_ONLY_REVIEW, ())
                context = self.adapter.start_context(workspace=self.workspace, model=model,
                    reasoning_effort=effort, purpose=purpose, tool_policy=policy,
                    no_tools=True, activity_metadata={'stage': self.stage_id, 'role': role,
                                                      'purpose': 'MODEL_SELECTION'})
                record = self.adapter.registry.get(context.thread_id)
                receipt.update(context_ref=context.thread_id, effective_model=record.model,
                               effective_effort=record.reasoning_effort, cleanup_status='PENDING')
                def parse(raw):
                    try:
                        result = json.loads(raw)
                        validate(result, schema)
                        return result
                    except (ValueError, TypeError):
                        raise WorkflowError('Decision selection output invalid') from None
                self.calls += 1
                receipt['turn_dispatch_attempted'] = True
                turn = self.adapter.run_turn(thread_id=context.thread_id, prompt=prompt, model=model,
                    reasoning_effort=effort, tool_profile=ToolProfile.READ_ONLY_REVIEW,
                    output_schema=schema, result_validator=parse, deadline_seconds=60)
                receipt.update(turn_id=turn.turn_id, terminal_status=turn.terminal_status,
                    elapsed_ms=turn.elapsed_ms, success=bool(turn.success),
                    error_category=turn.error.category.value if turn.error else None)
                if not turn.success or not isinstance(turn.structured_result, dict):
                    failed = True
                elif invocation:
                    value = Invocation(turn.structured_result, context.thread_id, metadata={
                        'origin': 'HOST_CODEX_NO_TOOLS_OPINION', 'model': model,
                        'reasoning_effort': effort, 'turn_id': turn.turn_id})
                else:
                    value = turn.structured_result
            except Exception as exc:
                failed = True
                receipt['error_category'] = exc.record.category.value if isinstance(exc, LoomModeError) else 'WORKFLOW_ERROR'
                if context is None:
                    observed = getattr(self.adapter, 'last_no_tools_start_observation', None)
                    if isinstance(observed, dict):
                        for key in ('context_ref', 'effective_model', 'effective_effort', 'cleanup_status'):
                            if key in observed:
                                receipt[key] = observed[key]
            finally:
                if context is not None:
                    try:
                        released = self.adapter.release_context(context.thread_id, reason='MODEL_SELECTION_COMPLETE')
                        receipt['cleanup_status'] = ('RELEASED' if isinstance(released, dict) and
                                                     released.get('released') is True else 'UNVERIFIED')
                    except Exception as cleanup:
                        receipt['cleanup_status'] = 'UNVERIFIED'
                        receipt['cleanup_category'] = (cleanup.record.category.value
                            if isinstance(cleanup, LoomModeError) else 'WORKFLOW_ERROR')
                receipt.setdefault('elapsed_ms', max(0, int((time.monotonic() - started) * 1000)))
                self.last_receipt = dict(receipt)
                if self.receipt_observer is not None:
                    try:
                        self.receipt_observer(dict(receipt))
                    except Exception:
                        receipt['publication_status'] = 'FAILED'
                        self.last_receipt = dict(receipt)
                        failed = True
            if failed or receipt['cleanup_status'] != 'RELEASED':
                problem = WorkflowError('Decision model invocation failed or cleanup/publication unverified; no automatic replay')
                problem.safe_receipt = dict(receipt)
                raise problem from None
            return value
        finally:
            self.lock.release()

    def __call__(self, request):
        schema = obj({'profile_id': text(), 'reason': text(), 'applies_to_activity': {'type': 'boolean'}})
        return self._call(
            'You are LoomMode Decision. Interpret the Owner global natural-language preferences '
            'and actual task nature. Select one configured profile_id for this activity and explain '
            'the choice. Provider ordinal is the catalog ordinal, separate from priority, role and '
            'permission. Respect explicit requests for an unavailable third AI: return its intended '
            'unconfigured id (e.g. unavailable-third-ai) with the reason, never silently substitute. '
            'If an explicitly requested configured profile lacks this capability, name that profile '
            'and explain the mismatch; the Host will reject it. Do not invent credentials, capability '
            'or authorization. Set applies_to_activity true only when the preference actually addresses '
            'this scenario. Otherwise set it false and return the first Codex default profile: this '
            'means retain the existing Host route, including an independently configured managed '
            'implementation backend. Do not reinterpret a discussion-only preference as a programming '
            'backend switch. No tools. '
            'Return exactly JSON matching schema.\nREQUEST: ' + json.dumps(request, ensure_ascii=False)
            + '\nSCHEMA: ' + json.dumps(schema), schema)

    def synthesize(self, question, opinions):
        schema = obj({'judgment': text(), 'reason': text()})
        return self._call('You are LoomMode Decision. Synthesize these independently produced, attributed '
            'opinions using their direct evidence. Their providers/rank grant no authority; distinguish '
            'disagreements and limitations. This advisory judgment changes no Engine node/permissions '
            'or formal Task acceptance. No tools. Return one JSON object.\nQUESTION: '
            + question + '\nORIGINAL OPINIONS: ' + json.dumps(opinions, ensure_ascii=False)
            + '\nSCHEMA: ' + json.dumps(schema), schema)

    def opinion(self, profile, packet):
        from loommode.roles.contracts import parse_result
        from loommode.workflow.transitions import Node, TABLE, FRESH_NODES
        node = Node(packet['activity'])
        model, effort = self.profiles.resolve_explanation()
        if profile.model != model or profile.reasoning_effort not in {effort, 'activity_default'}:
            raise WorkflowError('Codex opinion profile differs from verified no-tools driver')
        reply = self._call('Provide an independent LoomMode read-only opinion. No history or tools. '
            'Read the objective approved packet and return its result_schema JSON. No fake test claims.\n'
            + json.dumps(packet, ensure_ascii=False), packet['result_schema'],
            purpose=ContextPurpose.FRESH_REVIEW if node in FRESH_NODES else ContextPurpose.READ_ONLY_ROLE,
            role=TABLE[node][0].value, invocation=True)
        result = parse_result(json.dumps(reply.result), node, packet['state'])
        return Invocation(result, reply.context_ref, metadata={**reply.metadata,
            'selection': {'profile_id': profile.profile_id, 'provider': profile.provider},
            'packet_sha256': digest(packet)})


class DeepSeekDecisionSelector:
    """Explicit Host opt-in to two fixed, separately authorized JSON activities."""
    selection_origin = 'DECISION_AI'

    def __init__(self, driver, profile, workspace, *, synthesis_scope=None):
        if (profile.verification != 'VERIFIED' or profile.provider != 'deepseek'
                or profile.transport != 'deepseek_chat'):
            raise WorkflowError('API Decision backend requires a verified explicitly selected DeepSeek profile')
        self.driver, self.profile, self.workspace = driver, profile, Path(workspace)
        self.synthesis_scope = synthesis_scope
        self.last_invocation = None

    def _call(self, activity, request):
        self.last_invocation = None
        reply = self.driver.decision_metadata(activity=activity, request=request,
                                             profile=self.profile, workspace=self.workspace)
        self.last_invocation = {'context_ref': reply.context_ref, **reply.metadata}
        return reply.result

    def __call__(self, request):
        return self._call(ApiDecisionActivity.MODEL_SELECTION, request)

    def synthesize(self, question, opinions, *, scope=None):
        scope = scope if scope is not None else (self.synthesis_scope() if callable(self.synthesis_scope) else self.synthesis_scope)
        if not isinstance(scope, dict) or set(scope) != {'project', 'stage_id', 'task_id'}:
            raise WorkflowError('fixed advisory synthesis requires an explicit current Host scope')
        return self._call(ApiDecisionActivity.ADVISORY_SYNTHESIS,
                          {**scope, 'question': question, 'opinions': opinions})

    def opinion(self, profile, packet):
        raise WorkflowError('native Codex no-tools opinions remain UNVERIFIED; API metadata selection does not qualify them')


class _Drivers:
    """Explicit per-profile grants for the same implemented transport, not a gateway."""
    def __init__(self, drivers):
        self.drivers = drivers

    def invoke(self, *, selection, **kwargs):
        driver = self.drivers.get(selection.profile.profile_id)
        if driver is None:
            raise WorkflowError('selected API profile has no current Host Grant/credential binding')
        return driver.invoke(selection=selection, **kwargs)

    def record_selection(self, evidence):
        # Includes rejected/unavailable choices even if no API driver matches.
        next(iter(self.drivers.values())).record_selection(evidence)

    def owns(self, ref):
        return bool(ref) and next(iter(self.drivers.values())).owns(ref)

    def release(self, ref, reason):
        return next(iter(self.drivers.values())).release(ref, reason)

    def ensure_dispatch_ready(self, profile_id):
        driver = self.drivers.get(profile_id)
        if driver is None:
            raise WorkflowError('selected API profile has no current Host Grant/credential binding')
        driver.ensure_dispatch_ready(profile_id)


def bind_model_routing(roles, executor, config, grant, credential_loader, ledger_path: Path,
                       decision_selector=None, *, transport=None, decision_selector_profile=None):
    """Bind only to an idle explicitly owned Host; configuration never loads a key.

    `grant` may be one ApiReviewGrant, or a profile-id -> distinct grant map.
    The caller retains its existing workspace lease and single writer obligation.
    """
    if (roles.adapter is not executor.adapter or roles.adapter.registry is not executor.adapter.registry
            or roles.policy.workspace.resolve() != executor.stage_policy.workspace.resolve()
            or roles.contexts or roles.explanation_context or executor.main_context or executor.latest_review
            or roles.model_router is not None or executor.model_router is not None):
        raise WorkflowError('model routing requires one idle shared Host/Registry/workspace')
    if decision_selector is not None and decision_selector_profile is not None:
        raise WorkflowError('choose one explicit Decision selector binding')
    catalog = ModelCatalog.load(config)
    grants = ({pid: grant for pid in grant.profile_ids} if isinstance(grant, ApiReviewGrant) else grant)
    if not isinstance(grants, dict) or not grants:
        raise WorkflowError('explicit current API review Grant binding required')
    if len(grants) > 1 and len({v.grant_id for v in grants.values()}) != len(grants):
        raise WorkflowError('separate API profiles require distinct explicit grants and ledgers')
    drivers = {}
    for pid, current in grants.items():
        if pid not in catalog.by_id or not isinstance(current, ApiReviewGrant) or pid not in current.profile_ids:
            raise WorkflowError('API profile/Grant binding mismatch')
        # File names are a Host choice, never an untrusted profile path.
        suffix = '.profile-' + str(list(grants).index(pid)) if len(grants) > 1 else ''
        path = Path(str(ledger_path) + suffix)
        options = {'transport': transport} if transport is not None else {}
        drivers[pid] = ApiReviewDriver(roles.adapter.registry, current, credential_loader, path, **options)
    driver_set = _Drivers(drivers)
    if decision_selector_profile is not None:
        if decision_selector_profile not in drivers:
            raise WorkflowError('explicit API Decision selector profile lacks its current Host driver/Grant')
        selector = DeepSeekDecisionSelector(drivers[decision_selector_profile], catalog.by_id[decision_selector_profile],
                                          roles.policy.workspace)
    else:
        selector = decision_selector or CodexDecisionSelector(roles.adapter, roles.policy.workspace, roles.stage_id, roles.profiles,
            receipt_observer=lambda receipt: driver_set.record_selection({'origin': 'HOST_DECISION_MODEL_ATTEMPT', 'receipt': receipt}))
    router = ModelRouter(catalog, selector, driver_set)
    roles.model_router = executor.model_router = router
    return router


def consult_models(router, *, profile_ids, question, node, state, materials, policy):
    """Host/Decision explicitly requests bounded sequential opinions and synthesis.

    Fresh review inputs must already be the Engine's objective materials. This API
    returns advisory content, not an Engine action or a formal acceptance grant.
    """
    from types import SimpleNamespace
    from loommode.roles.model_routing import ModelSelection
    if (not isinstance(profile_ids, (list, tuple)) or not 2 <= len(profile_ids) <= 4
            or len(set(profile_ids)) != len(profile_ids) or not isinstance(question, str)
            or not question.strip() or len(question) > 4000):
        raise WorkflowError('bounded distinct opinion profiles and explicit question required')
    profiles = [router.catalog.eligible(pid, node) for pid in profile_ids]
    if len({p.model for p in profiles}) < 2:
        raise WorkflowError('multi-model consultation requires distinct model identities')
    if isinstance(router.selector, DeepSeekDecisionSelector) and any(p.transport == 'codex_app_server' for p in profiles):
        raise WorkflowError('native Codex no-tools opinions remain UNVERIFIED with the explicit API metadata selector')
    source = next(iter(router.driver.drivers.values()))
    g = source.grant
    source.grant.check(SimpleNamespace(profile_id=g.profile_ids[0], provider=g.provider,
        transport=g.transport, model=g.model, reasoning_effort=g.reasoning_effort),
        node, state, materials, policy, source.clock())
    packet = source.packet(node=node, state=state, materials=materials, policy=policy,
                           role_prompts=(API_INDEPENDENT_OPINION,), purpose='INDEPENDENT_OPINION', question=question)
    replies = []
    try:
        for profile in profiles:
            evidence = {'origin': 'DECISION_EXPLICIT_OPINIONS', 'profile_id': profile.profile_id,
                        'reason': question, 'activity': node.value,
                        'catalog_sha256': router.catalog.fingerprint}
            router.driver.record_selection(evidence)
            if profile.transport == 'codex_app_server':
                reply = router.selector.opinion(profile, packet)
            else:
                try:
                    reply = router.invoke(ModelSelection(profile, evidence), node=node, state=state,
                        materials=materials, policy=policy,
                        purpose='INDEPENDENT_OPINION', question=question,
                        role_prompts=(API_INDEPENDENT_OPINION,))
                except OutputProblem as exc:
                    router.driver.release(exc.context_ref, 'INVALID_INDEPENDENT_OPINION_TRANSFERRED')
                    raise
            replies.append(reply)
            # Preserve each paid/independent result before another model can fail.
            router.driver.record_selection({'origin': 'INDEPENDENT_OPINION_RESULT',
                'question': question, 'activity': node.value, 'profile_id': profile.profile_id,
                'context_ref': reply.context_ref, 'result': reply.result, 'invocation': reply.metadata})
        originals = [{'profile_id': r.metadata['selection']['profile_id'], 'context_ref': r.context_ref,
                      'result': r.result, 'invocation': r.metadata} for r in replies]
        synthesize = getattr(router.selector, 'synthesize', None)
        if synthesize is None:
            raise WorkflowError('an authorized Decision synthesis callable is required')
        result = (synthesize(question, originals, scope={key: state.get(key) for key in ('project', 'stage_id', 'task_id')})
                  if isinstance(router.selector, DeepSeekDecisionSelector) else synthesize(question, originals))
        validate(result, obj({'judgment': text(), 'reason': text()}))
        router.driver.record_selection({'origin': 'DECISION_OPINION_SYNTHESIS',
            'original_opinions': originals, 'synthesis': result})
        return {'opinions': originals, 'decision': result, 'advisory_only': True}
    finally:
        for reply in replies:
            if router.driver.owns(reply.context_ref):
                router.driver.release(reply.context_ref, 'INDEPENDENT_OPINION_TRANSFERRED')
