"""One formal Adapter, four read-only role contexts, explicit activity profiles."""
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any
from loommode.codex.adapter import ThinCodexAdapter
from loommode.codex.context import ContextPurpose, FreshnessState
from loommode.tools.runtime import ToolPolicy, ToolProfile
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node, Role, TABLE
from .contracts import parse_result, result_schema, validate, OVERRIDE_SCHEMA
from .prompts import build_prompt
from loommode.tools.filesystem import BoundedFileSystem
from .explanation import (OWNER_STATUS_EXPLANATION, explanation_prompt, explanation_schema,
                          parse_explanation, validate_explanation)
from loommode.workflow.errors import OutputProblem
from .api_review import ApiRolePrompt, API_ROLE_CORRECTION


def run_handoff(adapter, *, node, state, receipt_observer=None, **kwargs):
    """Keep the complete reply; only a known completed format failure is correctable."""
    captured = []
    def read(raw):
        captured.append(raw)
        return parse_result(raw, node, state)
    turn = adapter.run_turn(**kwargs, result_validator=read)
    from loommode.workflow.failure_evidence import safe_observation
    metadata = turn.as_dict()
    observation=safe_observation(getattr(adapter,'last_safe_observation',None))
    if receipt_observer:
        receipt_observer(metadata)
    if (not turn.success and captured and turn.error
            and turn.error.category.value == 'STRUCTURED_OUTPUT_ERROR'
            and turn.terminal_status == 'completed'):
        exc=OutputProblem('role result schema rejected', captured[-1], kwargs['thread_id'], metadata)
        exc.safe_observation=observation
        raise exc
    if not turn.success or not isinstance(turn.structured_result, dict):
        exc=WorkflowError('role Adapter invocation failed')
        exc.safe_observation=observation
        raise exc
    return Invocation(turn.structured_result, kwargs['thread_id'], metadata={
        'model': kwargs['model'], 'reasoning_effort': kwargs['reasoning_effort'],
        'turn_id': turn.turn_id, 'elapsed_ms': turn.elapsed_ms, 'safe_observation':observation,
        'raw_output': captured[-1] if captured else None})


@dataclass(frozen=True)
class Invocation:
    result: dict[str, Any]
    context_ref: str
    commit_receipt: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    no_commit_evidence: dict[str, Any] | None = None
    host_output_ref: str | None = None  # Set by Engine after durable Host publication, never model input.


class ModelProfiles:
    def __init__(self, defaults: dict[str, tuple[str, str]], verified_combinations: set[tuple[str, str]]) -> None:
        self.defaults = dict(defaults)
        self.verified = frozenset(verified_combinations)

    def resolve(self, activity: Node, override: dict[str, Any] | None = None) -> tuple[str, str]:
        base = self.defaults.get(activity.value)
        if base is None or base not in self.verified:
            raise WorkflowError("missing or unverified activity default")
        if override:
            validate(override, OVERRIDE_SCHEMA)
            if override["activity"] != activity.value:
                raise WorkflowError("override applies only to its explicit invocation")
            base = (override["model"] or base[0], override["reasoning_effort"] or base[1])
        if base not in self.verified:
            raise WorkflowError("model/reasoning combination is not verified")
        return base

    def resolve_explanation(self) -> tuple[str, str]:
        base = self.defaults.get(OWNER_STATUS_EXPLANATION)
        if base is None or base not in self.verified:
            raise WorkflowError("missing or unverified explanation default")
        return base


def current_verified_profiles() -> ModelProfiles:
    """Explicit deployment baseline: A1-A0/A1-A1 verified low and medium only."""
    higher = {Node.STAGE_REVIEW, Node.STAGE_PLANNING, Node.STAGE_ACCEPTANCE, Node.DECISION_REVIEW,
              Node.DECISION_RE_REVIEW, Node.STAGE_MACHINE_CLOSE, Node.STAGE_CLOSE_SYNC,
              Node.ROLE_MEMORY_CONSOLIDATION, Node.OWNER_SUMMARY, Node.STAGE_PLAN_DECISION, Node.DECISION_MEDIATION,
              Node.STAGE_ISSUE_TRIAGE, Node.STAGE_KNOWLEDGE}
    defaults = {n.value: ("gpt-6.1-sol", "medium" if n in higher else "low") for n in Node}
    defaults[OWNER_STATUS_EXPLANATION] = ("gpt-6.1-sol", "low")
    return ModelProfiles(defaults,
                         {("gpt-6.1-sol", "low"), ("gpt-6.1-sol", "medium")})


class RoleRuntime:
    def __init__(self, adapter: ThinCodexAdapter, role_files: dict[Role, Path],
                 tool_policy: ToolPolicy, profiles: ModelProfiles, stage_id: str, *, model_router=None) -> None:
        if tool_policy.profile != ToolProfile.READ_ONLY_REVIEW or tool_policy.writable_paths or tool_policy.stageable_paths or tool_policy.commit_messages:
            raise WorkflowError("intelligent roles must have no write or commit grants")
        if set(role_files) != {Role.PROMOTER, Role.CONSTRAINT, Role.DISCUSSANT, Role.DECISION}:
            raise WorkflowError("four explicit role files are required")
        self.adapter, self.role_files, self.policy, self.profiles = adapter, role_files, tool_policy, profiles
        self.stage_id = stage_id
        self.contexts: dict[Role, str] = {}
        self.last_metadata: dict[str, Any] | None = None
        self._invocation_lock = Lock()
        self.explanation_context: str | None = None
        self.explanation_policy = ToolPolicy(tool_policy.workspace, ToolProfile.READ_ONLY_REVIEW, ())
        self.model_router = model_router
        self.api_report_selections = {}

    @contextmanager
    def _exclusive(self):
        if not self._invocation_lock.acquire(blocking=False):
            raise WorkflowError("a role invocation is already in flight")
        try:
            yield
        finally:
            self._invocation_lock.release()

    def _role_text(self, role: Role) -> str:
        role_text = self.role_files[role].read_text(encoding="utf-8")
        if "## Part I — Fixed Role Definition" not in role_text or "## Part II — Long-term Role Experience" not in role_text:
            raise WorkflowError("role definition/experience boundary missing")
        return role_text

    def _api_role_prompt(self, role: Role):
        prompt = ApiRolePrompt.from_file(self.role_files[role])
        if ('## Part I — Fixed Role Definition' not in prompt.text
                or '## Part II — Long-term Role Experience' not in prompt.text):
            raise WorkflowError('role definition/experience boundary missing')
        return prompt

    def renew_contexts(self) -> dict[str, Any]:
        """Lazy rebuilding uses the next current-State/materials prompt, never a transcript."""
        with self._exclusive():
            release = getattr(self.adapter, "release_context", None)
            if release is None:
                raise WorkflowError("Adapter does not support verified Context renewal")
            receipts = []
            for role, thread_id in tuple(self.contexts.items()):
                if self.model_router and self.model_router.driver.owns(thread_id):
                    receipts.append(self.model_router.driver.release(thread_id, 'QUIESCENT_ROLE_RENEWAL'))
                else:
                    receipts.append(release(thread_id, reason="QUIESCENT_ROLE_RENEWAL"))
                del self.contexts[role]
            if self.explanation_context:
                receipts.append(release(self.explanation_context, reason="QUIESCENT_DECISION_EXPLANATION_RENEWAL"))
                self.explanation_context = None
            return {"released": len(receipts), "receipts": receipts,
                    "rehydration": "CURRENT_AUTHORITY_STATE_TASK_SERIES_AND_REFERENCES"}

    def _context(self, role: Role, model: str, effort: str) -> str:
        if role not in self.contexts:
            context = self.adapter.start_context(workspace=self.policy.workspace, model=model, reasoning_effort=effort,
                                                 purpose=ContextPurpose.READ_ONLY_ROLE, tool_policy=self.policy,
                                                 activity_metadata={"stage": self.stage_id, "role": role.value})
            self.contexts[role] = context.thread_id
        else:
            record = self.adapter.registry.get(self.contexts[role])
            metadata = record.activity_metadata or {}
            if (record.purpose != ContextPurpose.READ_ONLY_ROLE or record.freshness != FreshnessState.READ_ONLY_ROLE
                    or record.tool_profile != ToolProfile.READ_ONLY_REVIEW.value
                    or Path(record.workspace).resolve() != self.policy.workspace.resolve()
                    or metadata.get("stage") != self.stage_id or metadata.get("role") != role.value):
                raise WorkflowError("cached role Context identity/purpose/profile mismatch")
            self.adapter.resume_context(thread_id=self.contexts[role], workspace=self.policy.workspace,
                                        tool_profile=ToolProfile.READ_ONLY_REVIEW)
        return self.contexts[role]

    def _explanation_context(self, model: str, effort: str) -> str:
        # The business role policy may allow fixed tests. Presentation gets no file/test/mutation grants.
        if self.explanation_context is None:
            context = self.adapter.start_context(workspace=self.policy.workspace, model=model, reasoning_effort=effort,
                purpose=ContextPurpose.READ_ONLY_ROLE, tool_policy=self.explanation_policy,
                activity_metadata={"stage": self.stage_id, "role": Role.DECISION.value,
                                   "purpose": OWNER_STATUS_EXPLANATION})
            self.explanation_context = context.thread_id
        else:
            record = self.adapter.registry.get(self.explanation_context)
            metadata = record.activity_metadata or {}
            if (record.purpose != ContextPurpose.READ_ONLY_ROLE or record.freshness != FreshnessState.READ_ONLY_ROLE
                    or record.tool_profile != ToolProfile.READ_ONLY_REVIEW.value
                    or Path(record.workspace).resolve() != self.policy.workspace.resolve()
                    or not isinstance(metadata, dict) or metadata.get("stage") != self.stage_id
                    or metadata.get("role") != Role.DECISION.value or metadata.get("purpose") != OWNER_STATUS_EXPLANATION):
                raise WorkflowError("cached explanation Context identity/purpose/profile mismatch")
            self.adapter.resume_context(thread_id=self.explanation_context, workspace=self.policy.workspace,
                                        tool_profile=ToolProfile.READ_ONLY_REVIEW)
        return self.explanation_context

    def invoke(self, role: Role, node: Node, state: dict[str, Any], materials: dict[str, str],
               override: dict[str, Any] | None = None) -> Invocation:
        with self._exclusive():
            return self._invoke(role, node, state, materials, override)

    def preflight(self, role: Role, node: Node, state: dict[str, Any], materials: dict[str, str],
                  override: dict[str, Any] | None = None):
        if state['stage_id'] != self.stage_id or role == Role.EXECUTOR:
            raise WorkflowError('role context scope mismatch')
        if node != Node.ROLE_MEMORY_CONSOLIDATION and (node not in TABLE or TABLE[node][0] != role):
            raise WorkflowError('role is not authorized for this activity')
        for field in ('formal_task_intent_ref', 'formal_constraint_ref'):
            ref = state.get(field)
            if ref and (ref not in materials or not isinstance(materials[ref], str) or not materials[ref].strip()):
                raise WorkflowError('known mandatory formal role input is missing')
        text = self._role_text(role)
        model, effort = self.profiles.resolve(node, override)
        self.policy.preflight()
        check = getattr(self.adapter, 'preflight_context', None)
        if check:
            check(workspace=self.policy.workspace, model=model, reasoning_effort=effort,
                  purpose=ContextPurpose.READ_ONLY_ROLE, tool_policy=self.policy, thread_id=self.contexts.get(role))
        return text, model, effort

    def _invoke(self, role: Role, node: Node, state: dict[str, Any], materials: dict[str, str],
                override: dict[str, Any] | None = None) -> Invocation:
        if state["stage_id"] != self.stage_id or role == Role.EXECUTOR:
            raise WorkflowError("role context scope mismatch")
        if node != Node.ROLE_MEMORY_CONSOLIDATION and (node not in TABLE or TABLE[node][0] != role):
            raise WorkflowError("role is not authorized for this activity")
        selection = self.model_router.select(node, state, materials) if self.model_router else None
        if selection and selection.profile.transport != 'codex_app_server':
            if (getattr(self, 'caller_verification', None) is not None
                    or getattr(self, 'caller_relay_verification', None) is not None):
                raise WorkflowError('caller verification requires its bound Codex role Context')
            if override:
                raise WorkflowError('API selection cannot consume a Codex model override')
            for field in ('formal_task_intent_ref', 'formal_constraint_ref'):
                ref = state.get(field)
                if ref and (ref not in materials or not isinstance(materials[ref], str) or not materials[ref].strip()):
                    raise WorkflowError('known mandatory formal role input is missing')
            self.api_report_selections[(state.get('task_id'), node)] = selection
            previous = self.contexts.pop(role, None)
            if previous and self.model_router.driver.owns(previous):
                self.model_router.driver.release(previous, 'STATELESS_ROLE_CONTEXT_REPLACED')
            elif previous:
                self.adapter.release_context(previous, reason='EXPLICIT_PROVIDER_SELECTION_REPLACED_ROLE')
            try:
                reply = self.model_router.invoke(selection, node=node, state=state, materials=materials,
                    role_prompts=(self._api_role_prompt(role),), policy=self.policy)
            except OutputProblem as exc:
                self.contexts[role] = exc.context_ref
                self.last_metadata = exc.metadata
                raise
            self.contexts[role] = reply.context_ref
            self.last_metadata = reply.metadata
            return reply
        if self.model_router and role in self.contexts and self.model_router.driver.owns(self.contexts[role]):
            self.model_router.driver.release(self.contexts.pop(role), 'EXPLICIT_CODEX_SELECTION_REPLACED_API_ROLE')
        if selection:
            override = self.model_router.codex_override(selection, node, override)
        self.api_report_selections.pop((state.get('task_id'), node), None)
        role_text, model, effort = self.preflight(role, node, state, materials, override)
        self._context(role, model, effort)
        verification = getattr(self, 'caller_verification', None)
        if verification is not None:
            materials = verification.bind_context(state, node.value, materials,
                self.caller_verification_authorities, self.contexts[role], self.adapter.registry)
        relay = getattr(self, 'caller_relay_verification', None)
        if relay is not None:
            materials = relay.bind_context(state, node.value, materials, self.contexts[role], self.adapter.registry)
        schema = result_schema(node, state)
        prompt = build_prompt(role_text=role_text, activity=node.value, state=state, materials=materials,
                              allowed_schema=schema, profile=(model, effort),
                              current_presence=BoundedFileSystem(self.policy.workspace, readable=self.policy.readable_paths, writable=()).list_allowed()["files"])
        reply = run_handoff(self.adapter, node=node, state=state, thread_id=self.contexts[role],
            prompt=prompt, model=model, reasoning_effort=effort,
            tool_profile=ToolProfile.READ_ONLY_REVIEW, output_schema=schema,
            receipt_observer=lambda receipt: setattr(self, 'last_metadata', receipt))
        return (Invocation(reply.result, reply.context_ref, metadata={**(reply.metadata or {}), 'selection': selection.evidence})
                if selection else reply)

    def correct_report(self, role, node, state, materials, override=None):
        with self._exclusive():
            selection = self.api_report_selections.get((state.get('task_id'), node))
            if selection:
                reply = self.model_router.invoke(selection, node=node, state=state, materials=materials,
                    role_prompts=(self._api_role_prompt(role), API_ROLE_CORRECTION),
                    policy=ToolPolicy(self.policy.workspace, ToolProfile.READ_ONLY_REVIEW, ()), correction=True)
                self.last_metadata = reply.metadata
                return reply
            text, model, effort = self.preflight(role, node, state, materials, override)
            policy = ToolPolicy(self.policy.workspace, ToolProfile.READ_ONLY_REVIEW, ())
            context = self.adapter.start_context(workspace=policy.workspace, model=model, reasoning_effort=effort,
                purpose=ContextPurpose.READ_ONLY_ROLE, tool_policy=policy,
                activity_metadata={'stage': self.stage_id, 'role': role.value, 'purpose': 'REPORT_CORRECTION'})
            try:
                verification = getattr(self, 'caller_verification', None)
                if verification is not None:
                    materials = verification.bind_context(state, node.value, materials,
                        self.caller_verification_authorities, context.thread_id, self.adapter.registry)
                relay = getattr(self, 'caller_relay_verification', None)
                if relay is not None:
                    materials = relay.bind_context(state, node.value, materials, context.thread_id, self.adapter.registry)
                prompt = build_prompt(role_text=text + '\nCorrect the report only; no tools or re-execution.',
                    activity=node.value, state=state, materials=materials, allowed_schema=result_schema(node, state),
                    profile=(model, effort))
                return run_handoff(self.adapter, node=node, state=state, thread_id=context.thread_id,
                    prompt=prompt, model=model, reasoning_effort=effort, tool_profile=ToolProfile.READ_ONLY_REVIEW,
                    output_schema=result_schema(node, state),
                    receipt_observer=lambda receipt: setattr(self, 'last_metadata', receipt))
            finally:
                self.adapter.release_context(context.thread_id, reason='REPORT_CORRECTION_COMPLETE')

    def explain_status(self, *, question: str, projection: dict[str, Any],
                       materials: dict[str, str]) -> Invocation:
        """Return presentation text only; the Host never feeds this result to Engine."""
        with self._exclusive():
            if projection.get("stage_id") != self.stage_id or projection.get("availability") != "AVAILABLE":
                raise WorkflowError("explanation requires a bound, validated Stage snapshot")
            if projection.get("workspace") != str(self.policy.workspace.resolve()):
                raise WorkflowError("explanation workspace mismatch")
            if projection["activity"]["in_flight"] or projection["activity"]["host_busy"]:
                raise WorkflowError("existing activity must finish before explanation")
            if not isinstance(question, str) or not question.strip():
                raise WorkflowError("explanation requires an explicit Owner question")
            model, effort = self.profiles.resolve_explanation()
            prompt = explanation_prompt(role_text=self._role_text(Role.DECISION), question=question,
                                        projection=projection, materials=materials, profile=(model, effort))
            context_ref = self._explanation_context(model, effort)
            turn = self.adapter.run_turn(thread_id=context_ref, prompt=prompt, model=model, reasoning_effort=effort,
                                         tool_profile=ToolProfile.READ_ONLY_REVIEW, output_schema=explanation_schema(),
                                         result_validator=lambda raw: parse_explanation(raw, set(materials)))
            self.last_metadata = turn.as_dict()
            if not turn.success or not isinstance(turn.structured_result, dict):
                raise WorkflowError(f"Decision explanation failed: {turn.error}")
            result = validate_explanation(turn.structured_result, set(materials))
            return Invocation(result, context_ref, metadata={"purpose": OWNER_STATUS_EXPLANATION,
                              "model": model, "reasoning_effort": effort, "turn_id": turn.turn_id,
                              "elapsed_ms": turn.elapsed_ms})
