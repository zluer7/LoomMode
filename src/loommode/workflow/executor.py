"""One Stage writer, fresh read-only review, and an explicit commit-only turn."""
from dataclasses import asdict, replace
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable
from loommode.codex.adapter import ThinCodexAdapter
from loommode.codex.context import ContextPurpose, ResourceState
from loommode.roles.contracts import empty_result, parse_result, result_schema, validate, INTENT_SCHEMA
from loommode.roles.prompts import build_prompt
from loommode.tools.filesystem import BoundedFileSystem
from loommode.roles.runtime import Invocation, ModelProfiles, run_handoff
from loommode.roles.api_review import API_FRESH_REVIEW, API_FRESH_CORRECTION
from loommode.tools.runtime import ToolPolicy, ToolProfile, ToolPhase
from .errors import WorkflowError, OutputProblem
from .transitions import FRESH_NODES, Node, Role, TABLE
from .implementation import (ImplementationConfig, ImplementationRequest, ManagedCodexBackend,
                             MANAGED_CODEX_CLI)


class ExecutorRuntime:
    def __init__(self, adapter: ThinCodexAdapter, stage_policy: ToolPolicy,
                 task_policies: dict[str, ToolPolicy], profiles: ModelProfiles, *,
                 task_policy_provider: Callable[[str], ToolPolicy] | None = None,
                 implementation_config: ImplementationConfig | None = None,
                 implementation_config_provider: Callable[[str], ImplementationConfig] | None = None,
                 managed_host_preflight: Any = None,
                 objective_review_materials: Callable | None = None, model_router=None) -> None:
        if stage_policy.profile != ToolProfile.BOUNDED_DEVELOPMENT:
            raise WorkflowError("Executor stage policy requires bounded development")
        self.objective_review_materials = objective_review_materials
        self.adapter, self.stage_policy, self.task_policies, self.profiles = adapter, stage_policy, task_policies, profiles
        self.main_context: str | None = None
        self.native_admission = None
        self.policy_provider = task_policy_provider
        self.latest_review: str | None = None
        self.review_has_report = False
        self.checkpoint_binding: dict[str, Any] | None = None
        self.implementation_binding: dict[str, Any] | None = None
        self.task_start_contexts: dict[str, str] = {}
        self._replaced_developers: set[str] = set()
        self.implementation_config = ImplementationConfig() if implementation_config is None else implementation_config
        if not isinstance(self.implementation_config, ImplementationConfig):
            raise WorkflowError("explicit typed implementation configuration required")
        self.implementation_config_provider = implementation_config_provider
        self.managed_backend = ManagedCodexBackend(managed_host_preflight)
        # Pinned only by actual invocation, never by repeatable preflight.
        self.task_requests: dict[str, ImplementationRequest] = {}
        self.task_profiles: dict[str, tuple[str, str]] = {}
        self.report_profiles = {}
        self._synthetic_cli_fixture = None
        self._managed_session = None
        self._managed_proofs = {}
        self.model_router = model_router
        self.api_report_selections = {}
        self._native_test_receipts = {}
        self._execution_evidence = {}
        self._capability_snapshots = {}

    def execution_capabilities(self, state):
        """Host configuration facts for planning, never a model permission grant."""
        task_id = state.get('task_id')
        policy = self._task_policy(task_id)
        policy.preflight(bound=self.stage_policy)
        request = self.task_requests.get(task_id)
        config = (request.config if request else self.implementation_config_provider(task_id)
                  if self.implementation_config_provider else self.implementation_config)
        if not isinstance(config, ImplementationConfig):
            raise WorkflowError('Host implementation provider returned malformed configuration')
        native = config.backend != MANAGED_CODEX_CLI and bool(
            getattr(self.adapter, 'native_workspace_development', False))
        value = {'origin': 'HOST_EXECUTOR_CAPABILITIES', 'project': state['project'],
            'stage_id': state['stage_id'], 'task_id': task_id,
            'source': 'CURRENT_HOST_CONFIGURATION_NOT_EXECUTION_OR_AUTHORIZATION',
            'backend': config.backend,
            'development_mode': ('native workspace-write' if native else
                                 'managed CLI' if config.backend == MANAGED_CODEX_CLI else 'legacy bounded Host tools'),
            'workspace': str(policy.workspace.resolve(strict=True)),
            'readable_paths': list(policy.readable_paths), 'writable_paths': list(policy.writable_paths),
            'fixed_tests': [{**asdict(spec), 'argv': list(spec.argv)} for spec in policy.test_specs],
            'stageable': list(policy.stageable_paths), 'commit_messages': list(policy.commit_messages),
            'allow_no_dev_change': policy.allow_no_dev_change,
            'normal_supply_authority_ref': policy.normal_supply_authority_ref,
            'native_shell_available_for_implementation': native,
            'new_file_inspection': ('Native shell may inspect authorized newly created files only if the frozen Final permits it. '
                'Host read-tool enum is fixed at context creation; refreshed listing does not update that enum.' if native else
                'Host read-tool enum contains files present at context creation; do not assume a missing target can be created/read by a tool.'),
            'limits': 'Capabilities do not override Intent, Final, Writer or ToolPolicy. Roles are read-only; their shell prohibition '
                'does not define Executor capability. Constraint/Discussant must resolve incompatible tool restrictions before Final; '
                'Executor must stop on a frozen Final conflict. Use original Host fixed tests; shell checks never replace them. '
                'No model Git/commit/push/release permission.'}
        previous = self._capability_snapshots.setdefault(task_id, copy.deepcopy(value))
        if previous != value:
            raise WorkflowError('Host Executor capabilities changed after Constraint input')
        return copy.deepcopy(value)

    def _capture_execution_evidence(self, state, context_ref, policy_json, prompt, receipt):
        request = self.task_requests[state['task_id']]
        value = {'origin': 'HOST_EXECUTOR_EXECUTION_EVIDENCE', 'binding': request.binding,
            'context_ref': context_ref, 'request_fingerprint': request.fingerprint,
            'policy_capture': 'EXACT_HOST_PREPARED_MATERIAL', 'policy_json': policy_json,
            'prompt_capture': 'EXACT_HOST_PREPARED_PROMPT', 'prompt': prompt,
            'prompt_sha256': hashlib.sha256(prompt.encode('utf-8')).hexdigest(),
            'adapter_receipt_capture': 'ORIGINAL_ADAPTER_RECEIPT_FIELD_PROJECTION',
            'adapter_receipt': {key: copy.deepcopy(receipt[key]) for key in
                ('success', 'thread_id', 'turn_id', 'terminal_status', 'tool_audit', 'event_methods', 'elapsed_ms')},
            'native_command_bodies': 'NOT_CAPTURED_BY_ADAPTER_RECEIPT; event_methods are names, not command text/results'}
        self._execution_evidence[state['task_id']] = copy.deepcopy(value)
        return value

    def verify_execution_evidence(self, state, context_ref, saved):
        task_id = state.get('task_id')
        cached = self._execution_evidence.get(task_id)
        request = self.task_requests.get(task_id)
        if (not cached or saved != cached or request is None or self.managed_task(task_id)
                or context_ref != self.main_context or context_ref != state.get('executor_context_ref')
                or cached['context_ref'] != context_ref or cached['request_fingerprint'] != request.fingerprint
                or any(request.binding.get(key) != state.get(field) for key, field in
                    (('project', 'project'), ('stage_id', 'stage_id'), ('task_id', 'task_id'),
                     ('intent_ref', 'formal_task_intent_ref'), ('final_ref', 'formal_constraint_ref')))):
            raise WorkflowError('execution evidence Task/ref/context or original evidence mismatch')
        return True

    def _capture_native_tests(self, task_id, context_ref):
        getter = getattr(self.adapter, 'task_proof', None)
        if self.managed_task(task_id) or not callable(getter):
            return None  # Older/test adapters have no trusted proof capability.
        request = self.task_requests.get(task_id)
        if request is None or context_ref != self.main_context:
            raise WorkflowError('native test receipt has no current implementation owner')
        from loommode.tools.task_proof import HostTaskProof
        proof = getter(context_ref)
        if (not isinstance(proof, HostTaskProof) or proof.context_ref != context_ref
                or proof.runtime.workspace.resolve() != request.policy.workspace.resolve()):
            raise WorkflowError('native test receipt proof/context/workspace mismatch')
        facts = proof.native_test_evidence(request.binding)
        self._native_test_receipts[task_id] = copy.deepcopy(facts)
        return facts

    def verify_native_test_evidence(self, state, context_ref, saved):
        task_id = state.get('task_id')
        cached = self._native_test_receipts.get(task_id)
        request = self.task_requests.get(task_id)
        if (not cached or saved != cached or request is None or self.managed_task(task_id)
                or context_ref != self.main_context or context_ref != state.get('executor_context_ref')
                or cached.get('context_ref') != context_ref
                or any(request.binding.get(key) != state.get(field) for key, field in
                       (('project', 'project'), ('stage_id', 'stage_id'), ('task_id', 'task_id'),
                        ('intent_ref', 'formal_task_intent_ref'), ('final_ref', 'formal_constraint_ref')))):
            raise WorkflowError('native test receipt Task/ref/context or original evidence mismatch')
        current = self.adapter.task_proof(context_ref).native_test_evidence(request.binding)
        if current != cached:
            raise WorkflowError('native test receipt changed after original implementation')
        return True

    def bind_managed_cli(self, working_root, reserve_dispatch, *, limits=None, native_host=None):
        """Bind one Host-owned lifecycle; native execution still needs real controls."""
        if self.task_requests or self.main_context or self._managed_session is not None:
            raise WorkflowError("unstarted managed CLI binding required")
        self._managed_session = self.managed_backend.bind_session(working_root, reserve_dispatch, limits=limits,
                                                                 native_host=native_host)

    def bind_synthetic_cli_for_test(self, fixture, working_root, reserve_dispatch, *, limits=None):
        """Explicit disposable Host fixture binding; never a config/model option."""
        from .managed_cli import SyntheticCliFixture
        if (not isinstance(fixture, SyntheticCliFixture) or self.task_requests
                or self.main_context or self._managed_session is not None):
            raise WorkflowError("unstarted typed synthetic CLI binding required")
        if not Path(working_root).resolve(strict=True).is_relative_to(fixture.root.resolve(strict=True)):
            raise WorkflowError("synthetic working files must remain within disposable fixture root")
        self.bind_managed_cli(working_root, reserve_dispatch, limits=limits)
        self._synthetic_cli_fixture = fixture

    def managed_task(self, task_id):
        request = self.task_requests.get(task_id)
        return bool(request and request.config.backend == MANAGED_CODEX_CLI)

    def cancel_active(self, *, cancel_adapter=True):
        if cancel_adapter:
            self.adapter.cancel_active()
        self.managed_backend.cancel()

    def managed_test_evidence(self, task_id):
        if not self.managed_task(task_id) or self._managed_session is None:
            return None
        entry = self._managed_session.tasks.get(task_id)
        if not entry:
            return None
        return entry[1].managed_test_evidence()

    def verify_managed_report(self, task_id, context_ref, saved):
        if not self.managed_task(task_id):
            return False
        if self._managed_session is None or task_id not in self._managed_session.tasks:
            raise WorkflowError('managed report lacks its owned Host session')
        session = self._managed_session
        request, proof = session.tasks[task_id]
        if (request != self.task_requests[task_id] or context_ref != proof.context_ref
                or self._managed_proofs.get(context_ref) is not proof or saved is None):
            raise WorkflowError('managed report Host ownership mismatch')
        proof.verify_managed_tests(request, session.generations[task_id],
                                   session.implementation_receipts.get(task_id), saved)
        return True

    def _register_managed_proof(self, task_id):
        if self._managed_session is None:
            return
        entry = self._managed_session.tasks.get(task_id)
        if entry is None:
            return
        request, proof = entry
        self._managed_proofs[proof.context_ref] = proof
        self.main_context = proof.context_ref
        self.implementation_binding = request.binding
        self.task_start_contexts.setdefault(task_id, proof.context_ref)
        self.checkpoint_binding = None
        registry = self.adapter.registry
        if not any(record.thread_id == proof.context_ref for record in registry.all()):
            registry.create(thread_id=proof.context_ref, purpose=ContextPurpose.DEVELOPMENT,
                workspace=request.policy.workspace, model=request.config.managed.model,
                reasoning_effort=request.config.managed.reasoning_effort,
                tool_profile=request.policy.profile.value, codex_version=request.config.managed.cli_version,
                owner_id=self.managed_backend.owner_id,
                activity_metadata={"stage": request.binding['stage_id'], "role": "Executor",
                    "backend": MANAGED_CODEX_CLI, "transport": "EXTERNAL_HOST_CONTEXT",
                    "production_eligible": "false"})
        receipt = self._managed_session.last_receipt or {}
        record = registry.get(proof.context_ref)
        record.activity_metadata['production_eligible'] = str(bool(receipt.get('production_eligible'))).lower()
        record.activity_metadata['external_session_ref'] = receipt.get('external_session_ref', '')
        registry.record_turn(proof.context_ref, receipt.get('attempt_id'), receipt.get('outcome', 'FAILED'))
        registry.resource(proof.context_ref, ResourceState.RETAINED, protection="CURRENT_TASK_BASELINE")

    def _protect(self, thread_id: str, reason: str | None) -> None:
        if self.model_router and self.model_router.driver.owns(thread_id):
            self.adapter.registry.resource(thread_id, ResourceState.RETAINED, protection=reason)
            return
        protect = getattr(self.adapter, "protect_context", None)
        if protect:
            protect(thread_id, reason)

    def _release(self, thread_id: str, reason: str) -> None:
        if self.model_router and self.model_router.driver.owns(thread_id):
            self.model_router.driver.release(thread_id, reason)
            return
        release = getattr(self.adapter, "release_context", None)
        if release:
            self._protect(thread_id, None)
            release(thread_id, reason=reason)

    def after_durable(self, node: Node, state: dict[str, Any]) -> None:
        """Invoked outside Engine rollback handling after formal State save."""
        if node in {Node.STAGE_REVIEW, Node.STAGE_ACCEPTANCE} and self.latest_review:
            self._release(self.latest_review, "PERSISTED_ONE_SHOT_REVIEW")
            self.latest_review, self.review_has_report = None, False
        if node != Node.TASK_COMPLETE:
            return
        task_id = state["task_id"]
        settle = getattr(self.adapter, "settle_task", None)
        for thread_id in {self.main_context, self.task_start_contexts.get(task_id)} - {None}:
            if thread_id in self._managed_proofs:
                self._managed_proofs[thread_id].runtime.settle_task()
                self.adapter.registry.resource(thread_id, ResourceState.RELEASED, receipt={
                    "proof": "DURABLE_TASK_CHECKPOINT_AND_OWNED_CLI_CLEANUP", "task_id": task_id,
                    "backend_owner_id": self.managed_backend.owner_id})
                del self._managed_proofs[thread_id]
                self._managed_session.tasks.pop(task_id)
                self.main_context = None
            elif settle:
                settle(thread_id)
        if self.latest_review:
            self._release(self.latest_review, "DURABLE_TASK_CHECKPOINT_SETTLED_REVIEW")
            self.latest_review, self.review_has_report = None, False
        for thread_id in tuple(self._replaced_developers):
            self._release(thread_id, "DURABLE_TASK_CHECKPOINT_REPLACED_DEVELOPER")
            self._replaced_developers.remove(thread_id)
        self.task_start_contexts.pop(task_id, None)
        self.task_policies.pop(task_id, None)
        self.checkpoint_binding = None
        self.implementation_binding = None
        self.task_requests.pop(task_id, None)
        self.task_profiles.pop(task_id, None)
        self._native_test_receipts.pop(task_id, None)
        self._execution_evidence.pop(task_id, None)
        self._capability_snapshots.pop(task_id, None)
        for key in tuple(self.api_report_selections):
            if key[0] == task_id:
                del self.api_report_selections[key]
        for key in tuple(self.report_profiles):
            if key[0] == task_id:
                del self.report_profiles[key]

    def renew_contexts(self) -> dict[str, Any]:
        # Current Task-start evidence must survive until checkpoint settlement.
        if self.task_start_contexts or self.latest_review or self._replaced_developers:
            return {"released": 0, "preserved": "TASK_BASELINE_OR_PENDING_FRESH_TRANSFER"}
        if self.main_context is None:
            return {"released": 0}
        self._release(self.main_context, "QUIESCENT_STAGE_DEVELOPER_RENEWAL")
        self.main_context = None
        return {"released": 1, "rehydration": "CURRENT_AUTHORITY_STATE_TASK_SERIES_AND_REFERENCES"}

    def renewal_protected(self) -> bool:
        return bool(self.task_start_contexts or self.latest_review or self._replaced_developers)

    def review_context_conversion_available(self, review_ref: str | None) -> bool:
        return bool(review_ref) and not (self.model_router and self.model_router.driver.owns(review_ref))

    def transfer_review_for_repair(self, task_id: str, review_ref: str) -> None:
        if self.model_router and self.model_router.driver.owns(review_ref):
            raise WorkflowError('stateless API review cannot become a native development context; use original developer and findings')
        request = self.task_requests.get(task_id)
        if request and request.config.backend == MANAGED_CODEX_CLI:
            raise WorkflowError("managed Repair consumes findings; Codex review context cannot become its developer")
        if not self.latest_review or review_ref != self.latest_review or not self.review_has_report:
            raise WorkflowError("explicit completed review context required for repair transfer")
        policy = self._task_policy(task_id)
        policy.preflight(bound=self.stage_policy)
        check = getattr(self.adapter, 'preflight_task_policy', None)
        if check:
            check(policy, self.implementation_binding)
        elif policy.normal_supply_authority_ref:
            raise WorkflowError('entry cannot verify authorized normal supply')
        old_main = self.main_context
        if old_main:
            self.adapter.suspend_mutations(old_main)
        self.adapter.authorize_development(self.latest_review)
        self.main_context = self.latest_review
        self.latest_review = None
        self.review_has_report = False
        self.adapter.configure_task(self.main_context, policy, task_binding=self.implementation_binding)
        if old_main:
            if old_main in self.task_start_contexts.values():
                self._replaced_developers.add(old_main)
            else:
                self._release(old_main, "EXPLICIT_REVIEW_TRANSFER_REPLACED_DEVELOPER")

    def _task_policy(self, task_id: str | None) -> ToolPolicy:
        if task_id in self.task_requests:
            return self.task_requests[task_id].policy
        if task_id and task_id not in self.task_policies and self.policy_provider:
            # Host-owned authorization lookup, never inferred from prose or model-selected paths.
            policy = self.policy_provider(task_id)
        elif task_id and task_id in self.task_policies:
            policy = self.task_policies[task_id]
        else:
            raise WorkflowError("no explicit current task tool policy")
        if not isinstance(policy, ToolPolicy) or any(not m.startswith(f"[{task_id}]") for m in policy.commit_messages):
            raise WorkflowError("task commit policy must name its exact Task ID")
        return policy

    def _implementation_request(self, state: dict[str, Any], materials: dict[str, str],
                                policy: ToolPolicy, binding: dict[str, Any]) -> ImplementationRequest:
        task_id = state['task_id']
        pinned = self.task_requests.get(task_id)
        config = (pinned.config if pinned else self.implementation_config_provider(task_id)
                  if self.implementation_config_provider else self.implementation_config)
        if not isinstance(config, ImplementationConfig):
            raise WorkflowError("Host implementation provider returned malformed configuration")
        request = ImplementationRequest.create(config, policy, binding,
                                              materials[binding['intent_ref']], materials[binding['final_ref']])
        if pinned and request != pinned:
            raise WorkflowError("current Task original Intent/Final/policy changed during Repair")
        return request

    def authorize_commit(self, state: dict[str, Any]) -> None:
        if state["current_node"] != Node.COMMIT_AUTHORIZATION.value or not self.main_context:
            raise WorkflowError("commit authorization outside accepted task node")
        target = self._managed_proofs.get(self.main_context)
        arguments = dict(acceptance_ref=state["acceptance_ref"],
                                      report_ref=state["latest_execution_report_ref"],
                                      checkpoint_binding=state.get("host_checkpoint_binding"))
        if target:
            target.authorize_commit(**arguments)
        else:
            self.adapter.authorize_commit(self.main_context, **arguments)
        self.checkpoint_binding = state.get("host_checkpoint_binding")

    def verify_no_dev_change(self, evidence: dict[str, Any], binding: dict[str, Any]) -> None:
        if (not self.main_context or binding["host_context_ref"] != self.main_context
                or self.task_start_contexts.get(binding["task_id"]) != self.main_context):
            raise WorkflowError("no-commit evidence is not bound to the current Executor Host context")
        proof = self._managed_proofs.get(self.main_context)
        if proof:
            proof.verify_no_dev_change(evidence, binding)
        else:
            self.adapter.verify_no_dev_change(self.main_context, evidence=evidence, binding=binding)

    def suspend(self) -> None:
        if self.main_context:
            proof = self._managed_proofs.get(self.main_context)
            if proof:
                proof.runtime.suspend_mutations()
            else:
                self.adapter.suspend_mutations(self.main_context)

    def preflight(self, node: Node, state: dict[str, Any], materials: dict[str, str],
                  override: dict[str, Any] | None = None):
        # Retain the original public four-value contract.
        return self._prepare(node, state, materials, override)[:4]

    def _prepare(self, node: Node, state: dict[str, Any], materials: dict[str, str],
                 override: dict[str, Any] | None = None):
        if node not in TABLE or TABLE[node][0] != Role.EXECUTOR:
            raise WorkflowError('Executor is not authorized for this activity')
        fresh = node in FRESH_NODES
        policy = replace(self.stage_policy, profile=ToolProfile.READ_ONLY_REVIEW,
                         normal_supply_authority_ref=None) if fresh else self._task_policy(state.get('task_id'))
        policy.preflight(bound=None if fresh else self.stage_policy, check_tests=node != Node.EXECUTOR_LOCAL_COMMIT)
        native_commit = getattr(self.adapter, 'native_workspace_development', False) and node == Node.EXECUTOR_LOCAL_COMMIT
        binding = None
        request = None
        if node == Node.EXECUTOR_IMPLEMENT:
            intent_ref, final_ref = state.get('formal_task_intent_ref'), state.get('formal_constraint_ref')
            if any(not ref or ref not in materials or not isinstance(materials[ref], str) or not materials[ref].strip()
                   for ref in (intent_ref, final_ref)):
                raise WorkflowError('explicit original Intent and final execution input required before dispatch')
            try:
                intent = json.loads(materials[intent_ref])
            except ValueError as exc:
                raise WorkflowError('original Intent must be valid structured input') from exc
            validate(intent, INTENT_SCHEMA)
            if intent['task_id'] != state['task_id'] or not set(policy.writable_paths).issubset(intent['scope']):
                raise WorkflowError('Task policy differs from actual original Intent scope')
            binding = {'project': state['project'], 'stage_id': state['stage_id'], 'task_id': state['task_id'],
                       'intent_ref': intent_ref, 'final_ref': final_ref, 'scope': intent['scope']}
            request = self._implementation_request(state, materials, policy, binding)
            if request.config.backend == MANAGED_CODEX_CLI:
                if self.native_admission is not None:
                    raise WorkflowError('native admission does not authorize managed implementation')
                if override:
                    raise WorkflowError("managed implementation does not consume Codex model overrides")
                if self._synthetic_cli_fixture is None:
                    self.managed_backend.preflight(request, materials)
                else:
                    self._managed_session.preflight(request, materials, fixture=self._synthetic_cli_fixture)
                return policy, None, None, binding, request, None
        if node == Node.EXECUTOR_LOCAL_COMMIT and self.main_context in self._managed_proofs:
            return policy, None, None, None, None, None
        base_profile = None
        if node == Node.EXECUTOR_IMPLEMENT:
            base_profile = self.task_profiles.get(state['task_id']) or self.profiles.resolve(node)
            # Pin defaults while preserving explicit overrides for one invocation.
            model, effort = ModelProfiles({node.value: base_profile}, self.profiles.verified).resolve(node, override)
        else:
            model, effort = (None, None) if native_commit else self.profiles.resolve(node, override)
        if node == Node.EXECUTOR_LOCAL_COMMIT and not self.main_context:
            raise WorkflowError('checkpoint requires actual current development context')
        check = getattr(self.adapter, 'preflight_context', None)
        if check:
            check(workspace=policy.workspace, model=model, reasoning_effort=effort,
                  purpose=ContextPurpose.FRESH_REVIEW if fresh else ContextPurpose.DEVELOPMENT,
                  tool_policy=policy, thread_id=None if fresh else self.main_context,
                  task_binding=binding if binding else self.checkpoint_binding,
                  required_phase=ToolPhase.COMMIT_AUTHORIZED if node == Node.EXECUTOR_LOCAL_COMMIT else None)
        elif policy.normal_supply_authority_ref:
            raise WorkflowError('entry cannot verify or support authorized normal supply')
        return policy, model, effort, binding, request, base_profile

    def invoke(self, node: Node, state: dict[str, Any], materials: dict[str, str],
               override: dict[str, Any] | None = None) -> Invocation:
        if node == Node.INDEPENDENT_REVIEW and self.objective_review_materials is not None:
            materials = self.objective_review_materials(self, state, materials)
        selection = (self.model_router.select(node, state, materials)
                     if self.model_router and node in FRESH_NODES | {Node.EXECUTOR_IMPLEMENT} else None)
        if selection and selection.profile.transport != 'codex_app_server':
            if node == Node.EXECUTOR_IMPLEMENT and self.native_admission is not None:
                raise WorkflowError('native admission does not authorize an API backend')
            if override:
                raise WorkflowError('API review cannot consume a Codex model override')
            self.suspend()
            if self.latest_review:
                self._release(self.latest_review, 'EXPLICIT_FRESH_REVIEW_SUPERSEDES_PRIOR_REVIEW')
                self.latest_review, self.review_has_report = None, False
            policy = ToolPolicy(self.stage_policy.workspace, ToolProfile.READ_ONLY_REVIEW, self.stage_policy.readable_paths)
            self.api_report_selections[(state.get('task_id'), node)] = selection
            try:
                reply = self.model_router.invoke(selection, node=node, state=state, materials=materials,
                    role_prompts=(API_FRESH_REVIEW,),
                    policy=policy)
            except OutputProblem as exc:
                self.latest_review = exc.context_ref
                self._protect(exc.context_ref, 'PENDING_REVIEW_TRANSFER')
                raise
            self.latest_review, self.review_has_report = reply.context_ref, True
            self._protect(reply.context_ref, 'PENDING_REVIEW_TRANSFER')
            return reply
        if selection:
            override = self.model_router.codex_override(selection, node, override)
        self.api_report_selections.pop((state.get('task_id'), node), None)
        policy, model, effort, binding, request, base_profile = self._prepare(node, state, materials, override)
        self.report_profiles[(state.get('task_id'), node)] = (model, effort)
        if node == Node.EXECUTOR_IMPLEMENT:
            if request.config.backend == MANAGED_CODEX_CLI:
                if self.native_admission is not None:
                    raise WorkflowError('native admission does not authorize managed implementation')
                self.task_requests.setdefault(state['task_id'], request)
                try:
                    if self._synthetic_cli_fixture is None:
                        invocation = self.managed_backend.execute(request, materials)
                    else:
                        invocation = self.managed_backend.execute_fixture(request, materials, self._synthetic_cli_fixture)
                except OutputProblem as exc:
                    self._register_managed_proof(state['task_id'])
                    self._check_managed_tests(state['task_id'])
                    exc.metadata['host_fixed_tests'] = self.managed_test_evidence(state['task_id'])
                    raise
                finally:
                    self._register_managed_proof(state['task_id'])
                self._check_managed_tests(state['task_id'], invocation.result)
                invocation.metadata['host_fixed_tests'] = self.managed_test_evidence(state['task_id'])
                return invocation
            self.task_requests.setdefault(state['task_id'], request)
            self.task_profiles.setdefault(state['task_id'], base_profile)
        native = getattr(self.adapter, "native_workspace_development", False)
        if node == Node.EXECUTOR_LOCAL_COMMIT and self.main_context in self._managed_proofs:
            if len(policy.commit_messages) != 1:
                raise WorkflowError("managed Host checkpoint requires one explicit Task message")
            checkpoint = self._managed_proofs[self.main_context].checkpoint(paths=list(policy.stageable_paths),
                message=policy.commit_messages[0], binding=self.checkpoint_binding)
            result = empty_result(checkpoint['disposition'], "Host verified accepted managed Task checkpoint")
            return Invocation(result, self.main_context, checkpoint['receipt'],
                {"origin": "HOST_CHECKPOINT", "backend": MANAGED_CODEX_CLI, "model": None}, checkpoint['no_commit_evidence'])
        if native and node == Node.EXECUTOR_LOCAL_COMMIT:
            policy = self._task_policy(state["task_id"])
            if not self.main_context or len(policy.commit_messages) != 1:
                raise WorkflowError("Host commit requires one explicit Task message and context")
            checkpoint = self.adapter.host_checkpoint(self.main_context, paths=list(policy.stageable_paths),
                                                       message=policy.commit_messages[0], binding=self.checkpoint_binding)
            action = checkpoint["disposition"]
            result = empty_result(action, "Host verified the accepted Task checkpoint disposition: " + action)
            return Invocation(result, self.main_context, checkpoint["receipt"],
                              {"origin": "HOST_CHECKPOINT", "model": None, "reasoning_effort": None},
                              checkpoint["no_commit_evidence"])
        fresh = node in FRESH_NODES
        if fresh:
            self.suspend()
            if self.latest_review:
                self._release(self.latest_review, "EXPLICIT_FRESH_REVIEW_SUPERSEDES_PRIOR_REVIEW")
                self.latest_review, self.review_has_report = None, False
            context = self.adapter.start_context(workspace=policy.workspace, model=model, reasoning_effort=effort,
                                                 purpose=ContextPurpose.FRESH_REVIEW, tool_policy=policy,
                                                 activity_metadata={"stage": state["stage_id"], "activity": node.value})
            thread_id = self.latest_review = context.thread_id
            self._protect(thread_id, "PENDING_REVIEW_TRANSFER")
            self.review_has_report = False
            profile = ToolProfile.READ_ONLY_REVIEW
            instructions = ("Fresh review: assess current code, fixed tests, effective authority and objective environment. "
                            "Developer reports/history/self-justification and verdicts are intentionally withheld, "
                            "including masked null reference fields. Report saving, repair authorization and "
                            "procedural acceptance/commit checks belong to Host/Promoter, not this code/test review. "
                            "Do not block solely because withheld documents are absent; actual missing objective "
                            "authority or code/test gaps still matter. Read-only; findings grant no repair permission.")
        else:
            had_context = self.main_context is not None
            if not self.main_context:
                context = self.adapter.start_context(workspace=policy.workspace, model=model, reasoning_effort=effort,
                                                     purpose=ContextPurpose.DEVELOPMENT, tool_policy=self.stage_policy,
                                                     task_policy=policy, task_binding=binding,
                                                     activity_metadata={"stage": state["stage_id"], "role": "Executor"})
                self.main_context = context.thread_id
            else:
                if node == Node.EXECUTOR_IMPLEMENT:
                    # Replace prior Task capabilities before resume validates them.
                    self.adapter.configure_task(self.main_context, policy, task_binding=binding)
                self.adapter.resume_context(thread_id=self.main_context, workspace=policy.workspace,
                                            tool_profile=ToolProfile.BOUNDED_DEVELOPMENT)
            thread_id = self.main_context
            if node == Node.EXECUTOR_IMPLEMENT:
                if not had_context:
                    self.adapter.configure_task(thread_id, policy, task_binding=binding)
                self.implementation_binding = binding
                self.task_start_contexts.setdefault(state["task_id"], thread_id)
                self.checkpoint_binding = None
            profile = ToolProfile.BOUNDED_DEVELOPMENT
            instructions = ("Implement the approved frozen Task autonomously in its specified workspace and scope. Run necessary tests and self-review; return EXECUTION_REPORT. The Host handles Task commit after acceptance; do not stage, commit, push, merge or release."
                            if node == Node.EXECUTOR_IMPLEMENT else
                            "Checkpoint-only phase, already accepted by Promoter. Inspect diff/status; exact authorized changes use one local commit. A permitted unchanged Task may request NO_DEV_CHANGE for Host verification. No implementation edits.")
            if node == Node.EXECUTOR_IMPLEMENT:
                policy_json = json.dumps({**self.execution_capabilities(state), 'binding': binding}, ensure_ascii=False)
                materials = {**materials, 'HOST_EXECUTOR_POLICY': policy_json}
        admission_ticket = None
        if node == Node.EXECUTOR_IMPLEMENT and self.native_admission is not None:
            try:
                admission_ticket, materials = self.native_admission.prepare(
                    state, thread_id, binding, materials, model, effort)
            except BaseException:
                self.suspend()
                raise
        prompt = build_prompt(role_text=instructions, activity=node.value, state=state, materials=materials,
                              allowed_schema=result_schema(node), profile=(model, effort),
                              native_implementation_policy=(policy if native and node == Node.EXECUTOR_IMPLEMENT
                                  and profile == policy.profile == ToolProfile.BOUNDED_DEVELOPMENT else None),
                              current_presence=(BoundedFileSystem(policy.workspace, readable=policy.readable_paths, writable=()).list_allowed()["files"]
                                  if profile == ToolProfile.READ_ONLY_REVIEW else None))
        captured_receipts = []
        try:
            admission_kwargs = {}
            if admission_ticket is not None:
                try:
                    admission_kwargs['deadline_seconds'] = self.native_admission.seal_dispatch(admission_ticket, state, prompt)
                except BaseException:
                    self.suspend()
                    raise
            if node == Node.EXECUTOR_IMPLEMENT:
                self._native_test_receipts.pop(state['task_id'], None)
            reply = run_handoff(self.adapter, node=node, state=state, thread_id=thread_id,
                prompt=prompt, model=model, reasoning_effort=effort,
                tool_profile=profile, output_schema=result_schema(node), receipt_observer=captured_receipts.append,
                **admission_kwargs)
        except WorkflowError as problem:
            if node == Node.EXECUTOR_IMPLEMENT:
                if captured_receipts:
                    evidence = self._capture_execution_evidence(state, thread_id, policy_json, prompt, captured_receipts[-1])
                    problem.host_execution_evidence = evidence
                    problem.context_ref = thread_id
                    if isinstance(problem, OutputProblem):
                        problem.metadata = {**(problem.metadata or {}), 'host_execution_evidence': evidence}
                try:
                    facts = self._capture_native_tests(state['task_id'], thread_id)
                    if facts is not None:
                        problem.native_test_receipt = facts
                        problem.context_ref = thread_id
                        if isinstance(problem, OutputProblem):
                            problem.metadata = {**(problem.metadata or {}), 'host_native_fixed_tests': facts}
                except Exception:
                    pass  # Preserve the original failure; never upgrade its eligibility.
            self.suspend()
            raise
        if node == Node.EXECUTOR_IMPLEMENT:
            evidence = self._capture_execution_evidence(state, thread_id, policy_json, prompt, captured_receipts[-1])
            reply = replace(reply, metadata={**(reply.metadata or {}), 'host_execution_evidence': evidence})
            facts = self._capture_native_tests(state['task_id'], thread_id)
            if facts is not None:
                reply = replace(reply, metadata={**(reply.metadata or {}), 'host_native_fixed_tests': facts})
        result = reply.result
        no_commit_evidence = None
        if node == Node.EXECUTOR_LOCAL_COMMIT and result["action"] == "NO_DEV_CHANGE":
            no_commit_evidence = self.adapter.host_no_dev_change(thread_id, binding=self.checkpoint_binding)
        if fresh:
            self.review_has_report = True
        else:
            self.suspend()
        receipt = self.adapter.commit_receipt(thread_id) if node == Node.EXECUTOR_LOCAL_COMMIT else None
        if node == Node.EXECUTOR_LOCAL_COMMIT and result["action"] == "COMMIT_COMPLETE" and receipt is None:
            raise WorkflowError("model commit claim lacks Host commit receipt")
        return Invocation(result, thread_id, receipt, reply.metadata, no_commit_evidence)

    def _check_managed_tests(self, task_id, result=None):
        self._managed_session.run_host_tests(task_id)
        # A known failure is evidence for the original Promoter Repair route.
        # The worker's claims cannot replace or suppress actual Host results.

    def correct_report(self, node, state, materials, override=None):
        if node not in {Node.EXECUTOR_IMPLEMENT, Node.INDEPENDENT_REVIEW}:
            raise WorkflowError('report-only correction is unavailable for this Executor activity')
        if node == Node.INDEPENDENT_REVIEW and self.objective_review_materials is not None:
            correction = {key: materials[key] for key in
                ('HOST_REPORT_CORRECTION', 'HOST_REPORT_ONLY', 'HOST_ORIGINAL_OUTPUT') if key in materials}
            materials = {**self.objective_review_materials(self, state, materials), **correction}
        selection = self.api_report_selections.get((state.get('task_id'), node))
        if selection:
            original = self.latest_review
            reply = self.model_router.invoke(selection, node=node, state=state, materials=materials,
                role_prompts=(API_FRESH_CORRECTION,),
                policy=ToolPolicy(self.stage_policy.workspace, ToolProfile.READ_ONLY_REVIEW, ()), correction=True)
            self.review_has_report = True
            return replace(reply, context_ref=original)
        self.suspend()
        task_id = state['task_id']
        if node == Node.EXECUTOR_IMPLEMENT and self.managed_task(task_id):
            session = self._managed_session
            request, proof = session.tasks[task_id]
            proof.verify_managed_tests(request, session.generations[task_id],
                session.implementation_receipts.get(task_id), require_passed=False)
            reply = self._managed_session.correct_report(self.task_requests[task_id], materials,
                fixture=self._synthetic_cli_fixture)
            self._register_managed_proof(task_id)
            proof.verify_managed_tests(request, session.generations[task_id],
                session.implementation_receipts.get(task_id), require_passed=False)
            reply.metadata['host_fixed_tests'] = self.managed_test_evidence(task_id)
            return reply
        model, effort = self.report_profiles.get((task_id, node)) or self.profiles.resolve(node, override)
        original = self.latest_review if node == Node.INDEPENDENT_REVIEW else self.main_context
        native_receipt = self._native_test_receipts.get(task_id) if node == Node.EXECUTOR_IMPLEMENT else None
        execution = getattr(self, '_execution_evidence', {}).get(task_id) if node == Node.EXECUTOR_IMPLEMENT else None
        if execution is not None:
            self.verify_execution_evidence(state, original, execution)
            materials = {**materials, 'HOST_EXECUTOR_POLICY': execution['policy_json'],
                         'HOST_EXECUTOR_EXECUTION_EVIDENCE': json.dumps(execution, ensure_ascii=False)}
        if native_receipt is not None:
            self.verify_native_test_evidence(state, original, native_receipt)
        policy = ToolPolicy(self.stage_policy.workspace, ToolProfile.READ_ONLY_REVIEW, ())
        context = self.adapter.start_context(workspace=policy.workspace, model=model, reasoning_effort=effort,
            purpose=ContextPurpose.READ_ONLY_ROLE, tool_policy=policy,
            activity_metadata={'stage': state['stage_id'], 'role': 'Executor', 'purpose': 'REPORT_CORRECTION'})
        try:
            prompt = build_prompt(role_text='Original Executor: correct the saved report only; no tools or re-execution.',
                activity=node.value, state=state, materials=materials, allowed_schema=result_schema(node, state),
                profile=(model, effort))
            reply = run_handoff(self.adapter, node=node, state=state, thread_id=context.thread_id,
                prompt=prompt, model=model, reasoning_effort=effort, tool_profile=ToolProfile.READ_ONLY_REVIEW,
                output_schema=result_schema(node, state))
            if node == Node.INDEPENDENT_REVIEW:
                self.review_has_report = True
            if native_receipt is not None:
                reply = replace(reply, metadata={**(reply.metadata or {}),
                    'host_native_fixed_tests': copy.deepcopy(native_receipt)})
            if execution is not None:
                reply = replace(reply, metadata={**(reply.metadata or {}), 'host_execution_evidence': copy.deepcopy(execution)})
            return replace(reply, context_ref=original)
        finally:
            self._release(context.thread_id, 'REPORT_CORRECTION_COMPLETE')
