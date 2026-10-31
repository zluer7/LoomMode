"""Sequential deterministic engine. No natural-language routing or task selection."""
import copy
import json
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any
from loommode.roles.contracts import INTENT_SCHEMA, SYNC_TARGETS, REQUIRED_ARTIFACT, allowed_artifact_kinds, review_repair_available, validate, handoff_schema as result_schema
from loommode.tools.git import require_no_commit_evidence
from loommode.roles.runtime import Invocation
from .artifacts import ArtifactStore
from .allowance_history import AllowanceHistorySource, merge_events, merge_reports, evidence_ids
from .errors import WorkflowError, OutputProblem
from .state import StateStore, WorkflowState, identity, unique_json_object
from .transitions import Action, FRESH_NODES, Node, Role, STOP_NODES, TABLE, TASK_REQUIRED_NODES, HARD_GATE_CATEGORIES
from .owner_requests import OWNER_INPUT_NODES, parse_owner_request
from .checkpoints import verify_saved_no_commit, task_closure_history
from .failure_evidence import failure_evidence, safe_outward_error
from .governance import ScopeGrant, digest, scope_name, stage_tuple, validate_issue_update, validate_triage, render_knowledge
from .transitions import WINDOW_NODES


class ScopeRejected(WorkflowError):
    """Known-effect unauthorized proposal; no Intent publication or replay fiction."""

TASK_NODES = TASK_REQUIRED_NODES


class WorkflowEngine:
    def __init__(self, state: WorkflowState, store: StateStore, artifacts: ArtifactStore,
                 roles: Any, executor: Any, authority_materials: dict[str, str], *,
                 stage_authorization_ref: str | None = None, local_commit_authorized: bool = False,
                 memory_authority_ref: str | None = None, scope_grant_refs: tuple[str, ...] = (),
                 allowance_history_sources: tuple[AllowanceHistorySource, ...] = ()) -> None:
        state.validate()
        if (state.project, state.stage_id) != (artifacts.project, artifacts.stage):
            raise WorkflowError("artifact/state identity mismatch")
        if not authority_materials:
            raise WorkflowError("explicit authority material is required")
        if not stage_authorization_ref or stage_authorization_ref not in authority_materials:
            raise WorkflowError("explicit Owner-approved Stage input reference is required")
        if state.stage_input_ref and state.stage_input_ref != stage_authorization_ref:
            raise WorkflowError("Stage authorization reference changed")
        state.stage_input_ref = stage_authorization_ref
        self.state, self.store, self.artifacts, self.roles, self.executor = state, store, artifacts, roles, executor
        self.authority = dict(authority_materials)
        self.commit_authorized = local_commit_authorized
        self.memory_authority = memory_authority_ref
        self.history_sources = {}
        self._allowance_write_failed = False
        for source in allowance_history_sources:
            if not isinstance(source, AllowanceHistorySource) or source.name in self.history_sources:
                raise WorkflowError('history requires unique actual Host source handles')
            self.history_sources[source.name] = source
        self.scope_grants = {}
        policy = getattr(executor, 'stage_policy', None)
        workspace = str((policy.workspace if policy else artifacts.root.parent / 'Dev').resolve())
        for ref in scope_grant_refs:
            if ref not in self.authority:
                raise WorkflowError("Owner scope grant reference unavailable")
            grant = ScopeGrant.from_authority(ref, self.authority[ref])
            if grant.project != state.project or state.stage_id not in grant.stage_ids or grant.workspace != workspace:
                raise WorkflowError("scope grant Project/Stage mismatch")
            self.scope_grants[ref] = grant
        cycle, phase, _ = stage_tuple(state.stage_id)
        # The existing constructor explicitly requires Owner-approved Stage input.
        # It grants that Stage only; no text interpretation can broaden it.
        self.stage_grant = ScopeGrant('STAGE', state.stage_id, stage_authorization_ref,
            digest(self.authority[stage_authorization_ref]), state.project, workspace,
            f'{cycle}-{phase}', (state.stage_id,))
        self.stage_grant.validate()
        if state.active_grant is None:
            state.active_grant = self.stage_grant.as_dict()
        self._busy = False
        self._resource_degraded: str | None = None
        self._resources_closed = False
        # A caller's fresh Context is not authority to replace durable spend.
        # This is a preservation guard, not automatic restart/replay recovery.
        if store.path.exists():
            old = WorkflowState(**json.loads(store.path.read_text(encoding='utf-8'), object_pairs_hook=unique_json_object))
            old.validate()
            aliases = ('HOST_ALLOWANCE_FAMILY', 'HOST_ALLOWANCE_CONSUMPTION', 'HOST_ALLOWANCE_GRANT', 'HOST_ALLOWANCE_HISTORY')
            if any(old.artifact_refs.get(alias) for alias in aliases):
                if (not set(old.used_task_ids).issubset(state.used_task_ids)
                        or any(not set(refs).issubset(state.artifact_refs.get(alias, []))
                               for alias, refs in old.artifact_refs.items())
                        or any(state.task_relationships.get(task) != relation for task, relation in old.task_relationships.items())
                        or any(value is True and state.blocker_ledger.get(key, {}).get(flag) is not True
                               for key, entry in old.blocker_ledger.items() for flag, value in entry.items())
                        or old.in_flight_activity and state.in_flight_activity != old.in_flight_activity):
                    raise WorkflowError('existing Store allowance facts cannot be replaced or reset by new Context')
        if state.artifact_refs.get('HOST_ALLOWANCE_HISTORY'):
            self._history_receipts(state)  # Validate before any constructor write.
            self._allowance_totals(state)
        self.store.save(state)

    def grant(self) -> ScopeGrant:
        value = dict(self.state.active_grant)
        for key in ('stage_ids', 'series_ids', 'task_ids'):
            value[key] = tuple(value[key])
        value['relationships'] = tuple(value['relationships'].items())
        result = ScopeGrant(**value)
        return self._check_grant(result)

    def _check_grant(self, result):
        result.validate()
        if digest(self.authority.get(result.authority_ref, '')) != result.authority_sha256:
            raise ScopeRejected("actual Owner grant bytes changed")
        policy = getattr(self.executor, 'stage_policy', None)
        actual_workspace = str(policy.workspace.resolve()) if policy else self.stage_grant.workspace
        if (result.project != self.state.project or self.state.stage_id not in result.stage_ids
                or result.workspace != actual_workspace or result.workspace != self.stage_grant.workspace):
            raise ScopeRejected('actual Owner grant Project/Stage/workspace binding changed')
        if result.scope not in {'TASK', 'STAGE'} and self.scope_grants.get(result.authority_ref) != result:
            raise ScopeRejected("broader scope not registered from actual Owner authority")
        return result

    def _active_task(self, state=None):
        """Historical last Task IDs are not active outside their actual lifecycle."""
        state = state or self.state
        node = Node(state.current_node)
        if node == Node.DECISION_MEDIATION:
            ref = state.decision_handoff_ref
            if not ref or ref not in state.artifact_refs.get('DECISION_HANDOFF', []):
                raise WorkflowError('mediation lacks actual saved handoff')
            finding = self.artifacts.read_json(ref)
            if (finding.get('origin') != 'HOST_INTERNAL_ESCALATION' or finding.get('stage_id') != state.stage_id
                    or finding.get('origin_activity') != finding.get('resume_node')):
                raise WorkflowError('mediation lifecycle provenance mismatch')
            node = Node(finding['resume_node'])
            if node in TASK_REQUIRED_NODES and finding.get('task_id') != state.task_id:
                raise WorkflowError('Task-origin mediation identity mismatch')
        if node in TASK_REQUIRED_NODES:
            if not state.task_id or not state.formal_task_intent_ref:
                raise WorkflowError('active Task lifecycle lacks actual Intent')
            return state.task_id
        return None

    def select_grant(self, scope, *, reference=None, scope_id=None, task_id=None):
        scope = scope_name(scope)
        if reference:
            grant = self.scope_grants.get(reference)
            if not grant or grant.scope != scope or grant.scope_id != scope_id:
                raise ScopeRejected("selected broader grant is not explicitly registered")
        elif scope == 'STAGE':
            grant = self.stage_grant
        elif scope == 'TASK' and task_id:
            self.preflight_task(task_id)
            grant = ScopeGrant('TASK', task_id, self.stage_grant.authority_ref, self.stage_grant.authority_sha256,
                self.state.project, self.stage_grant.workspace, self.stage_grant.major_phase,
                (self.state.stage_id,), task_ids=(task_id,))
        else:
            raise ScopeRejected("Series/Major Phase/bounded delegation requires its own actual Owner grant")
        grant.validate()
        if self.state.stage_id not in grant.stage_ids:
            raise ScopeRejected("current Stage outside selected Owner grant")
        if grant.workspace != self.stage_grant.workspace:
            raise ScopeRejected('actual Owner grant workspace mismatch')
        self._check_grant(grant)
        active = self._active_task()
        if active:
            self.preflight_task(active, grant=grant)
        self.state.active_grant = grant.as_dict()
        self.store.save(self.state)
        return grant

    def preflight_task(self, task_id, relationship=None, *, grant=None, state=None):
        import re
        state = state or self.state
        grant = self._check_grant(grant) if grant is not None else self.grant()
        if not grant.contains(task_id, stage=state.stage_id, relationship_check=False):
            raise ScopeRejected("Task outside actual delegated parent membership/relationship")
        if re.search(r'-[RF][0-9]+$', task_id):
            relation = relationship or state.task_relationships.get(task_id)
            pinned = dict(grant.relationships).get(task_id)
            if not relation:
                raise ScopeRejected('derived Task requires explicit typed parent/relationship evidence')
            try:
                validate(relation, INTENT_SCHEMA['properties']['relationship'])
            except WorkflowError as error:
                raise ScopeRejected('derived Task requires a valid typed relationship') from error
            parent = relation['parent_task_id']
            if pinned and parent != pinned:
                raise ScopeRejected('derived Task parent differs from explicit Owner relationship pin')
            from .governance import original_task_id
            if original_task_id(task_id) != original_task_id(parent):
                raise ScopeRejected('derived Task relationship must retain the original Task stem')
            exact_child = grant.scope in {'TASK', 'EXPLICIT_BOUNDED_SCOPE'} and task_id in grant.task_ids
            if (parent == task_id or (not exact_child and not grant.contains(parent, relationship_check=False))
                    or not self.stage_grant.contains(parent, stage=state.stage_id, relationship_check=False) or parent not in state.used_task_ids
                    or relation['parent_ref'] not in ({ref for refs in state.artifact_refs.values() for ref in refs})):
                raise ScopeRejected('derived Task parent is not actual authorized current work/evidence')
            ref = relation['parent_ref']
            bound = False
            for kind in ('TASK_INTENT', 'FINAL_TASK_CONSTRAINT', 'EXECUTION_REPORT', 'DECISION'):
                try:
                    self.artifacts.assert_task_reference(ref, kind, parent)
                    bound = True
                    break
                except WorkflowError:
                    continue
            if not bound:
                raise ScopeRejected('relationship evidence does not belong to named parent Task')
            if not relation['reason'].strip():
                raise ScopeRejected('bounded derived Task reason required')
            expected = 'REPAIR' if re.search(r'-R[0-9]+$', task_id) else 'FOLLOWUP'
            if relation['kind'] != expected:
                raise ScopeRejected('derived Task relationship kind mismatch')

    def register_issue(self, update):
        """Host can register discovery/update at a quiescent live Stage boundary."""
        if self._busy or self.state.in_flight_activity or self.state.stage_closed:
            raise WorkflowError("issue update requires known-effect active Stage boundary")
        working = copy.deepcopy(self.state)
        self._apply_issues(working, [update])
        if working.stage_acceptance_ref:
            working.stage_acceptance_ref = None
            working.stage_knowledge_ref = None
            working.machine_close_ready = False
            working.memory_completed_roles = []
            self._move(working, Node.STAGE_ACCEPTANCE)
        self.store.save(working)
        self.state = working
        return working

    def _apply_issues(self, state, updates):
        known = set(self.authority) | {ref for refs in state.artifact_refs.values() for ref in refs}
        if len({row['issue_id'] for row in updates}) != len(updates):
            raise WorkflowError("duplicate current issue update")
        for update in updates:
            value = validate_issue_update(update, state.stage_issues, known)
            for ref in {value['origin_ref'], *value['evidence_refs']}:
                if ref not in self.authority:
                    self.artifacts.read(ref)
            state.stage_issues[value['issue_id']] = value
        if updates:
            state.issue_triage = []
            self._save_artifact(state, 'STAGE_ISSUE_LEDGER', json.dumps({'stage_id': state.stage_id, 'issues': state.stage_issues}, ensure_ascii=False))

    def soft_window_expired(self, event):
        """Only the bound Host applies its authenticated queued event at quiescence."""
        if self._busy or self.state.in_flight_activity or Node(self.state.current_node) not in WINDOW_NODES:
            raise WorkflowError("soft expiry requires a quiescent window")
        node = Node(self.state.current_node)
        ref = self.state.stage_notice_ref if node == Node.SOFT_REVIEW_WAIT else self.state.stage_closeout_ref
        if event.get('notice_ref') != ref or event.get('stage_id') != self.state.stage_id:
            raise WorkflowError("obsolete Stage notice expiry")
        self.artifacts.read(ref)
        working = copy.deepcopy(self.state)
        working.soft_window_events.append({**event, 'outcome': 'NO_OBJECTION_OBSERVED', 'owner_accepted': False})
        working.owner_accepted = False
        if node == Node.SOFT_ACCEPTANCE_WAIT:
            working.stage_closed = True
        self._move(working, Node.TASK_SELECTION if node == Node.SOFT_REVIEW_WAIT else Node.COMPLETED)
        self.store.save(working)
        self.state = working
        return working

    def owned_adapters(self) -> tuple[Any, ...]:
        from loommode.codex.adapter import ThinCodexAdapter
        values = (getattr(self.roles, "adapter", None), getattr(self.executor, "adapter", None))
        return tuple({id(value): value for value in values if isinstance(value, ThinCodexAdapter)}.values())

    def _retain_context_references(self) -> None:
        refs = set(self.state.role_context_refs.values()) | {
            self.state.executor_context_ref, self.state.active_review_context_ref}
        for adapter in self.owned_adapters():
            adapter.registry.retain_current_references(refs - {None})

    def owned_implementation_backends(self) -> tuple[Any, ...]:
        from .implementation import ManagedCodexBackend
        backend = getattr(self.executor, 'managed_backend', None)
        return (backend,) if isinstance(backend, ManagedCodexBackend) and backend.owns_session else ()

    def resource_health(self) -> dict[str, Any]:
        adapters = [adapter.health() for adapter in self.owned_adapters()]
        managed = [backend.health() for backend in self.owned_implementation_backends()]
        reasons = ([self._resource_degraded] if self._resource_degraded else []) + [
            reason for adapter in adapters for reason in adapter["reasons"]]
        if len(adapters) > 1:
            reasons.append("Host roles/Executor must share one owned Adapter")
        reasons.extend(reason for backend in managed for reason in backend.get('reasons', []))
        if any(not backend['healthy'] for backend in managed) and not reasons:
            reasons.append("managed implementation resource health unproved")
        return {"scope": "SUPPORTED_HOST_OWNED_RUNTIME", "status": "DEGRADED" if reasons else
                "RELEASED" if self._resources_closed else "HEALTHY",
                "reasons": reasons, "adapters": adapters, "managed_backends": managed}

    def assert_resource_health(self) -> None:
        health = self.resource_health()
        if health["reasons"] or self._resources_closed:
            raise WorkflowError("resource health blocks dispatch: " + "; ".join(health["reasons"]))
        for adapter in self.owned_adapters():
            adapter.assert_healthy()
        if any(backend.health().get('closed') for backend in self.owned_implementation_backends()):
            raise WorkflowError("closed managed backend blocks dispatch")

    def close_resources(self) -> dict[str, Any]:
        if self._busy:
            raise WorkflowError("cannot retire resources while Engine activity is active")
        for backend in self.owned_implementation_backends():
            receipt = backend.close()
            if (not receipt.get('closed') or not receipt.get('healthy', True)
                    or receipt.get('unknown_side_effect') or not backend.health()['healthy']):
                self._resource_degraded = "managed resource closure unproved; writer ownership must be retained"
                raise WorkflowError(self._resource_degraded)
        for adapter in self.owned_adapters():
            adapter.close()
        # Unknown/custom Adapter doubles are outside this owned-resource proof.
        # Only an actual owned production Adapter closure fences its dispatch.
        self._resources_closed = bool(self.owned_adapters() or self.owned_implementation_backends())
        return self.resource_health()

    def renew_contexts(self) -> dict[str, Any]:
        if self._busy or self.state.in_flight_activity or Node(self.state.current_node) in {
                Node.FAILED, Node.RECOVERY_REQUIRED, Node.COMPLETED}:
            raise WorkflowError("renewal requires a quiescent known-effect live boundary")
        self.assert_resource_health()
        self._retain_context_references()
        if json.loads(self.store.path.read_text(encoding="utf-8")) != self.state.as_dict():
            raise WorkflowError("renewal State is not durably current")
        native = any(adapter.process_renewal_mode for adapter in self.owned_adapters())
        if native and self.executor.renewal_protected():
            return {"deferred": True, "preserved": "CURRENT_TASK_BASELINE_OR_PENDING_FRESH_TRANSFER",
                    "state_mutated": False, "permissions_expanded": False}
        try:
            result = {"roles": self.roles.renew_contexts(), "executor": self.executor.renew_contexts(),
                      "state_mutated": False, "permissions_expanded": False}
            result["processes"] = [adapter.renew_process() for adapter in self.owned_adapters()
                                   if adapter.process_renewal_mode]
            for adapter in self.owned_adapters():
                adapter.record_renewal()
            return result
        except Exception as exc:
            self._resource_degraded = "quiescent renewal failed: " + str(exc)
            raise WorkflowError(self._resource_degraded) from exc

    def resource_renewal_due(self) -> bool:
        return any(adapter.renewal_due for adapter in self.owned_adapters())

    def _move(self, state: WorkflowState, node: Node, reason: str | None = None) -> None:
        state.current_node = node.value
        state.waiting_human = node in {Node.HUMAN_GATE, Node.HUMAN_BLOCK, Node.RECOVERY_REQUIRED}
        state.human_gate_reason = reason if state.waiting_human else None
        state.status = {Node.HUMAN_GATE: "WAITING_HUMAN", Node.HUMAN_BLOCK: "WAITING_HUMAN",
                        Node.FAILED: "FAILED", Node.COMPLETED: "COMPLETED",
                        Node.RECOVERY_REQUIRED: "RECOVERY_REQUIRED"}.get(node, "RUNNING")

    def _refs(self, state: WorkflowState, kind: str) -> list[str]:
        return state.artifact_refs.get(kind, [])

    def _save_artifact(self, state: WorkflowState, kind: str, content: str) -> str:
        ref = self.artifacts.save(kind, content, task_id=state.task_id if Node(state.current_node) in TASK_NODES else None)
        state.artifact_refs.setdefault(kind, []).append(ref)
        if kind == "FINAL_TASK_CONSTRAINT":
            state.formal_constraint_ref = ref
        if kind == "EXECUTION_REPORT":
            state.latest_execution_report_ref = ref
        return ref

    def _owner_request(self, state: WorkflowState, ref: str, *, current: bool = True) -> dict[str, Any]:
        if ref not in state.artifact_refs.get("OWNER_REQUEST", []):
            raise WorkflowError("Owner input is not registered in this Stage")
        value = parse_owner_request(self.artifacts.read(ref))
        if (value["project"], value["stage_id"]) != (state.project, state.stage_id):
            raise WorkflowError("Owner request identity mismatch")
        owner = value["task_id"] if value["scope"] == "TASK" else state.stage_id
        self.artifacts.assert_task_reference(ref, "DECISION", owner)
        if current and value["scope"] == "TASK" and value["task_id"] != state.task_id:
            raise WorkflowError("Owner request targets an old Task")
        return value

    def register_owner_request(self, ref: str) -> WorkflowState:
        """Register explicit Host input only; do not select work or change a node/grant."""
        self.state.validate()
        if self._busy or self.state.in_flight_activity or self.state.status in {"FAILED", "COMPLETED"}:
            raise WorkflowError("Owner input cannot be registered during unknown/in-flight/completed work")
        existing = self.state.artifact_refs.get("OWNER_REQUEST", [])
        if ref in existing:
            raise WorkflowError("Owner request is already registered")
        if len(existing) >= 32:
            raise WorkflowError("bounded Stage Owner input limit reached")
        working = copy.deepcopy(self.state)
        working.artifact_refs.setdefault("OWNER_REQUEST", []).append(ref)
        value = self._owner_request(working, ref)
        if any(self._owner_request(self.state, old, current=False)["request_id"] == value["request_id"] for old in existing):
            raise WorkflowError("duplicate Owner request identity")
        known = set(self.authority) | {r for refs in self.state.artifact_refs.values() for r in refs}
        if any(e not in known for e in value["evidence_refs"]):
            raise WorkflowError("Owner evidence is not explicit Stage input")
        for evidence in value["evidence_refs"]:
            if evidence not in self.authority:
                self.artifacts.read(evidence)
        self.store.save(working)
        self.state = working
        return working

    def _review_conversion_available(self, state: WorkflowState) -> bool:
        if not review_repair_available(state.as_dict()) or self._managed_selected(state.task_id):
            return False
        check = getattr(self.executor, 'review_context_conversion_available', None)
        return bool(check(state.active_review_context_ref)) if check else True

    def _materials(self, state: WorkflowState, node: Node, owner_request_refs: tuple[str, ...] = ()) -> dict[str, str]:
        materials = dict(self.authority)
        procedural_authority = set()
        if node not in {Node.DECISION_MEDIATION, Node.PROMOTER_RESULT_REVIEW}:
            # These witnesses include an old checkpoint/verdict, not objective
            # code authority. Keep them in Host validation and procedural roles.
            for ref, raw in self.authority.items():
                try:
                    value = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if not isinstance(value, dict) or value.get('origin') != 'OWNER_KNOWN_INTERNAL_FINDING_REPAIR_AUTHORIZATION':
                    continue
                admission_ref = value.get('admission_ref')
                admission = json.loads(self.authority[admission_ref], object_pairs_hook=unique_json_object)
                for hidden in (ref, value.get('owner_source_ref'), admission_ref, *admission['source_evidence_refs']):
                    if hidden in self.authority:
                        procedural_authority.add(hidden)
        materials['HOST_GOVERNANCE'] = json.dumps({'grant': state.active_grant,
            'stage_plan_ref': state.stage_plan_ref, 'stage_acceptance_ref': None if node in FRESH_NODES else state.stage_acceptance_ref,
            'current_issues': state.stage_issues, 'triage': [] if node in FRESH_NODES else state.issue_triage,
            'knowledge_ref': None if node in FRESH_NODES else state.stage_knowledge_ref,
            'required_protocol': 'Fresh review → plan → Decision → persisted notice → 1800s soft review; acceptance → triage/repair → early eligibility → readable knowledge → six-target sync → four-role memory → final Decision → 3600s soft acceptance. Silence is not approval.'}, ensure_ascii=False)
        if state.formal_task_intent_ref and node in {Node.PROMOTER_RESULT_REVIEW, Node.DECISION_MEDIATION}:
            totals = self._allowance_totals(state)
            family = totals['family_task_id']
            members = {task for task in state.used_task_ids
                       if self._allowance_family(state, task, require_source=False) == family}
            sources = {}
            for kind in ('HOST_ALLOWANCE_FAMILY', 'HOST_ALLOWANCE_HISTORY', 'HOST_ALLOWANCE_CONSUMPTION',
                         'HOST_ALLOWANCE_GRANT', 'REPORT_RESULT'):
                refs = []
                for ref in self._refs(state, kind):
                    value = self.artifacts.read_json(ref)
                    if kind == 'REPORT_RESULT':
                        for task in members:
                            try:
                                self.artifacts.assert_task_reference(ref, 'DECISION', task)
                                break
                            except WorkflowError:
                                continue
                        else:
                            continue
                    elif value['family_task_id'] != family:
                        continue
                    materials[ref] = self.artifacts.read(ref)
                    refs.append(ref)
                    if kind == 'HOST_ALLOWANCE_FAMILY':
                        materials[value['intent_ref']] = self.artifacts.read(value['intent_ref'])
                        if value['parent_ref']:
                            materials[value['parent_ref']] = self.artifacts.read(value['parent_ref'])
                sources[kind] = refs
            materials['HOST_ALLOWANCE_FACTS'] = json.dumps({
                'task_id': state.task_id, 'family_task_id': family,
                'used': {kind: totals[kind] for kind in totals['capacity']},
                'capacity': totals['capacity'],
                'remaining': {kind: totals['capacity'][kind] - totals[kind] for kind in totals['capacity']},
                'source_refs': sources,
                'boundary': 'Read-only family accounting, not dispatch authorization. Cite the formal source refs, '
                            'not this dynamic key. Native budget, Writer, current source/Grant and expiry are '
                            'separate Host checks and must be rechecked before dispatch.'}, ensure_ascii=False)
        if node not in FRESH_NODES and state.mediation_result_ref:
            materials[state.mediation_result_ref] = self.artifacts.read(state.mediation_result_ref)
            if state.decision_handoff_ref:
                materials[state.decision_handoff_ref] = self.artifacts.read(state.decision_handoff_ref)
                source = self.artifacts.read_json(state.decision_handoff_ref)['original_result_ref']
                materials[source] = self.artifacts.read(source)
        if node == Node.STAGE_PLANNING:
            refs = [ref for ref in state.owner_window_refs if ref in self._refs(state, 'OWNER_REQUEST')
                    and ((value := self._owner_request(state, ref, current=False))['scope'] == 'STAGE'
                         or value['task_id'] == state.task_id)]
            for ref in refs:
                materials[ref] = self.artifacts.read(ref)
            if refs:
                materials['HOST_OWNER_WINDOW_INPUTS'] = json.dumps([{'reference': ref, **self._owner_request(state, ref)} for ref in refs], ensure_ascii=False)
        if node == Node.DECISION_MEDIATION:
            handoff = self.artifacts.read_json(state.decision_handoff_ref)
            materials[state.decision_handoff_ref] = self.artifacts.read(state.decision_handoff_ref)
            for ref in [handoff['original_result_ref'], *handoff['evidence_refs']]:
                materials[ref] = self.authority[ref] if ref in self.authority else self.artifacts.read(ref)
            materials['HOST_MEDIATION_POLICY'] = json.dumps({'protected_categories': sorted(HARD_GATE_CATEGORIES),
                'boundary': 'Decision judges the supplied finding. Protected categories require HARD_GATE or SAFE_STOP. No new Intent, grant, retry, tool permission or frozen Final rewrite. Planner owns any adjustment/derived Intent. Owner-window inputs require plan revision and a new notice/window, or an explicit COMPLETE_STAGE_REVIEW receipt for bounded early review.'})
        if node in FRESH_NODES:
            materials["HOST_FRESH_REVIEW_SCOPE"] = json.dumps({
                "activity": node.value,
                "purpose": "OBJECTIVE_CODE_AND_TEST_FINDINGS",
                "deliberately_withheld": ["developer execution reports", "developer self-review",
                                           "previous acceptance verdicts", "previous independent review verdicts",
                                           "previous procedural action receipts", "context history"],
                "report_reference_fields_are_masked": True,
                "procedural_report_acceptance_commit_auditors": ["Host", "Promoter"],
                "boundary": "Judge current code, fixed tests and supplied objective authority. Report/acceptance/commit "
                            "and prior review/action receipt prerequisites in Task documents apply to later procedural judgments, not this fresh "
                            "code review. Withheld reports/verdicts and masked null reference fields are not missing "
                            "prerequisites here. Actual missing objective contract or unsafe/unverifiable code still blocks.",
            }, ensure_ascii=False)
        # Later action receipts must not replace the actual Decision contract.
        # These refs are only the role-produced documents, not developer or
        # acceptance narratives; they remain objective inputs for fresh tests.
        for ref in self._refs(state, "DECISION_PLAN"):
            materials[ref] = self.artifacts.read(ref)
        own_sync = self._refs(state, "SYNC_APPLICATION")[-1:]
        replaced_targets = {item['target'] for ref in own_sync for item in self.artifacts.read_json(ref)['sync'] if item['updated_ref']}
        for ref in self._refs(state, 'PROGRAM_INPUT')[-1:]:
            current = self.artifacts.read_json(ref)
            if current.get('origin') != 'HOST_SUCCESSOR_PROGRAM_INPUT' or current.get('target_stage') != state.stage_id:
                raise WorkflowError('successor current Program input identity mismatch')
            if current['target'] not in replaced_targets:
                content = self.artifacts.read(current['updated_ref'])
                materials[current['updated_ref']] = content
                materials['SYNC_CURRENT:'+current['target']] = content
                materials['HOST_CURRENT_PROGRAM_SOURCE'] = json.dumps(current,ensure_ascii=False)
        for ref in own_sync:
            materials[ref] = self.artifacts.read(ref)
            for item in self.artifacts.read_json(ref)["sync"]:
                if item["updated_ref"]:
                    content = self.artifacts.read(item["updated_ref"])
                    materials[item["updated_ref"]] = content
                    materials[f"SYNC_CURRENT:{item['target']}"] = content
        # Every call supplies actual formal refs, never a directory scan or remembered facts.
        if state.formal_task_intent_ref:
            materials[state.formal_task_intent_ref] = self.artifacts.read(state.formal_task_intent_ref)
            intent = self.artifacts.read_json(state.formal_task_intent_ref)
            withheld = {ref for kind in ("EXECUTION_REPORT", "REPORT_RESULT", "ACCEPTANCE", "INDEPENDENT_REVIEW", "DECISION", "OWNER_REQUEST")
                        for ref in self._refs(state, kind)} if node in FRESH_NODES else set()
            if node in FRESH_NODES:
                # Role-produced Decision contracts remain objective inputs;
                # automatic action receipts carry prior procedural judgments.
                withheld.difference_update(self._refs(state, "DECISION_PLAN"))
                withheld.update(state.task_checkpoint_refs.values())
            for ref in intent["authority_refs"]:
                if ref not in materials and ref not in withheld:
                    materials[ref] = self.artifacts.read(ref)
        if state.formal_constraint_ref:
            materials[state.formal_constraint_ref] = self.artifacts.read(state.formal_constraint_ref)
        if node not in FRESH_NODES and state.latest_execution_report_ref:
            materials[state.latest_execution_report_ref] = self.artifacts.read(state.latest_execution_report_ref)
        if node not in FRESH_NODES and state.acceptance_ref:
            # Continuation may cite the saved result judgment visible in State.
            # It is evidence, never an authority grant or a fresh-review input.
            materials[state.acceptance_ref] = self.artifacts.read(state.acceptance_ref)
        kinds = (["PLAN_REFERENCE", "STAGE_ISSUE_LEDGER"] if node in FRESH_NODES else
                 ["PLAN_REFERENCE", "CONSTRAINT_DRAFT", "DISCUSSANT_REVIEW", "DECISION", "IMPLEMENTATION_PLAN", "INDEPENDENT_REVIEW", "STAGE_ISSUE_LEDGER"])
        for kind in kinds:
            refs = self._refs(state, kind)
            if state.task_id and node in TASK_NODES and kind in {"CONSTRAINT_DRAFT", "DISCUSSANT_REVIEW", "DECISION", "IMPLEMENTATION_PLAN", "INDEPENDENT_REVIEW"}:
                refs = [ref for ref in refs if f"{state.task_id}_" in ref]
            if refs:
                materials[refs[-1]] = self.artifacts.read(refs[-1])
        if node == Node.TASK_SELECTION and state.task_id:
            # A follow-up needs the just-completed Task's failure/repair facts,
            # not remembered locators or every earlier milestone's history.
            for kind in ("EXECUTION_REPORT", "REPORT_RESULT", "ACCEPTANCE", "DECISION"):
                for ref in self._refs(state, kind):
                    if Path(ref.rsplit("#sha256=", 1)[0]).name.startswith(f"{state.task_id}_"):
                        actual_kind = "DECISION" if kind == "REPORT_RESULT" else kind
                        self.artifacts.assert_task_reference(ref, actual_kind, state.task_id)
                        materials[ref] = self.artifacts.read(ref)
            checkpoint = state.task_checkpoint_refs.get(state.task_id)
            if checkpoint:
                self.artifacts.assert_task_reference(checkpoint, "DECISION", state.task_id)
                materials[checkpoint] = self.artifacts.read(checkpoint)
        if node in {Node.STAGE_SETTLEMENT, Node.STAGE_MACHINE_CLOSE, Node.STAGE_CLOSE_SYNC,
                    Node.STAGE_ISSUE_TRIAGE, Node.STAGE_KNOWLEDGE, Node.ROLE_MEMORY_CONSOLIDATION, Node.OWNER_SUMMARY}:
            # Procedural closure needs each actual Host checkpoint proof. Later
            # Decision receipts cannot substitute for a Task's saved evidence.
            # Fresh code/test reviews deliberately receive none of these verdicts.
            for ref in state.task_checkpoint_refs.values():
                materials[ref] = self.artifacts.read(ref)
            if state.stage_acceptance_ref:
                materials[state.stage_acceptance_ref] = self.artifacts.read(state.stage_acceptance_ref)
        if node == Node.STAGE_ACCEPTANCE:
            # A fresh integration reviewer needs every milestone's objective
            # execution input, including earlier Tasks, without writer verdicts.
            withheld = {ref for kind in ("EXECUTION_REPORT", "REPORT_RESULT", "ACCEPTANCE", "INDEPENDENT_REVIEW", "DECISION", "OWNER_REQUEST")
                        for ref in self._refs(state, kind)}
            withheld.difference_update(self._refs(state, "DECISION_PLAN"))
            withheld.update(state.task_checkpoint_refs.values())
            for kind in ("TASK_INTENT", "FINAL_TASK_CONSTRAINT"):
                for ref in self._refs(state, kind):
                    materials[ref] = self.artifacts.read(ref)
                    if kind == "TASK_INTENT":
                        for source in self.artifacts.read_json(ref)["authority_refs"]:
                            if source not in materials and source not in withheld:
                                materials[source] = self.artifacts.read(source)
        if node == Node.OWNER_SUMMARY:
            provider = getattr(self, 'host_continuation_facts', None)
            if provider:
                facts, receipts = provider()
                if facts and facts['persistence']['verification'] != 'VERIFIED':
                    raise WorkflowError('final Decision continuation evidence is unverified')
                materials['HOST_CONTINUATION_FACTS'] = json.dumps(facts, ensure_ascii=False)
                materials.update(receipts)
            materials['HOST_FINAL_CLOSE_FACTS'] = json.dumps({'issues': state.stage_issues, 'triage': state.issue_triage,
                'grant': state.active_grant, 'soft_window_events': state.soft_window_events,
                'mediation_refs': self._refs(state, 'DECISION_HANDOFF'),
                'decision_notice_refs': self._refs(state, 'DECISION_NOTICE'),
                'memory_completed_roles': state.memory_completed_roles}, ensure_ascii=False)
            for kind in ("STAGE_RECORD", "STAGE_KNOWLEDGE", "ROLE_EXPERIENCE", "MAJOR_PHASE_PROMOTION", 'DECISION_HANDOFF', 'DECISION_MEDIATION_RESULT', 'DECISION_NOTICE'):
                for ref in self._refs(state, kind):
                    materials[ref] = self.artifacts.read(ref)
                    if kind == 'MAJOR_PHASE_PROMOTION':
                        applied = self.artifacts.read_json(ref)['updated_ref']
                        materials[applied] = self.artifacts.read(applied)
        if node in {Node.STAGE_CLOSE_SYNC, Node.ROLE_MEMORY_CONSOLIDATION}:
            if not state.stage_knowledge_ref:
                raise WorkflowError('Program relevance and memory require actual readable Stage Knowledge first')
            materials[state.stage_knowledge_ref] = self.artifacts.read(state.stage_knowledge_ref)
        if node == Node.PROMOTER_RESULT_REVIEW:
            native = self._native_test_material(state)
            if native is not None:
                materials['HOST_NATIVE_FIXED_TESTS'] = json.dumps(native, ensure_ascii=False)
        if node in {Node.CONSTRAINT_DRAFT, Node.DISCUSS_NORMAL, Node.CONSTRAINT_FINALIZE, Node.EXECUTOR_IMPLEMENT}:
            capabilities = getattr(self.executor, 'execution_capabilities', None)
            if callable(capabilities):
                materials['HOST_EXECUTOR_CAPABILITIES'] = json.dumps(capabilities(state.as_dict()), ensure_ascii=False)
        if node in {Node.DECISION_MEDIATION, Node.PROMOTER_RESULT_REVIEW}:
            for ref in self._refs(state, 'HOST_NATIVE_EXECUTOR_ADMISSION'):
                fact = self.artifacts.read_json(ref)
                if fact.get('task_id') == state.task_id:
                    materials[ref] = self.artifacts.read(ref)  # Historical dispatch observation, not new admission.
        execution_handoff = node == Node.PROMOTER_RESULT_REVIEW
        result_decision_nodes = {Node.DISCUSSANT_DECISION_ANALYSIS.value, Node.DECISION_REVIEW.value,
            Node.DECISION_RE_REVIEW.value, Node.PROMOTER_IMPLEMENTATION_PLAN.value,
            Node.DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW.value, Node.PROMOTER_DECISION_ACCEPTANCE.value}
        active_result = state.latest_execution_report_ref is not None and state.task_id not in state.task_checkpoint_refs
        if node.value in result_decision_nodes and active_result:
            execution_handoff = True
        if node == Node.DECISION_MEDIATION and state.decision_handoff_ref:
            finding = self.artifacts.read_json(state.decision_handoff_ref)
            origin = finding.get('resume_node')
            execution_handoff = origin in {
                Node.EXECUTOR_IMPLEMENT.value, Node.PROMOTER_RESULT_REVIEW.value,
                Node.INDEPENDENT_REVIEW.value, Node.EXECUTOR_LOCAL_COMMIT.value} or (
                    origin in result_decision_nodes and active_result)
        if execution_handoff:
            execution = self._execution_material(state)
            if execution is not None:
                materials['HOST_EXECUTOR_EXECUTION_EVIDENCE'] = json.dumps(execution, ensure_ascii=False)
                materials['HOST_EXECUTOR_POLICY'] = execution['evidence']['policy_json']
                source = self.artifacts.read_json(execution['role_output_ref'])
                tests = (source.get('invocation') or {}).get('host_native_fixed_tests')
                if tests is not None:
                    self.executor.verify_native_test_evidence(state.as_dict(), source['context_ref'], tests)
                    materials['HOST_NATIVE_FIXED_TESTS'] = json.dumps({
                        'report_result_ref': execution['report_result_ref'],
                        'role_output_ref': execution['role_output_ref'], 'receipt': tests}, ensure_ascii=False)
        if node == Node.PROMOTER_RESULT_REVIEW:
            managed = self._managed_selected(state.task_id)
            available = self._review_conversion_available(state)
            materials["HOST_REVIEW_REPAIR_POLICY"] = json.dumps({
                "review_context_conversion_available": available,
                "completed_task_review_refs": [ref for ref in self._refs(state, "INDEPENDENT_REVIEW")
                                               if f"{state.task_id}_INDEPENDENT_REVIEW_" in ref],
                "review_context_ref": state.active_review_context_ref if available else None,
                "ordinary_repair_executor_ref": state.executor_context_ref,
                "managed_findings_only": managed,
                "named_post_repair_review_available": self._owner_post_repair_review_available(state),
            }, ensure_ascii=False)
        if node in {Node.EXECUTOR_IMPLEMENT, Node.PROMOTER_RESULT_REVIEW}:
            evidence = getattr(self.executor, 'managed_test_evidence', lambda task: None)(state.task_id)
            if evidence:
                materials['HOST_MANAGED_FIXED_TESTS'] = json.dumps(evidence, ensure_ascii=False)
            if node == Node.EXECUTOR_IMPLEMENT and getattr(self.executor, 'managed_task', lambda task: False)(state.task_id):
                for kind in ('REPORT_RESULT', 'DECISION'):
                    refs = [ref for ref in self._refs(state, kind) if f'{state.task_id}_' in ref]
                    if refs:
                        materials[refs[-1]] = self.artifacts.read(refs[-1])
        if node == Node.TASK_SELECTION and self._refs(state,'ISSUE_REPAIR_REQUEST'):
            ref = self._refs(state,'ISSUE_REPAIR_REQUEST')[-1]
            materials[ref] = self.artifacts.read(ref)
            materials['HOST_STAGE_ISSUE_REPAIR'] = json.dumps({'request_ref':ref,
                'current_issues':state.stage_issues,'decision_triage':state.issue_triage,
                'duty':'Planner owns the actual authorized repair Intent and named-parent evidence. Unresolved must-fix prevents Stage close; repaired work requires new fresh Stage acceptance.'},ensure_ascii=False)
        if node == Node.STAGE_MACHINE_CLOSE:
            materials["HOST_WORKFLOW_PHASE"] = json.dumps({
                "current_activity": node.value,
                "purpose": "Judge eligibility to perform the remaining Stage close activities",
                "acceptance_refs": self._refs(state, "INDEPENDENT_REVIEW")[-1:],
                "settlement_refs": self._refs(state, "STAGE_ISSUE_LEDGER")[-1:],
                "scheduled_after_this_judgment": [Node.STAGE_KNOWLEDGE.value, Node.STAGE_CLOSE_SYNC.value,
                                                  Node.ROLE_MEMORY_CONSOLIDATION.value, "STAGE_RECORD",
                                                  Node.OWNER_SUMMARY.value, Node.SOFT_ACCEPTANCE_WAIT.value],
                "already_completed_memory_roles": state.memory_completed_roles,
                "owner_accepted": state.owner_accepted,
            }, ensure_ascii=False)
        # Fresh review state omits prior result narrative/report metadata in the caller.
        if node in TASK_NODES and not state.formal_task_intent_ref:
            raise WorkflowError("task activity missing original formal Intent")
        if owner_request_refs:
            if node not in OWNER_INPUT_NODES:
                raise WorkflowError("Owner requests require a permitted responsible role activity")
            requests = [{"reference": ref, **self._owner_request(state, ref)} for ref in owner_request_refs]
            for ref in owner_request_refs:
                materials[ref] = self.artifacts.read(ref)
            materials["HOST_OWNER_REQUESTS"] = json.dumps(requests, ensure_ascii=False)
        if node in FRESH_NODES:
            refs = (state.last_result or {}).get("owner_request_refs", [])
            scopes = [{"request_ref": ref, "scope": value["scope"], "task_id": value["task_id"],
                       "check_focus": value["check_focus"]}
                      for ref in refs if (value := self._owner_request(state, ref))["kind"] == "CHECK"]
            if scopes:
                materials["HOST_OWNER_CHECK_SCOPE"] = json.dumps(scopes, ensure_ascii=False)
        for ref in procedural_authority:
            materials.pop(ref, None)
        verification = getattr(self, 'caller_verification', None)
        if verification is not None:
            materials = verification.materials(state.as_dict(), node.value, materials, self.authority)
        relay = getattr(self, 'caller_relay_verification', None)
        if relay is not None:
            materials = relay.materials(state.as_dict(), node.value, materials)
        return materials

    def _task_intent(self, state: WorkflowState, result: dict[str, Any], owner_request_refs: tuple[str, ...] = ()) -> Node:
        intent = result["intent"]
        if intent is None:
            raise WorkflowError("Promoter task selection omitted structured Intent")
        task_id = identity(intent["task_id"])
        prior_task, prior_intent = state.task_id, state.formal_task_intent_ref
        parent = intent['relationship']['parent_task_id'] if intent['relationship'] else prior_task if state.active_blocker_id else None
        family = self._allowance_family(state, parent) if parent else task_id
        self.preflight_task(task_id, intent['relationship'])
        if task_id in state.used_task_ids:
            raise WorkflowError("duplicate task ID")
        # Formal planning/Decision evidence is a legitimate Intent reference, not
        # an additional Host permission grant. Require an actual authority anchor
        # and accept only materials explicitly supplied to this invocation.
        supplied_refs = self._materials(state, Node(state.current_node), owner_request_refs)
        if (not intent["scope"] or not intent["authority_refs"] or
                not any(ref in self.authority for ref in intent["authority_refs"]) or
                any(ref not in supplied_refs for ref in intent["authority_refs"])):
            raise WorkflowError("Intent missing authorized scope/material references")
        if intent["workflow_path"] == "FAST":
            if not intent["fast_authorization_ref"] or intent["fast_authorization_ref"] not in self.authority or not intent["execution_input"]:
                raise WorkflowError("Fast Path lacks explicit authorization/execution input")
            if state.active_blocker_id:
                raise WorkflowError("Fast Path cannot bypass an unresolved blocker")
        if state.pending_override_task_id is not None:
            self._clear_override(state)
        state.task_id = task_id
        if intent['relationship']:
            state.task_relationships[task_id] = intent['relationship']
        if state.pending_override and state.pending_override["activity"] in {n.value for n in TASK_NODES}:
            state.pending_override_task_id = task_id
        state.used_task_ids.append(task_id)
        state.workflow_path = intent["workflow_path"]
        state.formal_task_intent_ref = self.artifacts.save("TASK_INTENT", json.dumps(intent, ensure_ascii=False), task_id=task_id)
        state.artifact_refs.setdefault("TASK_INTENT", []).append(state.formal_task_intent_ref)
        binding = self.artifacts.save('DECISION', json.dumps({'origin': 'HOST_ALLOWANCE_FAMILY',
            'task_id': task_id, 'family_task_id': family, 'intent_ref': state.formal_task_intent_ref,
            'parent_task_id': parent, 'parent_ref': intent['relationship']['parent_ref'] if intent['relationship'] else prior_intent if parent else None,
            'blocker_id': state.active_blocker_id}, ensure_ascii=False), task_id=task_id)
        state.artifact_refs.setdefault('DECISION', []).append(binding)
        state.artifact_refs.setdefault('HOST_ALLOWANCE_FAMILY', []).append(binding)
        state.formal_constraint_ref = state.latest_execution_report_ref = state.acceptance_ref = None
        state.commit_receipt = None
        if not state.active_blocker_id:
            state.arbitration_used = state.independent_review_used = state.decision_re_review_used = False
        state.normal_repair_used = state.decision_new_basis_used = state.decision_treatment_used = False
        if state.active_blocker_id:
            entry = state.blocker_ledger[state.active_blocker_id]
            state.normal_repair_used, state.decision_new_basis_used = entry["repair_used"], entry["new_basis_used"]
            state.decision_treatment_used = entry["decision_treatment_used"]
        required_history = [source for source in self.history_sources.values() if source.recipient_task_id == task_id]
        if required_history:
            candidate, _ = self._prepare_allowance_history(state, required_history[0].name)
            state.artifact_refs = candidate.artifact_refs
        totals = self._allowance_totals(state)
        state.normal_repair_used |= bool(totals['repair'])
        state.decision_new_basis_used |= bool(totals['new_basis'])
        state.decision_treatment_used |= bool(totals['treatment'])
        if intent["model_override"]:
            self._set_override(state, intent["model_override"], task_id)
        if state.workflow_path == "FAST":
            state.formal_constraint_ref = self.artifacts.save("FINAL_TASK_CONSTRAINT", intent["execution_input"], task_id=task_id)
            state.artifact_refs.setdefault("FINAL_TASK_CONSTRAINT", []).append(state.formal_constraint_ref)
            return Node.EXECUTOR_IMPLEMENT
        return Node.CONSTRAINT_DRAFT

    @staticmethod
    def _clear_override(state: WorkflowState) -> None:
        state.pending_override = None
        state.pending_override_task_id = None

    @staticmethod
    def _set_override(state: WorkflowState, override: dict[str, Any], task_id: str | None) -> None:
        state.pending_override = copy.deepcopy(override)
        # Ownership follows the target activity, not the issuing Role's node.
        state.pending_override_task_id = task_id if Node(override["activity"]) in TASK_NODES else None

    def _take_override(self, state: WorkflowState, node: Node) -> dict[str, Any] | None:
        override = state.pending_override
        if override is None or override["activity"] != node.value:
            return None
        if state.pending_override_task_id is not None and state.pending_override_task_id != state.task_id:
            raise WorkflowError("override belongs to a different Task")
        # Consume this object before invoking. The result may create a new object.
        self._clear_override(state)
        return override

    def _blocker(self, state: WorkflowState, result: dict[str, Any]) -> dict[str, Any]:
        key = result["blocker_id"] or state.active_blocker_id
        if not key:
            raise WorkflowError("repair/Decision requires explicit stable blocker identity")
        if state.active_blocker_id and key != state.active_blocker_id:
            raise WorkflowError("unresolved blocker cannot be renamed to reset retries")
        state.active_blocker_id = key
        entry = state.blocker_ledger.setdefault(key, {"repair_used": False, "new_basis_used": False,
                                                    "decision_treatment_used": False, "decision_flow_used": False, "basis_id": None})
        totals = self._allowance_totals(state)
        entry['repair_used'] |= bool(totals['repair'])
        entry['new_basis_used'] |= bool(totals['new_basis'])
        entry['decision_treatment_used'] |= bool(totals['treatment'])
        entry['decision_flow_used'] |= bool(totals['decision_flow'])
        state.normal_repair_used, state.decision_new_basis_used = entry["repair_used"], entry["new_basis_used"]
        state.decision_treatment_used = entry["decision_treatment_used"]
        return entry

    def _allowance_family(self, state, task=None, *, require_source=True):
        task = task or state.task_id
        if not task:
            return state.stage_id
        bindings = {}
        for ref in state.artifact_refs.get('HOST_ALLOWANCE_FAMILY', []):
            value = self.artifacts.read_json(ref)
            if (set(value) != {'origin', 'task_id', 'family_task_id', 'intent_ref', 'parent_task_id', 'parent_ref', 'blocker_id'}
                    or ref not in state.artifact_refs.get('DECISION', [])
                    or value['intent_ref'] not in state.artifact_refs.get('TASK_INTENT', [])):
                raise WorkflowError('allowance family lacks registered original sources')
            self.artifacts.assert_task_reference(ref, 'DECISION', value['task_id'])
            if value.get('origin') != 'HOST_ALLOWANCE_FAMILY' or value['task_id'] in bindings:
                raise WorkflowError('invalid or duplicate allowance family binding')
            intent = self.artifacts.read_json(value['intent_ref'])
            self.artifacts.assert_task_reference(value['intent_ref'], 'TASK_INTENT', value['task_id'])
            if intent['task_id'] != value['task_id'] or value['task_id'] not in state.used_task_ids:
                raise WorkflowError('allowance family is not actual selected Task')
            relation = state.task_relationships.get(value['task_id'])
            if (relation != intent['relationship'] or relation and
                    (value['parent_task_id'], value['parent_ref']) != (relation['parent_task_id'], relation['parent_ref'])):
                raise WorkflowError('allowance relationship differs from original Intent source')
            bindings[value['task_id']] = value
        if require_source and task in state.used_task_ids and task not in bindings:
            raise WorkflowError('legacy Task lacks actual allowance family source; directed recovery required')
        seen = set()
        while task in state.task_relationships or (task in bindings and bindings[task]['parent_task_id']):
            if task in seen:
                raise WorkflowError('allowance causal family cycle')
            seen.add(task)
            relation = state.task_relationships.get(task)
            parent = relation['parent_task_id'] if relation else bindings[task]['parent_task_id']
            ref = relation['parent_ref'] if relation else bindings[task]['parent_ref']
            if parent not in state.used_task_ids or ref not in {r for refs in state.artifact_refs.values() for r in refs}:
                raise WorkflowError('allowance parent is not saved actual work')
            if require_source and parent not in bindings:
                raise WorkflowError('legacy parent lacks actual allowance family source; directed recovery required')
            bound = False
            for kind in ('TASK_INTENT', 'FINAL_TASK_CONSTRAINT', 'EXECUTION_REPORT', 'DECISION'):
                try:
                    self.artifacts.assert_task_reference(ref, kind, parent)
                    bound = True
                    break
                except WorkflowError:
                    continue
            if not bound:
                raise WorkflowError('allowance causal source does not belong to named parent')
            self.artifacts.read(ref)
            task = parent
        histories = self._history_receipts(state)
        inherited = {value['family_task_id'] for value in histories if value['recipient_task_id'] == task}
        required = any(source.recipient_task_id == task for source in self.history_sources.values())
        if len(inherited) > 1 or required and not inherited:
            raise WorkflowError('required Host allowance history missing or family conflict')
        family = next(iter(inherited), task)
        for child in seen | {task}:
            expected = task if child == task else family
            if child in bindings and bindings[child]['family_task_id'] != expected:
                raise WorkflowError('allowance family binding drift')
        return family

    def _allowance_workspace(self):
        return getattr(self, '_history_workspace', self.stage_grant.workspace)

    def _check_history_endpoint(self):
        if not getattr(self, '_history_read_only', False):
            self.grant()  # Actual recipient Host policy, authority and Grant.
            if (self.store.project, self.store.stage_id) != (self.state.project, self.state.stage_id):
                raise WorkflowError('allowance history recipient Store identity mismatch')
            return
        value = dict(self.state.active_grant)
        for key in ('stage_ids', 'series_ids', 'task_ids'):
            value[key] = tuple(value[key])
        value['relationships'] = tuple(value['relationships'].items())
        grant = ScopeGrant(**value)
        grant.validate()
        if (grant.project != self.state.project or self.state.stage_id not in grant.stage_ids
                or grant.workspace != self._allowance_workspace()
                or digest(self.authority.get(grant.authority_ref, '')) != grant.authority_sha256):
            raise WorkflowError('allowance history source Grant/authority identity mismatch')

    def _history_receipts(self, state):
        if self._allowance_write_failed:
            raise WorkflowError('allowance persistence failed; reconstruct from durable evidence')
        receipts, names = [], set()
        for ref in state.artifact_refs.get('HOST_ALLOWANCE_HISTORY', []):
            value = self.artifacts.read_json(ref)
            name = value.get('source', {}).get('name')
            source = self.history_sources.get(name)
            if source is None or name in names:
                raise WorkflowError('allowance history lacks unique configured Host source')
            names.add(name)
            expected = self._history_receipt(source, source.snapshot(self))
            if (value != expected or ref not in state.artifact_refs.get('DECISION', [])
                    or value['recipient_task_id'] not in state.used_task_ids):
                raise WorkflowError('allowance history receipt/source/recipient mismatch')
            self.artifacts.assert_task_reference(ref, 'DECISION', value['recipient_task_id'])
            receipts.append(value)
        # Required predecessors cannot silently disappear on a reconfigured Host.
        for source in self.history_sources.values():
            if source.recipient_task_id in state.used_task_ids and source.name not in names:
                raise WorkflowError('required Host allowance history source not imported')
        for left in receipts:
            for right in receipts:
                if left['family_task_id'] != right['family_task_id']:
                    continue
                a = evidence_ids(left['source'])
                b = evidence_ids(right['source'])
                if not (a <= b or b <= a):
                    raise WorkflowError('allowance history sources are not one linear lineage')
        return receipts

    def _history_receipt(self, source, snapshot):
        return {'origin': 'HOST_ALLOWANCE_HISTORY', 'project': self.state.project,
                'stage_id': self.state.stage_id, 'workspace': self._allowance_workspace(),
                'recipient_store_path': str(self.store.path.resolve()),
                'recipient_records_root': str(self.artifacts.root.resolve()),
                'recipient_task_id': source.recipient_task_id,
                'family_task_id': snapshot['family_task_id'], 'source': snapshot}

    def _allowance_events(self, state, family):
        histories = [v for v in self._history_receipts(state) if v['family_task_id'] == family]
        groups = [v['source']['events'] for v in histories]
        prefix = max((v['source']['used_lower_bounds']['implementation'] for v in histories), default=0)
        local = []
        for ref in state.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION', []):
            value = self.artifacts.read_json(ref)
            if value['family_task_id'] != family:
                continue
            local.append({'reference': ref, 'store_path': str(self.store.path.resolve()),
                          'project': state.project, 'stage_id': state.stage_id, **value})
        reports = self._allowance_reports(state, family)
        return merge_events([*groups, local], reports=reports,
                            implementation_units=self._allowance_report_count(state, family, reports),
                            verified_implementation_prefix=prefix)

    def _allowance_reports(self, state, family):
        groups = [v['source']['reports'] for v in self._history_receipts(state) if v['family_task_id'] == family]
        local = []
        refs = state.artifact_refs.get('REPORT_RESULT', [])
        if len(refs) != len(set(refs)):
            raise WorkflowError('duplicate Host report evidence')
        for ref in refs:
            if ref not in state.artifact_refs.get('DECISION', []):
                raise WorkflowError('allowance report lacks Host registration')
            for task in state.used_task_ids:
                try:
                    self.artifacts.assert_task_reference(ref, 'DECISION', task)
                except WorkflowError:
                    continue
                break
            else:
                raise WorkflowError('allowance report Task/Stage identity mismatch')
            value = self.artifacts.read_json(ref)
            validate(value, result_schema(Node.EXECUTOR_IMPLEMENT))
            if self._allowance_family(state, task, require_source=False) == family:
                local.append({'reference': ref, 'store_path': str(self.store.path.resolve()),
                              'project': state.project, 'stage_id': state.stage_id, 'task_id': task})
        return merge_reports([*groups, local])

    def _allowance_report_count(self, state, family, reports=None):
        from .allowance_history import count_report_units, report_unit
        def resolve(report):
            if report['store_path'] == str(self.store.path.resolve()):
                return report_unit(state, self.store, self.artifacts, report, self._allowance_workspace())
            sources = [s for s in self.history_sources.values() if s.contains_report_store(report['store_path'])]
            if not sources:
                raise WorkflowError('report unit lacks configured original Host source')
            units = {source.report_unit(report) for source in sources}
            if len(units) != 1:
                raise WorkflowError('report unit source conflict')
            return units.pop()
        return count_report_units(self._allowance_reports(state, family) if reports is None else reports, resolve)

    def _persist_native_admission(self, state, reference):
        candidate = copy.deepcopy(state)
        alias = 'HOST_NATIVE_EXECUTOR_ADMISSION'
        for key in ('DECISION', alias):
            candidate.artifact_refs.setdefault(key, []).append(reference)
        self.store.save(candidate)
        for target in (state, self.state):
            for key in ('DECISION', alias):
                if reference not in target.artifact_refs.setdefault(key, []):
                    target.artifact_refs[key].append(reference)

    def _persist_allowance(self, state, alias, reference):
        candidate = copy.deepcopy(state)
        for key in ('DECISION', alias):
            candidate.artifact_refs.setdefault(key, []).append(reference)
        try:
            self.store.save(candidate)
        except Exception:
            # replace may have succeeded before an I/O error was reported. Never
            # authorize from this instance's uncertain in-memory outcome.
            self._allowance_write_failed = True
            raise
        for target in (state, self.state):
            for key in ('DECISION', alias):
                if reference not in target.artifact_refs.setdefault(key, []):
                    target.artifact_refs[key].append(reference)

    def import_allowance_history(self, source_name):
        """Host-only consumption import. No State/Grant/context/proof migration."""
        if self._busy or self.state.in_flight_activity or self._allowance_write_failed:
            raise WorkflowError('history import requires quiescent durable Host state')
        candidate, result = self._prepare_allowance_history(self.state, source_name)
        try:
            self.store.save(candidate)
        except Exception:
            self._allowance_write_failed = True
            raise
        self.state = candidate
        return result

    def _prepare_allowance_history(self, state, source_name):
        source = self.history_sources.get(source_name)
        if source is None or source.recipient_task_id != state.task_id:
            raise WorkflowError('history import requires configured Host source and exact recipient')
        bindings = [self.artifacts.read_json(ref) for ref in state.artifact_refs.get('HOST_ALLOWANCE_FAMILY', [])
                    if self.artifacts.read_json(ref).get('task_id') == state.task_id]
        if (state.status != 'RUNNING' or len(bindings) != 1
                or bindings[0]['family_task_id'] != state.task_id
                or any(bindings[0][key] is not None for key in ('parent_task_id', 'parent_ref', 'blocker_id'))):
            raise WorkflowError('history recipient must be a new independent selected activity')
        snapshot = source.snapshot(self)
        expected = self._history_receipt(source, snapshot)
        for ref in state.artifact_refs.get('HOST_ALLOWANCE_HISTORY', []):
            old = self.artifacts.read_json(ref)
            if old.get('source', {}).get('name') == source_name:
                if old != expected:
                    raise WorkflowError('allowance history source identity reused')
                self._allowance_totals(state)
                return copy.deepcopy(state), ref
        # A new recipient starts with its original local family. History must be
        # attached before any consumption/capacity grant in that local family.
        for alias in ('HOST_ALLOWANCE_CONSUMPTION', 'HOST_ALLOWANCE_GRANT'):
            if any(self.artifacts.read_json(ref)['task_id'] == state.task_id
                   for ref in state.artifact_refs.get(alias, [])):
                raise WorkflowError('history must be imported before recipient spend or capacity')
        # Validate the full candidate before publishing even an orphan receipt.
        # Pending sources are checked together; importing a configured set is one
        # bounded operation so no intermediate incomplete history is admissible.
        pending = []
        for item in self.history_sources.values():
            if item.recipient_task_id == state.task_id:
                pending.append((item, self._history_receipt(item, item.snapshot(self))))
        families = {value['family_task_id'] for _, value in pending}
        if len(families) != 1:
            raise WorkflowError('allowance history recipient has conflicting families')
        snapshots = [value['source'] for _, value in pending]
        for a in snapshots:
            for b in snapshots:
                if not (evidence_ids(a) <= evidence_ids(b) or evidence_ids(b) <= evidence_ids(a)):
                    raise WorkflowError('allowance history sources are not one linear lineage')
        reports = merge_reports([s['reports'] for s in snapshots])
        merge_events([s['events'] for s in snapshots], reports=reports,
                     implementation_units=self._allowance_report_count(state, next(iter(families)), reports),
                     verified_implementation_prefix=max((s['used_lower_bounds']['implementation'] for s in snapshots), default=0))
        candidate = copy.deepcopy(state)
        result = None
        for item, value in pending:
            ref = self.artifacts.save('DECISION', json.dumps(value, ensure_ascii=False), task_id=state.task_id)
            candidate.artifact_refs.setdefault('DECISION', []).append(ref)
            candidate.artifact_refs.setdefault('HOST_ALLOWANCE_HISTORY', []).append(ref)
            if item.name == source_name:
                result = ref
        self._allowance_totals(candidate)
        return candidate, result

    def _allowance_totals(self, state):
        family = self._allowance_family(state)
        members = [task for task in state.used_task_ids if self._allowance_family(state, task, require_source=False) == family]
        counts = {'implementation': 0, 'repair': 0, 'treatment': 0, 'decision_flow': 0, 'new_basis': 0}
        capacity = {'implementation': 3, 'repair': 1, 'treatment': 1, 'decision_flow': 1}
        blockers = set()
        for alias in ('HOST_ALLOWANCE_CONSUMPTION', 'HOST_ALLOWANCE_GRANT'):
            refs = state.artifact_refs.get(alias, [])
            if len(refs) != len(set(refs)):
                raise WorkflowError('duplicate allowance facts')
            for ref in refs:
                if ref not in state.artifact_refs.get('DECISION', []):
                    raise WorkflowError('allowance fact lacks Host registration')
                value = self.artifacts.read_json(ref)
                task = value['task_id']
                self.artifacts.assert_task_reference(ref, 'DECISION', task or state.stage_id)
                expected_family = self._allowance_family(state, task) if task else state.stage_id
                if value['family_task_id'] != expected_family or value['origin'] != alias:
                    raise WorkflowError('allowance fact identity mismatch')
                if value['family_task_id'] != family:
                    continue
                if alias == 'HOST_ALLOWANCE_GRANT':
                    authority = self.authority.get(value['authority_ref'])
                    if not authority or digest(authority) != value['authority_sha256']:
                        raise WorkflowError('saved allowance authority is missing or changed')
                    for key, extra in value['additional_capacity'].items():
                        if key not in capacity or type(extra) is not int or extra < 0:
                            raise WorkflowError('invalid additional allowance capacity')
                        capacity[key] += extra
                else:
                    if (set(value) != {'origin', 'task_id', 'family_task_id', 'kind', 'ordinal',
                                      'blocker_id', 'source', 'dispatch_status'}
                            or value['kind'] not in counts or type(value['ordinal']) is not int or value['ordinal'] < 1
                            or not isinstance(value['source'], dict) or not value['source']
                            or value['dispatch_status'] != ('RESERVED_BEFORE_CALL' if value['kind'] == 'implementation'
                                                           else 'FORMAL_ROUTE_GRANTED')):
                        raise WorkflowError('invalid allowance consumption')
                    counts[value['kind']] = max(counts[value['kind']], value['ordinal'])
                    if value['blocker_id']:
                        blockers.add(value['blocker_id'])
        if state.active_blocker_id:
            blockers.add(state.active_blocker_id)
        for key in blockers:
            entry = state.blocker_ledger.get(key, {})
            for kind, flag in (('repair', 'repair_used'), ('new_basis', 'new_basis_used'),
                               ('treatment', 'decision_treatment_used'), ('decision_flow', 'decision_flow_used')):
                counts[kind] = max(counts[kind], int(entry.get(flag, False)))
        events = self._allowance_events(state, family)
        for kind in counts:
            counts[kind] = max(counts[kind], max((event['ordinal'] for event in events if event['kind'] == kind), default=0))
        counts['implementation'] = max(counts['implementation'], self._allowance_report_count(state, family))
        return {**counts, 'capacity': capacity, 'family_task_id': family}

    def _allowance_available(self, state, kind):
        totals = self._allowance_totals(state)
        return totals[kind] < totals['capacity'][kind]

    def _consume_allowance(self, state, kind, source):
        totals = self._allowance_totals(state)
        if kind != 'new_basis' and totals[kind] >= totals['capacity'][kind]:
            raise WorkflowError(f'{kind} allowance exhausted for actual causal family')
        value = {'origin': 'HOST_ALLOWANCE_CONSUMPTION', 'task_id': state.task_id,
            'family_task_id': totals['family_task_id'], 'kind': kind, 'ordinal': totals[kind] + 1,
            'blocker_id': state.active_blocker_id, 'source': source,
            'dispatch_status': 'RESERVED_BEFORE_CALL' if kind == 'implementation' else 'FORMAL_ROUTE_GRANTED'}
        ref = self.artifacts.save('DECISION', json.dumps(value, ensure_ascii=False), task_id=state.task_id)
        self._persist_allowance(state, 'HOST_ALLOWANCE_CONSUMPTION', ref)
        return ref

    def apply_owner_allowance(self, reference):
        """Host-only explicit capacity addition; never unblocks or resets history."""
        if self._busy or self.state.in_flight_activity or reference not in self.authority:
            raise WorkflowError('allowance requires quiescent explicit Host authority')
        raw = self.authority[reference]
        value = json.loads(raw, object_pairs_hook=unique_json_object)
        expected = {'origin', 'authorization_id', 'project', 'stage_id', 'workspace', 'family_task_id',
                    'recipient_task_id', 'scope_authority_ref', 'scope_authority_sha256', 'additional_capacity', 'reason'}
        grant = self.grant()
        if (set(value) != expected or value['origin'] != 'OWNER_ALLOWANCE_AUTHORIZATION'
                or (value['project'], value['stage_id'], value['workspace']) !=
                   (self.state.project, self.state.stage_id, str(self.executor.stage_policy.workspace.resolve()))
                or value['recipient_task_id'] != self.state.task_id
                or value['family_task_id'] != self._allowance_family(self.state)
                or (value['scope_authority_ref'], value['scope_authority_sha256']) != (grant.authority_ref, grant.authority_sha256)
                or not isinstance(value['reason'], str) or not value['reason'].strip()):
            raise WorkflowError('explicit Owner allowance scope/family/recipient mismatch')
        identity(value['authorization_id'])
        self.preflight_task(self.state.task_id)
        extra = value['additional_capacity']
        if (not isinstance(extra, dict) or set(extra) != {'implementation', 'repair', 'treatment', 'decision_flow'}
                or any(type(n) is not int or n < 0 for n in extra.values()) or not any(extra.values())):
            raise WorkflowError('explicit positive capacity addition required')
        for ref in self.state.artifact_refs.get('HOST_ALLOWANCE_GRANT', []):
            old = self.artifacts.read_json(ref)
            if old['authorization_id'] == value['authorization_id']:
                if old['authority_sha256'] != digest(raw) or old['authority_ref'] != reference:
                    raise WorkflowError('Owner allowance authorization identity was reused')
                return ref
        receipt = {'origin': 'HOST_ALLOWANCE_GRANT', 'task_id': self.state.task_id,
            'family_task_id': value['family_task_id'], 'authorization_id': value['authorization_id'],
            'authority_ref': reference, 'authority_sha256': digest(raw), 'additional_capacity': extra}
        ref = self.artifacts.save('DECISION', json.dumps(receipt), task_id=self.state.task_id)
        self._persist_allowance(self.state, 'HOST_ALLOWANCE_GRANT', ref)
        return ref

    def _enter_decision(self, state: WorkflowState, result: dict[str, Any]) -> Node:
        entry = self._blocker(state, result)
        if not self._allowance_available(state, 'decision_flow'):
            return self._host_escalation(state, Node(state.current_node), 'TRUE_UNRESOLVED_BLOCKER', 'Finite Decision flow already used for this stable blocker.')
        self._consume_allowance(state, 'decision_flow', result)
        entry["decision_flow_used"] = True
        return Node.DISCUSSANT_DECISION_ANALYSIS

    def _executor_report_eligible(self, state, report):
        """One qualification check at acceptance, commit and completion.

        Managed eligibility comes from the owned Host proof and its saved
        output, never a worker-selected backend or worker evidence booleans.
        The original Codex report retains its original five-evidence gate.
        """
        if getattr(self.executor, 'managed_task', lambda task: False)(state.task_id):
            from .allowance_history import report_outputs
            reports = self._refs(state, 'REPORT_RESULT')
            if not reports or self.artifacts.read_json(reports[-1]) != report:
                raise WorkflowError('managed report disagrees with current formal report')
            output_ref = report_outputs(state, self.artifacts).get(reports[-1])
            if output_ref is None:
                raise WorkflowError('managed report lacks original Host output binding')
            output = self.artifacts.read_json(output_ref)
            if output.get('context_ref') != state.executor_context_ref:
                raise WorkflowError('managed saved report/context disagrees with current Executor output')
            saved = (output.get('invocation') or {}).get('host_fixed_tests')
            self.executor.verify_managed_report(state.task_id, state.executor_context_ref, saved)
            return report.get('action') == 'REPORT_READY'
        return bool(report.get('evidence') and all(report['evidence'].values()))

    def _verify_commit_gate(self, state: WorkflowState, *, completed: bool = False) -> dict[str, Any]:
        if state.task_id:
            self.preflight_task(state.task_id, state=state)
        if not self.commit_authorized or not state.task_id or not state.acceptance_ref:
            raise WorkflowError("commit lacks explicit accepted Task and Stage grant")
        if not completed and (state.commit_receipt or state.task_id in state.task_checkpoint_refs):
            raise WorkflowError("completed Task checkpoint cannot be replayed")
        for ref, kind in ((state.acceptance_ref, "ACCEPTANCE"), (state.formal_constraint_ref, "FINAL_TASK_CONSTRAINT"),
                          (state.latest_execution_report_ref, "EXECUTION_REPORT"),
                          (state.formal_task_intent_ref, "TASK_INTENT")):
            if not ref:
                raise WorkflowError("commit formal input missing")
            self.artifacts.assert_task_reference(ref, kind, state.task_id)
        acceptance = self.artifacts.read_json(state.acceptance_ref)
        validate(acceptance, result_schema(Node.PROMOTER_RESULT_REVIEW))
        if acceptance["action"] != Action.TASK_ACCEPTED.value or not acceptance["evidence"] or not all(acceptance["evidence"].values()):
            raise WorkflowError("saved artifact is not an explicit Promoter acceptance")
        intent = self.artifacts.read_json(state.formal_task_intent_ref)
        validate(intent, INTENT_SCHEMA)
        if intent["task_id"] != state.task_id or not intent["scope"]:
            raise WorkflowError("checkpoint scope/Intent identity is unknown")
        reports = self._refs(state, "REPORT_RESULT")
        if not reports:
            raise WorkflowError("checkpoint lacks saved Executor validation result")
        report_result_ref = reports[-1]
        self.artifacts.assert_task_reference(report_result_ref, "DECISION", state.task_id)
        report = self.artifacts.read_json(report_result_ref)
        validate(report, result_schema(Node.EXECUTOR_IMPLEMENT))
        if report["action"] != "REPORT_READY" or not self._executor_report_eligible(state, report):
            raise WorkflowError("checkpoint has incomplete Executor validation result")
        required_refs = [state.formal_task_intent_ref, state.formal_constraint_ref,
                         state.latest_execution_report_ref, state.acceptance_ref, report_result_ref]
        for artifact in report["artifacts"]:
            refs = self._refs(state, artifact["kind"])
            if not refs:
                raise WorkflowError("required Executor artifact was not saved")
            ref = state.latest_execution_report_ref if artifact["kind"] == "EXECUTION_REPORT" else refs[-1]
            self.artifacts.assert_task_reference(ref, artifact["kind"], state.task_id)
            if self.artifacts.read(ref) != artifact["content"]:
                raise WorkflowError("required Executor artifact disagrees with saved report result")
            if ref not in required_refs:
                required_refs.append(ref)
        if sum(a["kind"] == "EXECUTION_REPORT" for a in report["artifacts"]) != 1:
            raise WorkflowError("checkpoint missing exactly one required Execution Report")
        for ref in required_refs:
            self.artifacts.read(ref)
        if state.stage_input_ref not in self.authority:
            raise WorkflowError("checkpoint Stage authority is unavailable")
        return {"project": state.project, "stage_id": state.stage_id, "task_id": state.task_id,
                "workspace": str(self.executor.stage_policy.workspace.resolve()) if hasattr(self.executor, "stage_policy") else "",
                "host_context_ref": state.executor_context_ref or "", "stage_input_ref": state.stage_input_ref,
                "stage_input_sha256": hashlib.sha256(self.authority[state.stage_input_ref].encode("utf-8")).hexdigest(),
                "intent_ref": state.formal_task_intent_ref, "final_ref": state.formal_constraint_ref,
                "report_ref": state.latest_execution_report_ref, "acceptance_ref": state.acceptance_ref,
                "report_result_ref": report_result_ref, "scope": intent["scope"], "required_artifact_refs": required_refs}

    def _verify_no_commit(self, state: WorkflowState, evidence: dict[str, Any]) -> None:
        binding = self._verify_commit_gate(state, completed=True)
        require_no_commit_evidence(evidence, binding=binding)
        verify_saved_no_commit(self.artifacts, evidence, project=state.project, stage_id=state.stage_id,
                               task_id=state.task_id, workspace=self.executor.stage_policy.workspace, authority=self.authority)
        if not hasattr(self.executor, "verify_no_dev_change"):
            raise WorkflowError("NO_DEV_CHANGE lacks a live Host verifier")
        self.executor.verify_no_dev_change(evidence, binding)

    def _checkpoint_records(self, state: WorkflowState) -> tuple[dict[str, Any], dict[str, Any]]:
        history = task_closure_history(self.artifacts, state.used_task_ids, state.artifact_refs,
                                       state.task_checkpoint_refs, state.task_relationships)
        if {task for task, row in history.items() if row['closure_required']} != set(state.task_checkpoint_refs):
            raise WorkflowError('closure-required Task lacks a checkpoint; explicit supersession may be required')
        commits, no_commits = {}, {}
        for task, ref in state.task_checkpoint_refs.items():
            self.artifacts.assert_task_reference(ref, "DECISION", task)
            value = self.artifacts.read_json(ref)
            if value.get("task_id") != task:
                raise WorkflowError("Task checkpoint identity mismatch")
            if value.get("origin") == "HOST_COMMIT_RECEIPT" and set(value) == {"origin", "task_id", "receipt"}:
                receipt = value["receipt"]
                if not isinstance(receipt, dict) or not receipt.get("commit_hash") or not receipt.get("staged_files"):
                    raise WorkflowError("invalid saved Host commit receipt")
                commits[task] = receipt
            elif value.get("origin") == "HOST_NO_DEV_CHANGE" and set(value) == {"origin", "task_id", "evidence"}:
                evidence = value["evidence"]
                verify_saved_no_commit(self.artifacts, evidence, project=state.project, stage_id=state.stage_id,
                                       task_id=task, workspace=self.executor.stage_policy.workspace, authority=self.authority)
                no_commits[task] = {"reference": ref, "disposition": "NO_DEV_CHANGE", "evidence": evidence}
            else:
                raise WorkflowError("unknown checkpoint disposition")
        return commits, no_commits

    def _prepare_mediation(self, state, node, actor, result_ref, escalation, *, owner_event=None):
        """Save compact provenance and actual limits; never select work or infer permission."""
        expected = (actor.value, node.value, state.stage_id, state.task_id)
        if tuple(escalation[k] for k in ('origin_role', 'origin_activity', 'stage_id', 'task_id')) != expected:
            raise WorkflowError('escalation origin does not match the actual producing activity')
        known = set(self.authority) | {ref for refs in state.artifact_refs.values() for ref in refs}
        refs = [result_ref, *escalation['evidence_refs']]
        if not escalation['reason'].strip() or any(ref not in known for ref in refs):
            raise WorkflowError('escalation requires actual formal provenance')
        for ref in refs:
            if ref not in self.authority:
                self.artifacts.read(ref)
        key = '|'.join((state.stage_id, state.task_id or '', actor.value, node.value, escalation['category'], state.active_blocker_id or ''))
        count = state.mediation_counts.get(key, 0)
        category = 'TRUE_UNRESOLVED_BLOCKER' if count and escalation['category'] != 'OWNER_INPUT' else escalation['category']
        state.mediation_counts[key] = count + 1
        value = {'origin': 'HOST_INTERNAL_ESCALATION', **escalation, 'category': category,
            'original_result_ref': result_ref, 'resume_node': node.value,
            'actual_scope': state.active_grant, 'blocker_id': state.active_blocker_id,
            'retry_limits': copy.deepcopy(state.blocker_ledger), 'prior_mediation_count': count,
            'owner_event': owner_event, 'permissions_expanded': False}
        state.decision_handoff_ref = self._save_artifact(state, 'DECISION', json.dumps(value, ensure_ascii=False))
        state.artifact_refs.setdefault('DECISION_HANDOFF', []).append(state.decision_handoff_ref)

    def queue_owner_mediation(self, ref, *, event=None):
        """Known-effect Host input interrupts a soft window before any execution."""
        if self._busy or self.state.in_flight_activity or Node(self.state.current_node) not in WINDOW_NODES:
            raise WorkflowError('Owner window input requires a quiescent current window')
        if event is None:
            self._owner_request(self.state, ref)
        else:
            value = self.artifacts.read_json(ref)
            request = value.get('request', {})
            if (event != 'COMPLETE_STAGE_REVIEW' or self.state.current_node != Node.SOFT_REVIEW_WAIT.value
                    or value.get('origin') != 'HOST_OWNER_WINDOW_REVIEW'
                    or value.get('notice_ref') != self.state.stage_notice_ref
                    or request.get('event') != event or request.get('kind') != 'GATE'
                    or (request.get('project'), request.get('stage_id'), request.get('task_id')) !=
                       (self.state.project, self.state.stage_id, self.state.task_id)
                    or not request.get('direction', '').strip() or not request.get('evidence_refs')):
                raise WorkflowError('explicit Owner early-review receipt binding is invalid')
            known = set(self.authority) | {r for refs in self.state.artifact_refs.values() for r in refs}
            if any(source not in known for source in request['evidence_refs']):
                raise WorkflowError('Owner early-review evidence is unavailable')
            for source in request['evidence_refs']:
                if source not in self.authority:
                    self.artifacts.read(source)
        state = copy.deepcopy(self.state)
        state.owner_window_refs.append(ref)
        node = Node(state.current_node)
        self._prepare_mediation(state, node, Role.DECISION, ref, {
            'origin_role': Role.DECISION.value, 'origin_activity': node.value,
            'stage_id': state.stage_id, 'task_id': state.task_id, 'category': 'OWNER_INPUT',
            'reason': 'Explicit Owner input interrupted the current soft window.',
            'evidence_refs': [], 'requested_treatment': 'PLANNER_ADJUSTMENT'}, owner_event=event)
        self._move(state, Node.DECISION_MEDIATION)
        self.store.save(state)
        self.state = state

    def _host_escalation(self, state, node, category, reason):
        self._route_escalation = {'origin_role': TABLE[node][0].value, 'origin_activity': node.value,
            'stage_id': state.stage_id, 'task_id': state.task_id, 'category': category,
            'reason': reason, 'evidence_refs': [], 'requested_treatment': 'HARD_GATE'}
        return Node.DECISION_MEDIATION

    def _record_output(self, state, node, invocation):
        assignment = ((invocation.metadata or {}).get('selection') or {}).get('task_assignment')
        if not assignment and node not in {Node.EXECUTOR_IMPLEMENT, Node.INDEPENDENT_REVIEW, Node.PROMOTER_RESULT_REVIEW,
                        Node.DECISION_MEDIATION, Node.DECISION_REVIEW, Node.DECISION_RE_REVIEW}:
            return invocation
        value = {'origin': 'HOST_ROLE_OUTPUT', 'activity': node.value, 'task_id': state.task_id,
                 'context_ref': invocation.context_ref, 'result': invocation.result,
                 'invocation': invocation.metadata}
        ref = self._save_artifact(state, 'DECISION', json.dumps(value, ensure_ascii=False))
        state.artifact_refs.setdefault('ROLE_OUTPUT', []).append(ref)
        self.store.save(state)  # Raw/evidence is durable before any correction call.
        return replace(invocation, host_output_ref=ref)

    def _native_test_material(self, state):
        """Use the current report's original Host output, never model claims."""
        reports = self._refs(state, 'REPORT_RESULT')
        if not reports:
            return None
        from .allowance_history import report_outputs
        report_ref = reports[-1]
        self.artifacts.assert_task_reference(report_ref, 'DECISION', state.task_id)
        output_ref = report_outputs(state, self.artifacts).get(report_ref)
        if output_ref is None:
            raise WorkflowError('native receipt handoff lacks original report output binding')
        self.artifacts.assert_task_reference(output_ref, 'DECISION', state.task_id)
        output = self.artifacts.read_json(output_ref)
        facts = (output.get('invocation') or {}).get('host_native_fixed_tests')
        if facts is None:
            return None
        if (output.get('origin'), output.get('activity'), output.get('task_id')) != (
                'HOST_ROLE_OUTPUT', Node.EXECUTOR_IMPLEMENT.value, state.task_id):
            raise WorkflowError('native receipt handoff original output mismatch')
        if output.get('result') != self.artifacts.read_json(report_ref):
            raise WorkflowError('native receipt handoff report/output content mismatch')
        verify = getattr(self.executor, 'verify_native_test_evidence', None)
        if not callable(verify):
            raise WorkflowError('native receipt handoff has no trusted proof verifier')
        verify(state.as_dict(), output.get('context_ref'), facts)
        return {'report_result_ref': report_ref, 'role_output_ref': output_ref, 'receipt': facts}

    def _execution_material(self, state):
        """Bind captured Host policy/turn facts to the actual published report."""
        # Stage history survives Task selection. This is only a candidate
        # identity filter; exact Task/kind/hash and Host bindings are checked below.
        reports = [ref for ref in self._refs(state, 'REPORT_RESULT') if state.task_id and
                   Path(ref.rsplit('#sha256=', 1)[0]).name.startswith(state.task_id + '_DECISION_')]
        if not reports:
            if (state.latest_execution_report_ref or
                    getattr(self.executor, '_execution_evidence', {}).get(state.task_id)):
                raise WorkflowError('current execution evidence lacks its Task report binding')
            return None
        from .allowance_history import report_outputs
        report_ref = reports[-1]
        self.artifacts.assert_task_reference(report_ref, 'DECISION', state.task_id)
        output_ref = report_outputs(state, self.artifacts).get(report_ref)
        if output_ref is None:
            raise WorkflowError('execution evidence lacks original report output binding')
        self.artifacts.assert_task_reference(output_ref, 'DECISION', state.task_id)
        output = self.artifacts.read_json(output_ref)
        evidence = (output.get('invocation') or {}).get('host_execution_evidence')
        if evidence is None:
            if getattr(self.executor, '_execution_evidence', {}).get(state.task_id):
                if output.get('result', {}).get('action') == 'REPORT_READY':
                    raise WorkflowError('execution evidence missing from original report output')
                # A report-format escalation is not an execution. Supply its
                # actual earlier Host output to Decision, never model-restored facts.
                for candidate in reversed(self._refs(state, 'ROLE_OUTPUT')):
                    source = self.artifacts.read_json(candidate)
                    captured = (source.get('invocation') or {}).get('host_execution_evidence')
                    if (captured is not None and
                            (source.get('origin'), source.get('activity'), source.get('task_id')) ==
                            ('HOST_ROLE_OUTPUT', Node.EXECUTOR_IMPLEMENT.value, state.task_id)):
                        self.artifacts.assert_task_reference(candidate, 'DECISION', state.task_id)
                        output_ref, output, evidence, report_ref = candidate, source, captured, None
                        break
                if evidence is None:
                    raise WorkflowError('execution escalation lacks original Host output')
            else:
                return None  # Historical/non-app-server adapters are not upgraded to captured evidence.
        if ((output.get('origin'), output.get('activity'), output.get('task_id')) !=
                ('HOST_ROLE_OUTPUT', Node.EXECUTOR_IMPLEMENT.value, state.task_id)
                or report_ref is not None and output.get('result') != self.artifacts.read_json(report_ref)):
            raise WorkflowError('execution evidence original report/output mismatch')
        verify = getattr(self.executor, 'verify_execution_evidence', None)
        if not callable(verify):
            raise WorkflowError('execution evidence has no trusted Host verifier')
        verify(state.as_dict(), output.get('context_ref'), evidence)
        return {'report_result_ref': report_ref, 'role_output_ref': output_ref, 'evidence': evidence}

    def _bind_report_result(self, state, report_ref, invocation):
        output_ref = invocation.host_output_ref
        if output_ref not in state.artifact_refs.get('ROLE_OUTPUT', []):
            raise WorkflowError('report publication requires its actual Host output')
        self.artifacts.assert_task_reference(output_ref, 'DECISION', state.task_id)
        output = self.artifacts.read_json(output_ref)
        if (output.get('origin'), output.get('activity'), output.get('task_id'), output.get('result')) != (
                'HOST_ROLE_OUTPUT', Node.EXECUTOR_IMPLEMENT.value, state.task_id, invocation.result):
            raise WorkflowError('report publication Host output mismatch')
        binding = {'origin': 'HOST_REPORT_OUTPUT_BINDING', 'task_id': state.task_id,
                   'report_result_ref': report_ref, 'role_output_ref': output_ref}
        ref = self._save_artifact(state, 'DECISION', json.dumps(binding, ensure_ascii=False))
        state.artifact_refs.setdefault('HOST_REPORT_OUTPUT_BINDING', []).append(ref)
        state.artifact_refs.setdefault('REPORT_RESULT', []).append(report_ref)

    def _correction(self, state, node, materials, problem, override=None, *, call_state=None,
                    original_output_ref=None):
        key = f'report-correction|{state.task_id}|{node.value}'
        if state.mediation_counts.get(key):
            raise problem
        state.mediation_counts[key] = 1
        self.store.save(state)  # Never replenish the one correction after failure.
        inputs = {**materials, 'HOST_REPORT_CORRECTION': str(problem),
                  'HOST_ORIGINAL_OUTPUT': problem.raw,
                  'HOST_REPORT_ONLY': 'Correct materials once. No implementation, tests, Git or tools. '
                                      'Preserve actual failures/evidence; do not invent missing facts.'}
        actor = TABLE[node][0]
        input_state = call_state if call_state is not None else state.as_dict()
        if original_output_ref is not None:
            if original_output_ref not in state.artifact_refs.get('ROLE_OUTPUT', []):
                raise WorkflowError('report correction requires its recorded original Host output')
            output_owner = state.task_id if node in TASK_NODES else state.stage_id
            self.artifacts.assert_task_reference(original_output_ref, 'DECISION', output_owner)
            output = self.artifacts.read_json(original_output_ref)
            if (output.get('origin'), output.get('activity'), output.get('task_id'), output.get('context_ref')) != (
                    'HOST_ROLE_OUTPUT', node.value, state.task_id, problem.context_ref):
                raise WorkflowError('report correction original Host output mismatch')
            if ((output.get('invocation') or {}).get('raw_output') != problem.raw
                    and json.dumps(output.get('result'), ensure_ascii=False) != problem.raw):
                raise WorkflowError('report correction does not match its original rejected output')
            inputs[original_output_ref] = self.artifacts.read(original_output_ref)
            inputs['HOST_ORIGINAL_ROLE_OUTPUT_REF'] = original_output_ref
            inputs['HOST_REPORT_CORRECTION_EVIDENCE_REFS'] = json.dumps(
                sorted(set(self.authority) | {ref for refs in state.artifact_refs.values() for ref in refs}))
            facts = (output.get('invocation') or {}).get('host_native_fixed_tests')
            execution = (output.get('invocation') or {}).get('host_execution_evidence')
            if node == Node.EXECUTOR_IMPLEMENT and execution is not None:
                evidence_state = {**input_state, 'executor_context_ref': output['context_ref']}
                if input_state.get('executor_context_ref') not in (None, output['context_ref']):
                    raise WorkflowError('execution correction differs from original context')
                if input_state.get('executor_context_ref') is None and input_state.get('latest_execution_report_ref') is not None:
                    raise WorkflowError('published execution correction lacks its bound context')
                self.executor.verify_execution_evidence(evidence_state, output['context_ref'], execution)
                input_state = evidence_state  # Initial handoff has not published the actual Executor context yet.
                inputs['HOST_EXECUTOR_EXECUTION_EVIDENCE'] = json.dumps({
                    'report_result_ref': None, 'role_output_ref': original_output_ref, 'evidence': execution}, ensure_ascii=False)
                inputs['HOST_EXECUTOR_POLICY'] = execution['policy_json']
            if node == Node.EXECUTOR_IMPLEMENT and facts is not None:
                if input_state.get('executor_context_ref') is None:
                    if input_state.get('latest_execution_report_ref') is not None:
                        raise WorkflowError('published native report correction lacks its bound context')
                    # First handoff has not published Executor context or a report.
                    # Bind only this local validation input from the actual saved
                    # Invocation, then keep the public verifier's strong checks.
                    input_state = {**input_state, 'executor_context_ref': output['context_ref']}
                self.executor.verify_native_test_evidence(input_state, output['context_ref'], facts)
                inputs['HOST_NATIVE_FIXED_TESTS'] = json.dumps({
                    'report_result_ref': None, 'role_output_ref': original_output_ref, 'receipt': facts})
        return (self.executor.correct_report(node, input_state, inputs, override) if actor == Role.EXECUTOR else
                self.roles.correct_report(actor, node, input_state, inputs, override))

    def _invoke_handoff(self, state, node, call_state, materials, override):
        actor = TABLE[node][0]
        def checked_handoff(reply, activity=node):
            # The outer step has no Invocation until this boundary returns.
            try:
                self._check_handoff(activity, reply.result, state, reply.context_ref)
            except Exception as problem:
                if getattr(problem, 'safe_observation', None) is None:
                    from .failure_evidence import safe_observation
                    metadata = reply.metadata or {}
                    problem.safe_observation = safe_observation({
                        **metadata.get('safe_observation', {}), 'stage': 'handoff'})
                raise
        reply = None
        try:
            if self._resolved_output(state, node):
                value = self.artifacts.read_json(self._refs(state, 'DECISION_RESOLVED_OUTPUT')[-1])
                metadata = {'origin': 'DECISION_INTERPRETED_OUTPUT'}
                if node == Node.EXECUTOR_IMPLEMENT:
                    original = self._execution_material(state)
                    if original is not None:
                        metadata['host_execution_evidence'] = original['evidence']
                        metadata['original_host_output_ref'] = original['role_output_ref']
                        source = self.artifacts.read_json(original['role_output_ref'])
                        tests = (source.get('invocation') or {}).get('host_native_fixed_tests')
                        if tests is not None:
                            self.executor.verify_native_test_evidence(state.as_dict(), value['context_ref'], tests)
                            metadata['host_native_fixed_tests'] = tests
                reply = Invocation(value['result'], value['context_ref'], metadata=metadata)
            else:
                admission = getattr(self.executor, 'native_admission', None)
                if node == Node.EXECUTOR_IMPLEMENT and admission is not None:
                    with admission.activity(state):
                        reply = self.executor.invoke(node, call_state, materials, override)
                else:
                    reply = (self.executor.invoke(node, call_state, materials, override) if actor == Role.EXECUTOR else
                             self.roles.invoke(actor, node, call_state, materials, override))
            reply = self._record_output(state, node, reply)
            checked_handoff(reply)
        except OutputProblem as problem:
            failed_output = self._record_output(state, node, Invocation({}, problem.context_ref,
                metadata={**(problem.metadata or {}), 'raw_output': problem.raw, 'problem': str(problem)}))
            if node not in {Node.EXECUTOR_IMPLEMENT, Node.INDEPENDENT_REVIEW, Node.PROMOTER_RESULT_REVIEW,
                            Node.DECISION_MEDIATION, Node.DECISION_REVIEW, Node.DECISION_RE_REVIEW}:
                raise
            try:
                original_output_ref = (reply if reply is not None else failed_output).host_output_ref
                reply = self._correction(state, node, materials, problem, override, call_state=call_state,
                                         original_output_ref=original_output_ref)
                reply = self._record_output(state, node, reply)
                checked_handoff(reply)
            except OutputProblem as remaining:
                self._record_output(state, node, Invocation({}, remaining.context_ref,
                    metadata={**(remaining.metadata or {}), 'raw_output': remaining.raw, 'problem': str(remaining)}))
                if actor == Role.DECISION:
                    raise  # No recursive arbitration after the arbitrator's one correction.
                return self._output_escalation(state, node, str(remaining), problem.context_ref)
        except WorkflowError as problem:
            facts = getattr(problem, 'native_test_receipt', None)
            execution = getattr(problem, 'host_execution_evidence', None)
            if node == Node.EXECUTOR_IMPLEMENT and (facts is not None or execution is not None):
                self._record_output(state, node, Invocation({}, problem.context_ref, metadata={
                    'host_native_fixed_tests': facts, 'host_execution_evidence': execution, 'problem': str(problem),
                    'safe_observation': getattr(problem, 'safe_observation', {})}))
            raise
        if node == Node.PROMOTER_RESULT_REVIEW and reply.result['action'] == Action.TASK_ACCEPTED:
            reports = self._refs(state, 'REPORT_RESULT')
            report = self.artifacts.read_json(reports[-1]) if reports else {}
            if not reply.result['evidence'] or not all(reply.result['evidence'].values()) or not self._executor_report_eligible(state, report):
                reply = self._output_escalation(state, node, 'Acceptance needs adequate original report and judgment evidence', reply.context_ref)
        escalation = reply.result.get('escalation')
        if escalation and escalation['requested_treatment'] == 'REPORT_CORRECTION':
            if (node not in {Node.PROMOTER_RESULT_REVIEW, Node.INDEPENDENT_REVIEW}
                    or escalation['category'] != 'INTERNAL_FINDING'
                    or (escalation['origin_role'], escalation['origin_activity'], escalation['stage_id'], escalation['task_id']) !=
                       (actor.value, node.value, state.stage_id, state.task_id)):
                raise WorkflowError('report correction request provenance mismatch')
            if not state.latest_execution_report_ref:
                raise WorkflowError('downstream report correction requires actual original report')
            source = self.artifacts.read_json(self._refs(state, 'REPORT_RESULT')[-1])
            problem = OutputProblem(escalation['reason'], json.dumps(source, ensure_ascii=False), state.executor_context_ref)
            try:
                corrected = self._correction(state, Node.EXECUTOR_IMPLEMENT,
                    self._materials(state, Node.PROMOTER_RESULT_REVIEW), problem)
                corrected = self._record_output(state, Node.EXECUTOR_IMPLEMENT, corrected)
                checked_handoff(corrected, Node.EXECUTOR_IMPLEMENT)
                if corrected.result['action'] != Action.REPORT_READY or corrected.result['escalation']:
                    return self._output_escalation(state, node, 'Original role disputes report completion', reply.context_ref)
                for artifact in corrected.result['artifacts']:
                    self._save_artifact(state, artifact['kind'], artifact['content'])
                ref = self._save_artifact(state, 'DECISION', json.dumps(corrected.result, ensure_ascii=False))
                self._bind_report_result(state, ref, corrected)
                self.store.save(state)
                # The requester judges the supplement. Fresh code review was
                # already completed; do not re-run it or leak reports into it.
                if node == Node.INDEPENDENT_REVIEW:
                    return self._output_escalation(state, node, escalation['reason'], reply.context_ref)
                return self._invoke_handoff(state, node, state.as_dict(), self._materials(state, node), override)
            except OutputProblem as remaining:
                self._record_output(state, Node.EXECUTOR_IMPLEMENT, Invocation({}, remaining.context_ref,
                    metadata={**(remaining.metadata or {}), 'raw_output': remaining.raw, 'problem': str(remaining)}))
                return self._output_escalation(state, node, str(remaining), reply.context_ref)
        return reply

    def _check_handoff(self, node, result, state, context_ref=None):
        validate(result, result_schema(node, state.as_dict()))
        required = REQUIRED_ARTIFACT.get(node)
        if (required and result['action'] not in {Action.HUMAN_REQUIRED, Action.OWNER_REQUIRED, Action.REQUEST_PROMOTER_ARBITRATION}
                and sum(a['kind'] == required for a in result['artifacts']) != 1):
            raise OutputProblem(f'{node.value} requires one {required}', json.dumps(result, ensure_ascii=False),
                                context_ref)
        escalation = result.get('escalation')
        if escalation:
            known = set(self.authority) | {ref for refs in state.artifact_refs.values() for ref in refs}
            if any(ref not in known for ref in escalation['evidence_refs']):
                raise OutputProblem('Escalation evidence must cite supplied authority or registered formal artifacts; '
                                    'dynamic Host fact keys are not formal references',
                                    json.dumps(result, ensure_ascii=False), context_ref)

    def _output_escalation(self, state, node, reason, context_ref):
        from loommode.roles.contracts import empty_result
        result = empty_result(Action.HUMAN_REQUIRED, reason)
        result['escalation'] = {'origin_role': TABLE[node][0].value, 'origin_activity': node.value,
            'stage_id': state.stage_id, 'task_id': state.task_id, 'category': 'INTERNAL_FINDING',
            'reason': reason, 'evidence_refs': self._refs(state, 'ROLE_OUTPUT')[:],
            'requested_treatment': 'REPORT_CORRECTION'}
        return self._record_output(state, node, Invocation(result, context_ref))

    def _resolved_output(self, state, node):
        refs = self._refs(state, 'DECISION_RESOLVED_OUTPUT')
        if state.last_completed_activity != Node.DECISION_MEDIATION or not refs:
            return False
        value = self.artifacts.read_json(refs[-1])
        return (value['activity'], value['task_id'], value['handoff_ref']) == (node.value, state.task_id, state.decision_handoff_ref)

    def _mediate(self, state, result):
        finding = self.artifacts.read_json(state.decision_handoff_ref)
        judgment = result['mediation']
        if (not judgment or judgment['handoff_ref'] != state.decision_handoff_ref
                or result['escalation'] or result['intent'] or result['model_override'] or result['new_basis']
                or result['repair_from_review'] or result['sync']):
            raise WorkflowError('Decision mediation requires matching finding and no authority expansion')
        outcome = judgment['outcome']
        if finding.get('owner_event') == 'REQUEST_SAME_TASK_REPAIR':
            if outcome not in {'SAME_TASK_REPAIR', 'HARD_GATE', 'SAFE_STOP', 'OWNER_ATTENTION'}:
                raise WorkflowError('Owner same-task request cannot select a new Task or replay execution')
            receipt = self.artifacts.read_json(finding['original_result_ref'])
            if outcome == 'SAME_TASK_REPAIR':
                self._same_task_repair_authority(state, receipt['evidence_refs'],
                    stop_ref=receipt['prior_handoff_ref'], mediation_ref=receipt['prior_mediation_ref'])
        if finding['category'] in HARD_GATE_CATEGORIES and outcome not in {'HARD_GATE', 'SAFE_STOP'}:
            raise WorkflowError('protected finding cannot be downgraded or retried')
        if outcome in {'HARD_GATE', 'SAFE_STOP', 'OWNER_ATTENTION'} and not judgment['notice']:
            raise WorkflowError('external Decision treatment requires an actual notice')
        if outcome in {'HARD_GATE', 'SAFE_STOP'}:
            self.executor.suspend()
            return Node.HUMAN_BLOCK
        origin = Node(finding['resume_node'])
        if finding['requested_treatment'] == 'REPORT_CORRECTION' and outcome == 'RETAIN_INTERNAL':
            if origin not in {Node.EXECUTOR_IMPLEMENT, Node.INDEPENDENT_REVIEW, Node.PROMOTER_RESULT_REVIEW}:
                raise WorkflowError('Decision cannot interpret side-effecting control results')
            from loommode.roles.contracts import parse_result
            resolved = parse_result(result['handoff'], origin, state.as_dict())
            self._check_handoff(origin, resolved, state)
            # Decision interprets role materials, never supplies Host receipts,
            # Grant or test facts. Original Result/commit Gates still run.
            context_ref = (state.active_review_context_ref if origin == Node.INDEPENDENT_REVIEW else
                           state.role_context_refs.get(Role.PROMOTER.value) if origin == Node.PROMOTER_RESULT_REVIEW else
                           state.executor_context_ref)
            if origin == Node.EXECUTOR_IMPLEMENT:
                check = getattr(self.executor, '_check_managed_tests', None)
                if check and getattr(self.executor, 'managed_task', lambda task: False)(state.task_id):
                    check(state.task_id, resolved)
            ref = self._save_artifact(state, 'DECISION', json.dumps({'origin': 'DECISION_INTERPRETED_OUTPUT',
                'activity': origin.value, 'task_id': state.task_id, 'handoff_ref': state.decision_handoff_ref,
                'context_ref': context_ref, 'result': resolved}, ensure_ascii=False))
            state.artifact_refs.setdefault('DECISION_RESOLVED_OUTPUT', []).append(ref)
            return origin
        if finding['requested_treatment'] == 'REPORT_CORRECTION' and outcome != 'SAME_TASK_REPAIR':
            raise WorkflowError('report correction needs interpreted output or safe stop; execution replay is forbidden')
        if outcome == 'REGISTER_ISSUE' and not result['issues']:
            raise WorkflowError('issue disposition requires a current typed issue update')
        if origin in WINDOW_NODES:
            if outcome == 'EARLY_OWNER_REVIEW':
                if origin != Node.SOFT_REVIEW_WAIT or finding['owner_event'] != 'COMPLETE_STAGE_REVIEW':
                    raise WorkflowError('early review needs an explicit bound Owner review-completion receipt')
                state.soft_window_events.append({'node': origin.value, 'notice_ref': state.stage_notice_ref,
                    'stage_id': state.stage_id, 'outcome': 'EXPLICIT_OWNER_REVIEW_COMPLETED',
                    'owner_receipt_ref': finding['original_result_ref'], 'owner_accepted': False})
                return Node.TASK_SELECTION
            if outcome in {'PLANNER_ADJUSTMENT', 'FOLLOWUP_DECOMPOSITION', 'REGISTER_ISSUE', 'RETAIN_INTERNAL', 'OWNER_ATTENTION'}:
                if origin == Node.SOFT_REVIEW_WAIT:
                    return Node.STAGE_PLANNING
                return self._restart_close(state)
            if outcome == 'FRESH_REACCEPTANCE':
                return self._restart_close(state)
            raise WorkflowError('Owner window input has no safe bounded treatment')
        if outcome in {'PLANNER_ADJUSTMENT', 'FOLLOWUP_DECOMPOSITION'}:
            if origin in {Node.STAGE_REVIEW, Node.STAGE_PLANNING, Node.STAGE_PLAN_DECISION}:
                return Node.STAGE_PLANNING
            if not state.task_id or not state.formal_task_intent_ref:
                raise WorkflowError('derived adjustment requires actual current Task provenance')
            return Node.TASK_SELECTION
        if outcome == 'SAME_TASK_REPAIR':
            if not state.latest_execution_report_ref or state.task_id in state.task_checkpoint_refs:
                raise WorkflowError('same-task repair cannot replay an accepted or reportless Task')
            totals = self._allowance_totals(state)
            if (totals['repair'] >= totals['capacity']['repair']
                    or totals['treatment'] and totals['capacity']['repair'] == 1):
                raise WorkflowError('Decision mediation cannot replenish exhausted repair budget')
            return Node.PROMOTER_RESULT_REVIEW
        if outcome == 'FRESH_REACCEPTANCE':
            if self.grant().scope in {'TASK', 'SERIES'}:
                raise ScopeRejected('partial delegation cannot request entire Stage acceptance')
            return self._restart_close(state)
        if outcome == 'REGISTER_ISSUE' and state.stage_acceptance_ref:
            return self._restart_close(state)
        if outcome == 'EARLY_OWNER_REVIEW':
            raise WorkflowError('early Owner review is only valid for a bound Stage-start window')
        return origin

    @staticmethod
    def _restart_close(state):
        state.stage_acceptance_ref = state.stage_knowledge_ref = state.stage_closeout_ref = None
        state.machine_close_ready = state.stage_closed = state.owner_accepted = False
        state.memory_completed_roles = []
        state.issue_triage = []
        return Node.STAGE_ACCEPTANCE

    def _guard_route(self, state: WorkflowState, node: Node, result: dict[str, Any],
                     owner_request_refs: tuple[str, ...] = ()) -> Node:
        action = Action(result["action"])
        if state.task_id and action in {Action.TASK_REPAIR, Action.REQUEST_DECISION, Action.NEW_BASIS_APPROVED,
                                      Action.DECISION_READY, Action.DECISION_ACCEPTED}:
            totals = self._allowance_totals(state)
            state.normal_repair_used |= bool(totals['repair'])
            state.decision_new_basis_used |= bool(totals['new_basis'])
            state.decision_treatment_used |= bool(totals['treatment'])
        if node == Node.DECISION_MEDIATION:
            if action != Action.MEDIATION_READY:
                raise WorkflowError('Decision mediation requires a typed final treatment')
            return self._mediate(state, result)
        if node == Node.STAGE_CLOSE_SYNC and any(item['target'] == 'HIGHEST_CONTRACT' and item['outcome'] == 'NEEDS_HUMAN' for item in result['sync']):
            return self._host_escalation(state, node, 'UPSTREAM_AUTHORITY_OR_CONTRACT', 'Actual upstream contract maintenance needs Owner authority.')
        if action in {Action.HUMAN_REQUIRED, Action.OWNER_REQUIRED} or result['escalation']:
            if not result['escalation']:
                raise WorkflowError('internal escalation requires a typed category and provenance')
            self._route_escalation = result['escalation']
            return Node.DECISION_MEDIATION
        next_node = TABLE[node][1][action]
        actor = TABLE[node][0]
        if action == Action.STAGE_READY and self.grant().scope in {'TASK', 'SERIES'}:
            raise ScopeRejected("partial delegated scope completion cannot assert Stage readiness")
        if action == Action.STAGE_READY and self.grant().scope == 'EXPLICIT_BOUNDED_SCOPE':
            remaining = [task for task in self.grant().task_ids if task.startswith(state.stage_id + '-') and task not in state.task_checkpoint_refs]
            if remaining:
                raise ScopeRejected('declared bounded current-Stage work remains')
        if node == Node.STAGE_PLANNING and action == Action.PLAN_READY:
            plan = result['stage_plan']
            if (not plan or plan['stage_id'] != state.stage_id
                    or not isinstance(plan['goal'], str) or not plan['goal'].strip()):
                raise WorkflowError('genuine typed Stage goal/plan required')
            if any(not plan[key] for key in ('functional_outcomes', 'series', 'initial_tasks', 'risks', 'authority_refs', 'acceptance_focus')):
                raise WorkflowError('Stage plan omits outcomes/Series/tasks/risks/authority/acceptance')
            if state.stage_input_ref not in plan['authority_refs'] or any(ref not in self.authority for ref in plan['authority_refs']):
                raise WorkflowError('Stage plan lacks actual Stage authority')
        if action == Action.SCOPE_COMPLETE:
            grant = self.grant()
            completion = result['completion']
            if grant.scope not in {'SERIES', 'EXPLICIT_BOUNDED_SCOPE'} or not completion:
                raise ScopeRejected("scope completion cannot substitute for Stage close")
            if (completion['scope'], completion['scope_id']) != (grant.scope, grant.scope_id):
                raise ScopeRejected("completion differs from actual grant")
            accepted_members = [task for task in state.used_task_ids if task in state.task_checkpoint_refs
                                and grant.contains(task, stage=state.stage_id, relationship_check=False)]
            history = task_closure_history(self.artifacts, state.used_task_ids, state.artifact_refs,
                                           state.task_checkpoint_refs, state.task_relationships)
            required_members = {task for task, row in history.items() if row['closure_required']
                                and grant.contains(task, stage=state.stage_id, relationship_check=False)}
            if required_members != set(accepted_members):
                raise WorkflowError('selected scope has an uncheckpointed closure-required Task')
            if completion['accepted_task_ids'] != accepted_members or completion['checkpoint_refs'] != [state.task_checkpoint_refs[task] for task in accepted_members]:
                raise WorkflowError("scope completion lacks actual accepted checkpoint chain")
            if not completion['residuals'] or not completion['remaining_stage_work'] or not accepted_members:
                raise WorkflowError("scope completion requires residual/remaining Stage assessment")
            if grant.scope == 'EXPLICIT_BOUNDED_SCOPE' and set(accepted_members) != set(grant.task_ids):
                raise WorkflowError("bounded scope has declared remaining Task membership")
            for ref in completion['checkpoint_refs']:
                self.artifacts.read(ref)
            state.scope_completion = completion
        elif result['completion'] is not None:
            raise WorkflowError("completion evidence without legitimate scope exhaustion")
        if node == Node.STAGE_PLAN_DECISION and action == Action.PLAN_ACCEPTED:
            if not result['owner_summary'] or not state.stage_plan_ref:
                raise WorkflowError("accepted Stage plan requires saved Owner notice")
        if node == Node.STAGE_ISSUE_TRIAGE and action in {Action.TRIAGE_READY, Action.ISSUE_REPAIR}:
            must_fix = validate_triage(result['triage'], state.stage_issues)
            if must_fix and action != Action.ISSUE_REPAIR:
                raise WorkflowError("unresolved must-fix prevents Stage close")
            if action == Action.ISSUE_REPAIR:
                if not must_fix or result['intent']:
                    raise WorkflowError("Decision requests actual must-fix repair; only Planner selects Intent")
                state.machine_close_ready = False
                state.stage_acceptance_ref = None
                state.stage_knowledge_ref = None
                next_node = Node.TASK_SELECTION
            else:
                previous_digest = self.artifacts.target_digests.get('MAJOR_PHASE_ISSUE_LEDGER')
                promoted_ref = self.artifacts.promote_issues(state.stage_id, state.stage_issues, result['triage'],
                    role_files=lambda: getattr(self.roles, 'role_files', None))
                if promoted_ref:
                    promotion_receipt = self._save_artifact(state, 'DECISION', json.dumps({
                        'origin': 'HOST_MAJOR_PHASE_PROMOTION', 'source_stage': state.stage_id,
                        'previous_sha256': previous_digest,
                        'updated_ref': promoted_ref, 'selected_ids': [row['issue_id'] for row in result['triage']
                                                                  if row['disposition'] == 'PROMOTE_TO_MAJOR_PHASE']}, ensure_ascii=False))
                    state.artifact_refs.setdefault('MAJOR_PHASE_PROMOTION', []).append(promotion_receipt)
            state.issue_triage = result['triage']
        if (node == Node.TASK_SELECTION and action == Action.STAGE_READY and self._refs(state,'ISSUE_REPAIR_REQUEST')
                and any(row['disposition']=='MUST_FIX_BEFORE_STAGE_CLOSE'
                    and state.stage_issues[row['issue_id']]['status']!='RESOLVED' for row in state.issue_triage)):
            raise WorkflowError('unresolved must-fix requires Planner-selected repair before Stage close')
        if node == Node.STAGE_KNOWLEDGE and action == Action.KNOWLEDGE_READY:
            if not result['knowledge'] or not result['evidence'] or not all(result['evidence'].values()):
                raise WorkflowError("Decision must judge actual substantive Knowledge adequate")
            content = render_knowledge(result['knowledge'], state, self.artifacts.read)
            state.stage_knowledge_ref = self._save_artifact(state, 'STAGE_KNOWLEDGE', content)
        if node == Node.OWNER_SUMMARY and action == Action.SUMMARY_READY:
            if not state.stage_knowledge_ref or set(state.memory_completed_roles) != {'Promoter', 'Constraint', 'Discussant', 'Decision'} or not self._refs(state, 'SYNC_APPLICATION'):
                raise WorkflowError("final Decision closeout requires actual Knowledge/sync/four-role memory")
            if validate_triage(state.issue_triage, state.stage_issues):
                raise WorkflowError('final closeout retains unresolved must-fix')
            if not result['evidence'] or not all(result['evidence'].values()):
                raise WorkflowError("final Decision must judge actual completed close artifacts/results")
        if result["model_override"]:
            if actor != Role.PROMOTER:
                raise WorkflowError("only Promoter may authorize a per-activity model override")
        selected_task = False
        if action == Action.TASK_INTENT_READY:
            next_node = self._task_intent(state, result, owner_request_refs)
            selected_task = True
        elif result["intent"] is not None:
            # A Decision implementation plan may explicitly reorganize a task on a new basis.
            if node != Node.PROMOTER_IMPLEMENTATION_PLAN or not (state.decision_new_basis_used or state.decision_treatment_used):
                raise WorkflowError("Intent may only be selected by Promoter at permitted node")
            self._task_intent(state, result, owner_request_refs)
            selected_task = True
        if result["model_override"] and not (selected_task and result["intent"]["model_override"]):
            self._set_override(state, result["model_override"],
                               state.task_id if selected_task or node in TASK_NODES else None)
        if action == Action.REQUEST_PROMOTER_ARBITRATION or node == Node.PROMOTER_ARBITRATION:
            if action == Action.RETURN_TO_CONSTRAINT_WITH_DIRECTION:
                if state.arbitration_used or not result["handoff"]:
                    return self._enter_decision(state, result)
                state.arbitration_used = True
            elif state.arbitration_used:
                return self._enter_decision(state, result)
        if action == Action.TASK_REPAIR:
            if result['repair_from_review'] and not self._review_conversion_available(state):
                raise WorkflowError('current review context cannot become the developer; use ordinary authorized repair')
            if not result["handoff"]:
                raise WorkflowError("targeted repair requires explicit directive")
            entry = self._blocker(state, result)
            if entry["decision_treatment_used"] and self._allowance_totals(state)['capacity']['repair'] == 1:
                return self._host_escalation(state, node, 'TRUE_UNRESOLVED_BLOCKER', 'Existing Decision treatment exhausted; no repair retry remains.')
            if not self._allowance_available(state, 'repair'):
                return self._enter_decision(state, result)
            self._consume_allowance(state, 'repair', result)
            entry["repair_used"] = state.normal_repair_used = True
            if result["repair_from_review"]:
                if not state.active_review_context_ref or not self._refs(state, "INDEPENDENT_REVIEW"):
                    raise WorkflowError("review repair has no completed review")
                if not self._managed_selected(state.task_id):
                    self.executor.transfer_review_for_repair(state.task_id, state.active_review_context_ref)
                    state.executor_context_ref = state.active_review_context_ref
                    state.active_review_context_ref = None
        elif result["repair_from_review"]:
            raise WorkflowError("review cannot gain write permission without Promoter targeted repair")
        if action == Action.REQUEST_DECISION:
            entry = self._blocker(state, result)
            if not self._allowance_available(state, 'treatment'):
                return self._host_escalation(state, node, 'TRUE_UNRESOLVED_BLOCKER', 'Existing Decision treatment exhausted; no new Decision flow remains.')
            next_node = self._enter_decision(state, result)
        if action == Action.NEW_BASIS_APPROVED:
            basis = result["new_basis"]
            entry = self._blocker(state, result)
            if not self._allowance_available(state, 'treatment'):
                return self._host_escalation(state, node, 'TRUE_UNRESOLVED_BLOCKER', 'Changed-basis treatment already used; no replenished budget.')
            if not basis or not basis["changed_premise"] or not basis["authority_refs"] or basis["change_kind"] == "CONFIG_ADJUSTMENT":
                raise WorkflowError("new basis requires Decision's explicit changed contract/task/implementation premise")
            if any(ref not in self.authority and ref not in self._refs(state, "DECISION") for ref in basis["authority_refs"]):
                raise WorkflowError("new basis authority not supplied")
            self._consume_allowance(state, 'treatment', result)
            self._consume_allowance(state, 'new_basis', result)
            entry["new_basis_used"] = state.decision_new_basis_used = True
            entry["decision_treatment_used"] = state.decision_treatment_used = True
            entry["basis_id"] = basis["basis_id"]
        elif result["new_basis"] is not None:
            raise WorkflowError("new basis payload without Decision approval")
        if action == Action.DECISION_READY and node in {Node.DECISION_REVIEW, Node.DECISION_RE_REVIEW}:
            if state.active_blocker_id:
                entry = self._blocker(state, result)
                if entry["repair_used"]:
                    if not self._allowance_available(state, 'treatment') and node != Node.DECISION_RE_REVIEW:
                        return self._host_escalation(state, node, 'TRUE_UNRESOLVED_BLOCKER', 'Existing Decision treatment cannot be repeated.')
                    if node != Node.DECISION_RE_REVIEW or not entry['decision_treatment_used']:
                        self._consume_allowance(state, 'treatment', result)
                    entry["decision_treatment_used"] = state.decision_treatment_used = True
        if next_node == Node.DECISION_RE_REVIEW:
            if state.decision_re_review_used:
                return self._host_escalation(state, node, 'TRUE_UNRESOLVED_BLOCKER', 'Finite Decision re-review already used.')
            state.decision_re_review_used = True
        if action == Action.REQUEST_INDEPENDENT_REVIEW:
            if state.independent_review_used and not self._owner_post_repair_review_available(state):
                return self._enter_decision(state, result)
            state.independent_review_used = True
        if action == Action.TASK_ACCEPTED:
            if (any(e.get('event') == 'REQUEST_SAME_TASK_REPAIR' and e.get('authorization_id')
                    for e in state.human_events) and self._named_internal_repair_applied(state)
                    and not self._owner_post_repair_review_available(state, completed=True)):
                raise WorkflowError('named internal repair requires its current post-repair fresh review')
            # Task acceptance is a role judgment independent of Git permission.
            # The subsequent commit gate still requires its explicit Host grant.
            if not state.latest_execution_report_ref or not state.formal_constraint_ref:
                raise WorkflowError("Task acceptance lacks frozen input or saved report")
            if not result["evidence"] or not all(result["evidence"].values()):
                raise WorkflowError("Promoter acceptance missing required validation evidence")
            reports = self._refs(state, "REPORT_RESULT")
            if not reports:
                raise WorkflowError("Executor report evidence missing")
            report = self.artifacts.read_json(reports[-1])
            if not self._executor_report_eligible(state, report):
                raise WorkflowError("failed/incomplete Executor report cannot pass commit gate")
        if action == Action.DECISION_ACCEPTED and state.formal_constraint_ref:
            if state.decision_treatment_used:
                raise WorkflowError("Decision treatment requires a new Promoter task identity before another Final")
            if state.normal_repair_used:
                return self._host_escalation(state, node, 'TRUE_UNRESOLVED_BLOCKER', 'Unchanged Final cannot reset the repair allowance.')
            # Direction under unchanged Final, not a new retry budget or contract rewrite.
            next_node = Node.EXECUTOR_IMPLEMENT
        if action == Action.DECISION_ACCEPTED and not state.normal_repair_used and not state.decision_treatment_used:
            # Promoter explicitly accepted the pre-execution direction. Preserve the ledger,
            # but allow a distinct later failure to be identified by the responsible role.
            state.active_blocker_id = None
        if action == Action.MACHINE_CLOSE_READY:
            state.machine_close_ready = True
        if action == Action.SYNC_READY:
            sync = result["sync"]
            if len(sync) != len(SYNC_TARGETS) or {s["target"] for s in sync} != set(SYNC_TARGETS):
                raise WorkflowError("Stage sync must account for all six targets exactly once")
            if any(item["outcome"] == "NEEDS_HUMAN" for item in sync):
                category = 'UPSTREAM_AUTHORITY_OR_CONTRACT' if any(item['target'] == 'HIGHEST_CONTRACT' and item['outcome'] == 'NEEDS_HUMAN' for item in sync) else 'SYNC_MAINTENANCE'
                return self._host_escalation(state, node, category, 'Six-target maintenance has an unresolved target; no partial sync is applied.')
            verified = {}
            role_files = lambda: getattr(self.roles, 'role_files', None)
            for item in sync:
                if item["outcome"] == "UPDATED":
                    if not item["content"] or not item["authority_ref"]:
                        raise WorkflowError("UPDATED lacks explicit content/authority")
                    if not self.authority.get(item["authority_ref"]):
                        raise WorkflowError("UPDATED lacks actual supplied authority provenance")
                    verified[item['target']] = self.artifacts.preflight_maintenance(
                        item["target"], item["content"], item["authority_ref"], role_files=role_files)
            applied = []
            for item in sync:
                updated_ref = None
                previous_sha256 = None
                if item["outcome"] == "UPDATED":
                    previous_sha256 = verified[item['target']]
                    updated_ref = self.artifacts.maintain(item["target"], item["content"], item["authority_ref"], role_files=role_files)
                applied.append({"target": item["target"], "outcome": item["outcome"],
                                "updated_ref": updated_ref, "authority_ref": item["authority_ref"],
                                'previous_sha256': previous_sha256,
                                'authority_sha256': digest(self.authority[item['authority_ref']]) if item['authority_ref'] in self.authority else None})
            receipt_ref = self._save_artifact(state, "DECISION", json.dumps({"origin": "HOST_SYNC_RECEIPT",
                                              'stage_id': state.stage_id, "sync": applied}, ensure_ascii=False))
            state.artifact_refs.setdefault("SYNC_APPLICATION", []).append(receipt_ref)
        if action == Action.SUMMARY_READY and not result["owner_summary"]:
            raise WorkflowError("Decision must provide a natural-language Owner summary")
        return next_node

    def step(self, *, owner_request_refs: tuple[str, ...] = ()) -> WorkflowState:
        self._history_receipts(self.state)
        if self._busy:
            raise WorkflowError("one active writer/activity only")
        self.assert_resource_health()
        self.state.validate()
        node = Node(self.state.current_node)
        if not isinstance(owner_request_refs, tuple) or any(not isinstance(ref, str) for ref in owner_request_refs):
            raise WorkflowError("Owner input refs must be an explicit tuple")
        if owner_request_refs:
            if node not in OWNER_INPUT_NODES or len(owner_request_refs) != len(set(owner_request_refs)):
                raise WorkflowError("Owner input at invalid node or duplicate refs")
            for ref in owner_request_refs:
                self._owner_request(self.state, ref)
        if node in STOP_NODES or node in WINDOW_NODES:
            return self.state
        if getattr(self, 'dispatch_fence', lambda: False)():
            return self.state
        if self.state.in_flight_activity:
            raise WorkflowError("unknown prior effects; restart/recovery required, no replay")
        active = self._active_task()
        if active:
            self.preflight_task(active)
        if node == Node.EXECUTOR_IMPLEMENT:
            if not self.state.stage_plan_decision_ref or not any(event['node'] == Node.SOFT_REVIEW_WAIT.value for event in self.state.soft_window_events):
                raise ScopeRejected('mandatory Decision-reviewed Stage start protocol not complete')
        self._busy = True
        before = copy.deepcopy(self.state)
        working = copy.deepcopy(self.state)
        implementation_dispatched = False
        try:
            self.state.in_flight_activity = node.value
            self.store.save(self.state)
            working = copy.deepcopy(self.state)
            if node == Node.STAGE_START:
                self._move(working, Node.STAGE_REVIEW)
            elif node == Node.EXECUTOR_REPORT_READY:
                if not working.latest_execution_report_ref:
                    raise WorkflowError("report-ready state has no saved report")
                self._move(working, Node.PROMOTER_RESULT_REVIEW)
            elif node == Node.COMMIT_AUTHORIZATION:
                binding = self._verify_commit_gate(working)
                self.executor.authorize_commit({**working.as_dict(), "host_checkpoint_binding": binding})
                self._move(working, Node.EXECUTOR_LOCAL_COMMIT)
            elif node == Node.TASK_COMPLETE:
                ref = working.task_checkpoint_refs.get(working.task_id)
                if not ref:
                    raise WorkflowError("Task completion lacks a formal Host checkpoint")
                self.artifacts.assert_task_reference(ref, "DECISION", working.task_id)
                value = self.artifacts.read_json(ref)
                if value.get("task_id") != working.task_id:
                    raise WorkflowError("Task completion checkpoint identity mismatch")
                if value.get("origin") == "HOST_NO_DEV_CHANGE" and set(value) == {"origin", "task_id", "evidence"}:
                    if working.commit_receipt is not None:
                        raise WorkflowError("no-commit completion contradicts actual commit receipt")
                    self._verify_no_commit(working, value["evidence"])
                elif value.get("origin") == "HOST_COMMIT_RECEIPT" and set(value) == {"origin", "task_id", "receipt"}:
                    self._verify_commit_gate(working, completed=True)
                    if not working.commit_receipt or value["receipt"] != working.commit_receipt:
                        raise WorkflowError("Task completion lacks matching Host commit receipt")
                else:
                    raise WorkflowError("Task completion has unknown checkpoint disposition")
                self.executor.suspend()
                working.active_blocker_id = None
                if working.pending_override_task_id == working.task_id:
                    self._clear_override(working)
                self._move(working, Node.TASK_SELECTION)
            else:
                materials = self._materials(working, node, owner_request_refs)
                actor = TABLE[node][0]
                if node == Node.ROLE_MEMORY_CONSOLIDATION:
                    if self._memory(working, materials):
                        commits, no_commits = self._checkpoint_records(working)
                        self._save_artifact(working, "STAGE_RECORD", json.dumps({"stage": working.stage_id,
                                        "stage_authorization_ref": working.stage_input_ref,
                                        "stage_goal_input": self.authority[working.stage_input_ref],
                                        "tasks": working.used_task_ids, "machine_close_ready": working.machine_close_ready,
                                        "task_history": task_closure_history(self.artifacts, working.used_task_ids,
                                            working.artifact_refs, working.task_checkpoint_refs, working.task_relationships),
                                        "machine_status": "MACHINE_CLOSE_READY",
                                        'delegated_scope': working.active_grant, 'stage_plan_ref': working.stage_plan_ref,
                                        'stage_plan_decision_ref': working.stage_plan_decision_ref,
                                        'stage_knowledge_ref': working.stage_knowledge_ref,
                                        'current_stage_issues': working.stage_issues, 'issue_triage': working.issue_triage,
                                        "owner_accepted": False, "checkpoints": working.task_checkpoint_refs,
                                        "task_commits": commits, "task_no_commits": no_commits,
                                        "decision_refs": self._refs(working, "DECISION"),
                                        "stage_acceptance_ref": self._refs(working, "INDEPENDENT_REVIEW")[-1],
                                        "acceptance_refs": self._refs(working, "INDEPENDENT_REVIEW"),
                                        "issue_ledger_refs": self._refs(working, "STAGE_ISSUE_LEDGER"),
                                        "sync_refs": self._refs(working, "SYNC_RESULT")[-1:],
                                        "sync_application_refs": self._refs(working, "SYNC_APPLICATION"),
                                        "memory_refs": self._refs(working, "ROLE_EXPERIENCE"),
                                        "memory_completed_roles": working.memory_completed_roles,
                                        "human_gate": {"status": "NO_EXPLICIT_OWNER_ACCEPTANCE", "owner_accepted": False,
                                                       "automatic_next_stage": False},
                                        "artifacts": working.artifact_refs}, ensure_ascii=False))
                        self._move(working, Node.OWNER_SUMMARY)
                else:
                    override = self._take_override(working, node)
                    call_state = working.as_dict()
                    if node == Node.PROMOTER_RESULT_REVIEW:
                        call_state['host_review_context_conversion_available'] = self._review_conversion_available(working)
                    if node == Node.STAGE_PLANNING:
                        # Materials also contain ordinary artifacts and HOST_* facts.
                        # Only the actual Engine authority mapping is legal here.
                        call_state['stage_authority_keys'] = sorted(self.authority)
                    if node == Node.EXECUTOR_IMPLEMENT and not self._resolved_output(working, node):
                        preflight = getattr(self.executor, 'preflight', None)
                        if preflight:
                            preflight(node, call_state, materials, override)
                        self._consume_allowance(working, 'implementation', {
                            'intent_ref': working.formal_task_intent_ref, 'final_ref': working.formal_constraint_ref})
                        implementation_dispatched = True
                        call_state = working.as_dict()
                    if node in FRESH_NODES:
                        for field in ("last_result", "latest_execution_report_ref", "role_context_refs", "executor_context_ref", "active_review_context_ref", "artifact_refs", "acceptance_ref", "commit_receipt", "task_checkpoint_refs", 'decision_handoff_ref', 'mediation_result_ref', 'latest_decision_notice_ref'):
                            call_state[field] = {} if field in {"role_context_refs", "artifact_refs", "task_checkpoint_refs"} else None
                        call_state['issue_triage'] = []
                        call_state['mediation_counts'] = {}
                        call_state['owner_window_refs'] = []
                        for field in ('stage_acceptance_ref', 'stage_closeout_ref', 'stage_knowledge_ref'):
                            call_state[field] = None
                    failure_stage='handoff'
                    invocation = self._invoke_handoff(working, node, call_state, materials, override)
                    failure_stage='parser_schema'
                    result = invocation.result
                    validate(result, result_schema(node, working.as_dict()))
                    if result["sync"] and node != Node.STAGE_CLOSE_SYNC:
                        raise WorkflowError("sync directives outside Stage close")
                    required = REQUIRED_ARTIFACT.get(node)
                    if Action(result["action"]) not in {Action.HUMAN_REQUIRED, Action.REQUEST_PROMOTER_ARBITRATION, Action.OWNER_REQUIRED}:
                        if required and sum(a["kind"] == required for a in result["artifacts"]) != 1:
                            raise WorkflowError(f"{node.value} requires exactly one {required}")
                    allowed_kinds = set(allowed_artifact_kinds(node))
                    if any(a["kind"] not in allowed_kinds for a in result["artifacts"]):
                        raise WorkflowError("artifact kind is not authorized for this activity")
                    if result['issues'] and node in {Node.STAGE_ISSUE_TRIAGE, Node.STAGE_MACHINE_CLOSE,
                            Node.STAGE_CLOSE_SYNC, Node.STAGE_KNOWLEDGE, Node.OWNER_SUMMARY}:
                        raise WorkflowError('new close findings must be registered before fresh acceptance/triage')
                    self._route_escalation = None
                    failure_stage='route'
                    next_node = self._guard_route(working, node, result, owner_request_refs)
                    failure_stage='artifact'
                    self._apply_issues(working, result['issues'])
                    for artifact in result["artifacts"]:
                        artifact_ref = self._save_artifact(working, artifact["kind"], artifact["content"])
                        if artifact["kind"] == "DECISION" and node != Node.DECISION_MEDIATION:
                            working.artifact_refs.setdefault("DECISION_PLAN", []).append(artifact_ref)
                    if result["experiences"]:
                        if any(c["role"] != actor.value for c in result["experiences"]):
                            raise WorkflowError("experience candidates must belong to producing role")
                        self._save_artifact(working, "ROLE_EXPERIENCE", json.dumps(result["experiences"], ensure_ascii=False))
                    receipt_kind = "ACCEPTANCE" if result["action"] == Action.TASK_ACCEPTED.value else "DECISION"
                    receipt_ref = self._save_artifact(working, receipt_kind, json.dumps(result, ensure_ascii=False))
                    if node == Node.STAGE_CLOSE_SYNC and result['action'] == Action.SYNC_READY.value and next_node != Node.DECISION_MEDIATION:
                        working.artifact_refs.setdefault('SYNC_RESULT', []).append(receipt_ref)
                    if node == Node.STAGE_ISSUE_TRIAGE and result['action'] == Action.ISSUE_REPAIR.value:
                        working.artifact_refs.setdefault('ISSUE_REPAIR_REQUEST', []).append(receipt_ref)
                    if next_node == Node.DECISION_MEDIATION:
                        self._prepare_mediation(working, node, actor, receipt_ref, self._route_escalation)
                    if node == Node.DECISION_MEDIATION:
                        working.mediation_result_ref = receipt_ref
                        working.artifact_refs.setdefault('DECISION_MEDIATION_RESULT', []).append(receipt_ref)
                        judgment = result['mediation']
                        if judgment['notice']:
                            working.latest_decision_notice_ref = self._save_artifact(working, 'DECISION', json.dumps({
                                'origin': 'DECISION_OWNER_NOTICE', 'stage_id': working.stage_id, 'task_id': working.task_id,
                                'handoff_ref': working.decision_handoff_ref, 'decision_result_ref': receipt_ref,
                                'outcome': judgment['outcome'], 'body': judgment['notice'], 'owner_accepted': False}, ensure_ascii=False))
                            working.artifact_refs.setdefault('DECISION_NOTICE', []).append(working.latest_decision_notice_ref)
                    if node == Node.STAGE_PLANNING and result['action'] == Action.PLAN_READY.value:
                        working.stage_plan_ref = self._save_artifact(working, 'PLAN_REFERENCE', json.dumps(result['stage_plan'], ensure_ascii=False))
                    if node == Node.STAGE_PLAN_DECISION and result['action'] == Action.PLAN_ACCEPTED.value:
                        working.stage_plan_decision_ref = receipt_ref
                        working.stage_notice_ref = self._save_artifact(working, 'DECISION', json.dumps({
                            'origin': 'STAGE_PLAN_OWNER_NOTICE', 'stage_id': working.stage_id,
                            'plan_ref': working.stage_plan_ref, 'decision_ref': receipt_ref,
                            'summary': result['owner_summary'], 'window_seconds': 1800, 'owner_accepted': False}, ensure_ascii=False))
                        working.latest_decision_notice_ref = working.stage_notice_ref
                        working.artifact_refs.setdefault('DECISION_NOTICE', []).append(working.stage_notice_ref)
                    if node == Node.STAGE_ACCEPTANCE:
                        working.stage_acceptance_ref = self._refs(working, 'INDEPENDENT_REVIEW')[-1]
                    if node == Node.OWNER_SUMMARY and result['action'] == Action.SUMMARY_READY.value:
                        working.stage_closeout_ref = receipt_ref
                        working.latest_decision_notice_ref = receipt_ref
                        working.artifact_refs.setdefault('DECISION_NOTICE', []).append(receipt_ref)
                    if node == Node.EXECUTOR_IMPLEMENT:
                        self._bind_report_result(working, receipt_ref, invocation)
                    if result["action"] == Action.TASK_ACCEPTED.value:
                        working.acceptance_ref = receipt_ref
                    if actor == Role.EXECUTOR:
                        if node in FRESH_NODES:
                            working.active_review_context_ref = invocation.context_ref
                        else:
                            working.executor_context_ref = invocation.context_ref
                    else:
                        working.role_context_refs[actor.value] = invocation.context_ref
                    if node == Node.EXECUTOR_LOCAL_COMMIT:
                        receipt = invocation.commit_receipt
                        evidence = invocation.no_commit_evidence
                        if result["action"] == Action.NO_DEV_CHANGE.value:
                            if receipt is not None or not evidence:
                                raise WorkflowError("NO_DEV_CHANGE lacks separate Host no-commit evidence")
                            self._verify_no_commit(working, evidence)
                            working.task_checkpoint_refs[working.task_id] = self._save_artifact(working, "DECISION", json.dumps(
                                {"origin": "HOST_NO_DEV_CHANGE", "task_id": working.task_id, "evidence": evidence}, ensure_ascii=False))
                        elif evidence is not None:
                            raise WorkflowError("no-commit evidence contradicts checkpoint action")
                        if result["action"] == Action.COMMIT_COMPLETE.value and not receipt:
                            raise WorkflowError("COMMIT_COMPLETE lacks actual Host receipt")
                        if receipt and result["action"] != Action.COMMIT_COMPLETE.value:
                            raise WorkflowError("commit receipt contradicts checkpoint action")
                        if receipt:
                            if not receipt.get("commit_hash") or not receipt.get("staged_files"):
                                raise WorkflowError("invalid Host commit receipt")
                            working.commit_receipt = receipt
                            working.task_checkpoint_refs[working.task_id] = self._save_artifact(working, "DECISION", json.dumps(
                                {"origin": "HOST_COMMIT_RECEIPT", "task_id": working.task_id, "receipt": receipt}, ensure_ascii=False))
                    working.last_result = {"action": result["action"], "handoff": result["handoff"],
                                           "explanation": result["explanation"], "result_ref": receipt_ref,
                                           "invocation": invocation.metadata}
                    if owner_request_refs:
                        working.last_result["owner_request_refs"] = list(owner_request_refs)
                    self._move(working, next_node, (result['mediation']['reason'] if node == Node.DECISION_MEDIATION else result["explanation"]) if next_node == Node.HUMAN_BLOCK else
                               "Machine close ready. Await explicit Owner stage event; no next Stage starts." if next_node == Node.HUMAN_GATE else None)
            working.in_flight_activity = None
            working.last_completed_activity = node.value
            failure_stage='state'
            self.store.save(working)
            self.state = working
        except Exception as exc:
            if (isinstance(exc, ScopeRejected) and not implementation_dispatched
                    and self.state.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION', []) == before.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION', [])):
                self.state = before
                self.store.save(before)
                raise
            self.executor.suspend()
            for alias in ('HOST_ALLOWANCE_CONSUMPTION', 'HOST_ALLOWANCE_GRANT', 'ROLE_OUTPUT', 'DECISION_RESOLVED_OUTPUT',
                          'HOST_NATIVE_EXECUTOR_ADMISSION'):
                for ref in working.artifact_refs.get(alias, []):
                    if ref not in before.artifact_refs.setdefault(alias, []):
                        before.artifact_refs[alias].append(ref)
                    if ref not in before.artifact_refs.setdefault('DECISION', []):
                        before.artifact_refs['DECISION'].append(ref)
            before.mediation_counts.update(working.mediation_counts)
            self.state = before
            self.state.in_flight_activity = node.value
            self._move(self.state, Node.FAILED)
            diagnostic = failure_evidence(exc)
            from .failure_evidence import safe_observation
            observed=getattr(exc,'safe_observation',None)
            if observed is None:
                metadata=getattr(locals().get('invocation'),'metadata',None) or {}
                observed={**metadata.get('safe_observation',{}),'stage':locals().get('failure_stage','handoff')}
            observation=safe_observation(observed,locals().get('failure_stage','handoff'))
            self.state.last_result = {"error": diagnostic["error"], "activity": node.value,
                                      "failure": {key: diagnostic[key] for key in
                                                  ("category", "failed_tool", "reason_code")},
                                      "failure_receipt_status": "NOT_APPLICABLE"}
            self.state.last_result['safe_observation']=observation
            # Stage-scoped receipt survives rollback before any Task exists.
            self.state.last_result['stage_failure_receipt_status'] = 'UNAVAILABLE'
            try:
                stage_ref=self.artifacts.save('DECISION',json.dumps({'origin':'HOST_STAGE_FAILURE',
                    'stage_id':self.state.stage_id,'activity':node.value,'reason_code':diagnostic['reason_code'],
                    'observation':observation},ensure_ascii=False))
                self.state.artifact_refs.setdefault('HOST_STAGE_FAILURE',[]).append(stage_ref)
                self.state.artifact_refs.setdefault('DECISION',[]).append(stage_ref)
                self.state.last_result['stage_failure_receipt_status'] = 'SAVED'
            except Exception:
                # Receipt setup/publish/cleanup can fail outside ArtifactStore's
                # OSError wrapper. Never publish that exception or skip State.
                diagnostic = failure_evidence(WorkflowError('artifact write failed; workflow must stop'))
                self.state.last_result['stage_failure_receipt_failure'] = diagnostic

            if self.state.task_id and self.state.task_id in self.state.used_task_ids:
                self.state.last_result["failure_receipt_status"] = "UNAVAILABLE"
                try:
                    failure_ref = self.artifacts.save('DECISION', json.dumps({'origin': 'HOST_TASK_FAILURE',
                        'task_id': self.state.task_id, 'activity': node.value, **diagnostic,
                        'may_have_dev_effects': implementation_dispatched or node in {Node.EXECUTOR_LOCAL_COMMIT, Node.TASK_COMPLETE}},
                        ensure_ascii=False), task_id=self.state.task_id)
                    self.state.artifact_refs.setdefault('DECISION', []).append(failure_ref)
                    self.state.artifact_refs.setdefault('HOST_TASK_FAILURE', []).append(failure_ref)
                    self.state.last_result["failure_receipt_status"] = "SAVED"
                except Exception:
                    # Task diagnostic setup/publish/cleanup errors obey the same
                    # safe stop contract as the stage receipt. State still needs
                    # its FAILED save attempt; never publish the raw exception.
                    diagnostic = failure_evidence(WorkflowError('artifact write failed; workflow must stop'))
                    self.state.last_result['task_failure_receipt_failure'] = diagnostic
            # Retain in-flight marker: external effects may have happened before failure.
            try:
                self.store.save(self.state)
            except Exception:
                raise WorkflowError('failure State publication failed; workflow stopped') from None
            raise WorkflowError(f"workflow stopped at {node.value}: {safe_outward_error(exc, diagnostic)}") from None
        finally:
            self._busy = False
        # Business checkpoint/transition is already durable. Cleanup errors must
        # never enter the rollback handler above or authorize accepted Task replay.
        try:
            self._retain_context_references()
            maintenance = getattr(self.executor, "after_durable", None)
            if maintenance:
                maintenance(node, self.state.as_dict())
        except Exception as exc:
            self._resource_degraded = "post-durable resource retirement failed: " + str(exc)
            raise WorkflowError(self._resource_degraded) from exc
        return self.state

    def _memory(self, state: WorkflowState, materials: dict[str, str]) -> bool:
        if not state.machine_close_ready:
            raise WorkflowError("memory consolidation before machine close")
        role_files = lambda: getattr(self.roles, 'role_files', None)
        self.artifacts.preflight_memory_ownership(role_files)
        # Known target drift must fence this entire entry before role publication.
        # Unconfigured legacy NO_CHANGE requires no memory maintenance authority.
        for role in (Role.PROMOTER, Role.CONSTRAINT, Role.DISCUSSANT, Role.DECISION):
            if f"ROLE_MEMORY:{role.value}" in self.artifacts.targets:
                authority = self.authority.get(self.memory_authority)
                if not isinstance(authority, str) or not authority.strip():
                    raise WorkflowError("configured memory lacks an explicit authority source")
                self.artifacts.preflight_memory(role.value, self.memory_authority, role_files=role_files)
        for role in (Role.PROMOTER, Role.CONSTRAINT, Role.DISCUSSANT, Role.DECISION):
            if role.value in state.memory_completed_roles:
                continue
            candidates = []
            for ref in self._refs(state, "ROLE_EXPERIENCE"):
                value = json.loads(self.artifacts.read(ref))
                if isinstance(value, list):
                    candidates.extend(c for c in value if c["role"] == role.value)
            known_refs = set(self.authority) | {ref for refs in state.artifact_refs.values() for ref in refs}
            role_materials = {**materials, "HOST_EXPERIENCE_CANDIDATES": json.dumps(candidates, ensure_ascii=False),
                              "HOST_FORMAL_SOURCE_REFS": json.dumps(sorted(known_refs), ensure_ascii=False)}
            override = self._take_override(state, Node.ROLE_MEMORY_CONSOLIDATION) if role == Role.PROMOTER else None
            invocation = self.roles.invoke(role, Node.ROLE_MEMORY_CONSOLIDATION, state.as_dict(), role_materials, override)
            result = invocation.result
            validate(result, result_schema(Node.ROLE_MEMORY_CONSOLIDATION))
            # A role call may expose a changed binding even when it requests NO_CHANGE.
            # Validate the current owners before evidence or completion is published.
            self.artifacts.preflight_memory_ownership(role_files)
            if f"ROLE_MEMORY:{role.value}" in self.artifacts.targets:
                self.artifacts.preflight_memory(role.value, self.memory_authority, role_files=role_files)
            if result["action"] == Action.HUMAN_REQUIRED.value:
                if not result['escalation']:
                    raise WorkflowError('memory escalation requires corresponding-role typed provenance')
                ref = self._save_artifact(state, "ROLE_EXPERIENCE", json.dumps(result, ensure_ascii=False))
                self._prepare_mediation(state, Node.ROLE_MEMORY_CONSOLIDATION, role, ref, result['escalation'])
                state.role_context_refs[role.value] = invocation.context_ref
                self._move(state, Node.DECISION_MEDIATION)
                return False
            if (result["action"] not in {Action.MEMORY_READY.value, Action.NO_CHANGE.value} or result["model_override"] or result["artifacts"]
                    or result["sync"] or result["intent"] or result["new_basis"] or result["repair_from_review"]):
                raise WorkflowError("invalid memory consolidation action or authority expansion")
            if result["action"] == Action.NO_CHANGE.value and result["experiences"]:
                raise WorkflowError("NO_CHANGE cannot request a memory update")
            if any(c["role"] != role.value for c in result["experiences"]):
                raise WorkflowError("one role cannot consolidate another role's memory")
            updated_ref = None
            if result["experiences"]:
                if not self.memory_authority:
                    raise WorkflowError("no explicit memory maintenance grant")
                if any(not c["source_refs"] or any(ref not in known_refs for ref in c["source_refs"]) for c in result["experiences"]):
                    raise WorkflowError("memory source is not explicit formal evidence")
                updated_ref = self.artifacts.consolidate_memory(role.value, result["experiences"], self.memory_authority,
                                                               role_files=role_files)
            self.artifacts.preflight_memory_ownership(role_files)
            if f"ROLE_MEMORY:{role.value}" in self.artifacts.targets:
                self.artifacts.preflight_memory(role.value, self.memory_authority, role_files=role_files)
            state.role_context_refs[role.value] = invocation.context_ref
            state.memory_completed_roles.append(role.value)
            result_ref = self._save_artifact(state, "ROLE_EXPERIENCE", json.dumps(result, ensure_ascii=False))
            self._save_artifact(state, "ROLE_EXPERIENCE", json.dumps({"origin": "HOST_MEMORY_RECEIPT",
                                "role": role.value, "outcome": "UPDATED" if updated_ref else "NO_CHANGE",
                                "updated_ref": updated_ref, "result_ref": result_ref,
                                "invocation": invocation.metadata}, ensure_ascii=False))
        return True

    def run(self, max_steps: int = 100) -> WorkflowState:
        if max_steps < 1:
            raise WorkflowError("positive step bound required")
        for _ in range(max_steps):
            self.state.validate()
            if Node(self.state.current_node) in STOP_NODES or Node(self.state.current_node) in WINDOW_NODES:
                return self.state
            self.step()
        raise WorkflowError("step bound reached; no automatic unbounded continuation")

    def _managed_selected(self, task_id):
        # Configuration selects a backend; it never supplies an owned proof.
        from .implementation import MANAGED_CODEX_CLI
        return (getattr(self.executor, 'managed_task', lambda task: False)(task_id)
                or getattr(getattr(self.executor, 'implementation_config', None), 'backend', None) == MANAGED_CODEX_CLI)

    @staticmethod
    def _known_closed_handoff(closed, bound_input, before_ref):
        if (set(closed) != {'origin', 'closed', 'runtime_ref', 'role_ledger_ref', 'native_ledger_ref'}
                or closed.get('origin') != 'HOST_CLOSED_PROTECTED_STOP_HANDOFF' or closed.get('closed') is not True):
            raise WorkflowError('named closed handoff requires original runtime and usage sources')
        runtime = bound_input(closed['runtime_ref'])
        if (runtime.get('origin') != 'HOST_VERIFIED_CLOSED_PROTECTED_STOP'
                or runtime.get('original_state_ref') != before_ref
                or runtime.get('phase') != 'CLOSED' or runtime.get('lease_status') != 'RELEASED'
                or runtime.get('in_flight') is not None or runtime.get('unknown_effects') is not False
                or not isinstance(runtime.get('original_close_ref'), str)
                or '#sha256=' not in runtime['original_close_ref']
                or any(type(runtime.get(k)) is not int or runtime[k] != 0 for k in
                       ('writers', 'workers', 'supervisors', 'adapter_processes', 'native_resources'))):
            raise WorkflowError('named handoff closure/effects are not verified')
        for key, count in (('role_ledger_ref', 'role_calls'), ('native_ledger_ref', 'native_calls')):
            ledger = bound_input(closed[key])
            content = ledger.get('content')
            source = ledger.get('source_ref', '')
            if (ledger.get('origin') != 'HOST_VERIFIED_USAGE_LEDGER' or not isinstance(content, str)
                    or not isinstance(source, str) or '#sha256=' not in source
                    or digest(content) != source.rsplit('#sha256=', 1)[1]):
                raise WorkflowError('named handoff usage source is missing or changed')
            rows = [json.loads(line, object_pairs_hook=unique_json_object) for line in content.splitlines()]
            if (type(runtime.get(count)) is not int or runtime[count] < 0
                    or len(rows) != runtime[count] or any(not isinstance(row, dict) for row in rows)):
                raise WorkflowError('named handoff must retain actual nonzero-call consumption')
        return runtime

    def _same_task_owner_receipts(self, state):
        # DECISION also contains model-authored prose; only Host handoffs name receipts.
        for ref in reversed(self._refs(state, 'DECISION_HANDOFF')):
            finding = self.artifacts.read_json(ref)
            if (finding.get('origin') != 'HOST_INTERNAL_ESCALATION'
                    or finding.get('owner_event') != 'REQUEST_SAME_TASK_REPAIR'
                    or (finding.get('stage_id'), finding.get('task_id')) != (state.stage_id, state.task_id)):
                continue
            source = finding.get('original_result_ref')
            if (finding.get('origin_role') != Role.DECISION.value
                    or finding.get('category') != 'OWNER_INPUT'
                    or finding.get('resume_node') not in {Node.HUMAN_BLOCK.value, Node.RECOVERY_REQUIRED.value}
                    or finding.get('origin_activity') != finding.get('resume_node')
                    or source not in self._refs(state, 'DECISION')):
                raise WorkflowError('same-task Owner handoff provenance mismatch')
            receipt = self.artifacts.read_json(source)
            if (receipt.get('origin') != 'HOST_OWNER_SAME_TASK_REPAIR_REQUEST'
                    or receipt.get('task_id') != state.task_id):
                raise WorkflowError('same-task Owner mediation receipt mismatch')
            yield receipt

    def _named_internal_repair_applied(self, state):
        for receipt in self._same_task_owner_receipts(state):
            raw = self.authority.get(receipt.get('authorization_ref'), '')
            if raw and json.loads(raw, object_pairs_hook=unique_json_object).get('origin') == 'OWNER_KNOWN_INTERNAL_FINDING_REPAIR_AUTHORIZATION':
                return True
        return False

    def _owner_post_repair_review_available(self, state, *, completed=False):
        # One explicit Owner grant over saved inputs; never reset the old flag.
        if (not getattr(self.executor, 'managed_task', lambda task: False)(state.task_id)
                or not state.normal_repair_used):
            return False
        for receipt in self._same_task_owner_receipts(state):
            auth_ref = receipt.get('authorization_ref')
            raw = self.authority.get(auth_ref)
            if not isinstance(raw, str) or not isinstance(auth_ref, str) or digest(raw) != auth_ref.rsplit('#sha256=', 1)[-1]:
                raise WorkflowError('post-repair review Owner authority changed')
            auth = json.loads(raw, object_pairs_hook=unique_json_object)
            if auth.get('origin') != 'OWNER_KNOWN_INTERNAL_FINDING_REPAIR_AUTHORIZATION':
                continue
            if (not any(e.get('event') == 'REQUEST_SAME_TASK_REPAIR'
                        and e.get('authorization_id') == auth['authorization_id'] for e in state.human_events)
                    or any(auth.get(k) != v for k, v in {'project': state.project, 'stage_id': state.stage_id,
                        'task_id': state.task_id, 'workspace': self.grant().workspace,
                        'intent_ref': state.formal_task_intent_ref, 'final_ref': state.formal_constraint_ref,
                        'stop_ref': receipt['prior_handoff_ref']}.items())
                    or type(auth.get('post_repair_review_limit')) is not int or auth['post_repair_review_limit'] != 1):
                raise WorkflowError('post-repair review requires the applied exact Owner event')
            for source in (auth['owner_source_ref'], auth['admission_ref']):
                text = self.authority.get(source)
                if not isinstance(text, str) or digest(text) != source.rsplit('#sha256=', 1)[-1]:
                    raise WorkflowError('post-repair review admission/source changed')
            reviews = [r for r in self._refs(state, 'INDEPENDENT_REVIEW')
                       if Path(r.rsplit('#sha256=', 1)[0]).name.startswith(f'{state.task_id}_INDEPENDENT_REVIEW_')]
            prior = auth['prior_review_refs']
            if (reviews[:len(prior)] != prior or len(reviews) != len(prior) + int(completed)
                    or state.latest_execution_report_ref == auth['report_ref']):
                return False
            self.artifacts.assert_task_reference(state.latest_execution_report_ref, 'EXECUTION_REPORT', state.task_id)
            # Requires current owned implementation/source/tests, not old metadata.
            report = self.artifacts.read_json(self._refs(state, 'REPORT_RESULT')[-1])
            if not self._executor_report_eligible(state, report):
                return False
            return True
        return False

    def _same_task_repair_authority(self, state, evidence_refs, *, stop_ref=None, mediation_ref=None):
        """Validate Host-supplied admission; model artifacts never grant recovery."""
        current_decision = (stop_ref is not None and mediation_ref is not None
                            and state.current_node == Node.DECISION_MEDIATION.value
                            and state.in_flight_activity == Node.DECISION_MEDIATION.value)
        if ((state.in_flight_activity and not current_decision) or not state.task_id or state.acceptance_ref or state.commit_receipt
                or state.task_id in state.task_checkpoint_refs or not state.latest_execution_report_ref):
            raise WorkflowError('same-task recovery requires a known, unaccepted, reported Task')
        stop_ref = stop_ref or state.decision_handoff_ref
        mediation_ref = mediation_ref or state.mediation_result_ref
        stop = self.artifacts.read_json(stop_ref)
        decision = self.artifacts.read_json(mediation_ref)
        if (stop.get('origin') != 'HOST_INTERNAL_ESCALATION'
                or (stop.get('stage_id'), stop.get('task_id')) != (state.stage_id, state.task_id)
                or stop.get('category') not in {'TRUE_UNRESOLVED_BLOCKER', 'INTERNAL_FINDING'}
                or stop.get('resume_node') not in {Node.EXECUTOR_IMPLEMENT.value, Node.PROMOTER_RESULT_REVIEW.value}
                or (decision.get('mediation') or {}).get('handoff_ref') != stop_ref
                or (decision.get('mediation') or {}).get('outcome') not in {'HARD_GATE', 'SAFE_STOP'}):
            raise WorkflowError('same-task recovery requires the original protected Task stop')
        if not self.grant().contains(state.task_id, stage=state.stage_id):
            raise WorkflowError('same-task recovery is outside the actual scope grant')
        for kind, ref in (('TASK_INTENT', state.formal_task_intent_ref),
                          ('FINAL_TASK_CONSTRAINT', state.formal_constraint_ref),
                          ('EXECUTION_REPORT', state.latest_execution_report_ref)):
            if ref not in self._refs(state, kind):
                raise WorkflowError('same-task recovery source is not registered')
            self.artifacts.assert_task_reference(ref, kind, state.task_id)
            self.artifacts.read(ref)

        def bound_input(ref):
            if not isinstance(ref, str):
                raise WorkflowError('same-task authority reference must be text')
            raw = self.authority.get(ref)
            path, separator, expected = ref.rpartition('#sha256=')
            if not isinstance(raw, str) or not separator or digest(raw) != expected:
                raise WorkflowError('same-task recovery requires digest-bound actual Host authority')
            try:
                return json.loads(raw, object_pairs_hook=unique_json_object)
            except (TypeError, ValueError) as exc:
                raise WorkflowError('invalid same-task Host authority') from exc

        candidates = []
        for ref in evidence_refs:
            raw = self.authority.get(ref)
            if not isinstance(raw, str):
                continue
            try:
                value = json.loads(raw, object_pairs_hook=unique_json_object)
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict) and value.get('origin') in {
                    'OWNER_SAME_TASK_REPAIR_AUTHORIZATION', 'OWNER_KNOWN_INTERNAL_FINDING_REPAIR_AUTHORIZATION'}:
                candidates.append((ref, bound_input(ref)))
        if len(candidates) != 1:
            raise WorkflowError('exactly one actual Owner same-task authorization is required')
        ref, value = candidates[0]
        named_internal = stop['category'] == 'INTERNAL_FINDING'
        expected = {'origin': ('OWNER_KNOWN_INTERNAL_FINDING_REPAIR_AUTHORIZATION' if named_internal
                              else 'OWNER_SAME_TASK_REPAIR_AUTHORIZATION'), 'project': state.project,
            'stage_id': state.stage_id, 'task_id': state.task_id, 'workspace': self.grant().workspace,
            'intent_ref': state.formal_task_intent_ref, 'final_ref': state.formal_constraint_ref,
            'report_ref': state.latest_execution_report_ref, 'stop_ref': stop_ref}
        extra = {'prior_review_refs', 'post_repair_review_limit'} if named_internal else set()
        if (set(value) != set(expected) | {'authorization_id', 'owner_source_ref', 'admission_ref', 'reason'} | extra
                or any(value.get(key) != item for key, item in expected.items())
                or not isinstance(value['reason'], str) or not value['reason'].strip()):
            raise WorkflowError('same-task Owner authorization does not match the current Task')
        identity(value['authorization_id'])
        if named_internal:
            reviews = [r for r in self._refs(state, 'INDEPENDENT_REVIEW')
                       if Path(r.rsplit('#sha256=', 1)[0]).name.startswith(f'{state.task_id}_INDEPENDENT_REVIEW_')]
            if (value['prior_review_refs'] != reviews or type(value['post_repair_review_limit']) is not int
                    or value['post_repair_review_limit'] != 1):
                raise WorkflowError('named internal repair requires the exact prior reviews and one final review')
        source = value['owner_source_ref']
        if not isinstance(source, str):
            raise WorkflowError('actual Owner source reference must be text')
        raw_source = self.authority.get(source)
        _, separator, expected_digest = source.rpartition('#sha256=')
        if (not isinstance(raw_source, str) or not raw_source.strip() or not separator
                or digest(raw_source) != expected_digest):
            raise WorkflowError('actual Owner source is missing or changed')
        admission = bound_input(value['admission_ref'])
        if (not isinstance(admission, dict)
                or admission.get('origin') != 'HOST_SAME_TASK_REPAIR_ADMISSION'
                or any(admission.get(key) != expected[key] for key in
                       ('project', 'stage_id', 'task_id', 'workspace', 'intent_ref', 'final_ref', 'report_ref', 'stop_ref'))
                or admission.get('effects_status') != 'KNOWN'
                or admission.get('physical_closed') is not True
                or type(admission.get('unknown_or_inflight')) is not int or admission['unknown_or_inflight'] != 0
                or admission.get('prerequisites_verified') is not True):
            raise WorkflowError('known physical effects and actual repair admission are required')
        if state.current_node == Node.RECOVERY_REQUIRED.value:
            restart = admission.get('restart_evidence')
            if (not isinstance(restart, dict) or set(restart) !=
                    {'origin', 'before_state_ref', 'after_state_sha256', 'closed_host_ref'}
                    or restart.get('origin') not in ({'HOST_KNOWN_ZERO_CALL_RESTART',
                        'HOST_KNOWN_CLOSED_PROTECTED_STOP_HANDOFF'} if named_internal else {'HOST_KNOWN_ZERO_CALL_RESTART'})):
                raise WorkflowError('restart same-task repair requires exact known zero-call evidence')
            prior = bound_input(restart['before_state_ref'])
            try:
                previous = WorkflowState(**prior)
                previous.validate()
            except (TypeError, ValueError) as error:
                raise WorkflowError('invalid original protected-stop checkpoint') from error
            current = state.as_dict()
            remaining = {'current_node', 'status', 'human_gate_reason'}
            if (previous.current_node != Node.HUMAN_BLOCK.value or previous.in_flight_activity
                    or previous.status != 'WAITING_HUMAN' or not previous.waiting_human
                    or current['status'] != 'RECOVERY_REQUIRED' or not state.waiting_human
                    or {k: v for k, v in prior.items() if k not in remaining} !=
                       {k: v for k, v in current.items() if k not in remaining}
                    or restart['after_state_sha256'] != digest(json.dumps(current, ensure_ascii=False, sort_keys=True))):
                raise WorkflowError('restart must preserve the exact original HumanBlock and all effects')
            closed = bound_input(restart['closed_host_ref'])
            if restart['origin'] == 'HOST_KNOWN_CLOSED_PROTECTED_STOP_HANDOFF':
                runtime = self._known_closed_handoff(closed, bound_input, restart['before_state_ref'])
            else:
                if (set(closed) != {'origin', 'closed', 'model_calls', 'provider_calls', 'executor_dispatches',
                               'owner_events', 'runtime_ref'}
                    or closed.get('origin') != 'HOST_CLOSED_ZERO_CALL_RESTART' or closed.get('closed') is not True
                    or any(type(closed.get(k)) is not int or closed[k] != 0 for k in
                           ('model_calls', 'provider_calls', 'executor_dispatches', 'owner_events'))):
                    raise WorkflowError('restart Host must be closed with no calls or dispatches')
                runtime = bound_input(closed['runtime_ref'])
                if runtime.get('closed') is not True or runtime.get('steps') != [] or runtime.get('last_turn') is not None:
                    raise WorkflowError('restart runtime does not prove a closed zero-turn Host')
            sources = admission.get('source_evidence_refs', [])
            required = [restart['before_state_ref'], restart['closed_host_ref'], closed['runtime_ref']]
            if restart['origin'] == 'HOST_KNOWN_CLOSED_PROTECTED_STOP_HANDOFF':
                required.extend((closed['role_ledger_ref'], closed['native_ledger_ref']))
            if any(r not in sources for r in required):
                raise WorkflowError('restart evidence must be explicitly registered in Host admission')
        sources = admission.get('source_evidence_refs')
        known = set(self.authority) | {r for refs in state.artifact_refs.values() for r in refs}
        if not isinstance(sources, list) or not sources or any(not isinstance(r, str) or r not in known for r in sources):
            raise WorkflowError('same-task admission requires registered source evidence')
        for source_ref in sources:
            if source_ref in self.authority:
                _, marker, sha = source_ref.rpartition('#sha256=')
                if not marker or digest(self.authority[source_ref]) != sha:
                    raise WorkflowError('same-task admission source changed')
            else:
                self.artifacts.read(source_ref)
        if not self._allowance_available(state, 'repair'):
            raise WorkflowError('same-task repair allowance is exhausted; Owner event never replenishes it')
        return ref, value

    def validate_same_task_repair_delegation(self):
        """Only an already-applied, fully rechecked same-task Owner mediation."""
        state = self.state
        if self._busy or state.in_flight_activity or state.current_node != Node.DECISION_MEDIATION.value:
            raise WorkflowError('same-task delegation requires idle Owner mediation')
        finding = self.artifacts.read_json(state.decision_handoff_ref)
        if (finding.get('owner_event') != 'REQUEST_SAME_TASK_REPAIR'
                or finding.get('category') != 'OWNER_INPUT' or finding.get('task_id') != state.task_id
                or finding.get('origin_role') != Role.DECISION.value
                or finding.get('resume_node') not in {Node.HUMAN_BLOCK.value, Node.RECOVERY_REQUIRED.value}
                or finding.get('origin_activity') != finding.get('resume_node')):
            raise WorkflowError('ordinary mediation cannot acquire same-task delegation')
        receipt = self.artifacts.read_json(finding['original_result_ref'])
        if receipt.get('origin') != 'HOST_OWNER_SAME_TASK_REPAIR_REQUEST' or receipt.get('task_id') != state.task_id:
            raise WorkflowError('same-task Owner mediation receipt mismatch')
        ref, value = self._same_task_repair_authority(state, receipt['evidence_refs'],
            stop_ref=receipt['prior_handoff_ref'], mediation_ref=receipt['prior_mediation_ref'])
        if (receipt.get('authorization_ref') != ref or not any(
                event.get('event') == 'REQUEST_SAME_TASK_REPAIR'
                and event.get('authorization_id') == value['authorization_id'] for event in state.human_events)):
            raise WorkflowError('same-task delegation requires the actual applied Owner event')
        self.preflight_task(state.task_id, grant=self.grant())
        return state.task_id

    def validate_same_task_repair_request(self, *, direction: str, evidence_refs: list[str]):
        """Read-only preflight before a Host starts recording possible effects."""
        self.state.validate()
        if (self._busy or self.state.current_node not in {Node.HUMAN_BLOCK.value, Node.RECOVERY_REQUIRED.value}
                or self.state.owner_accepted or not isinstance(direction, str) or not direction.strip()
                or not isinstance(evidence_refs, list) or not evidence_refs
                or any(not isinstance(ref, str) or not ref.strip() for ref in evidence_refs)):
            raise WorkflowError('same-task repair requires an explicit Owner request at a known protected stop')
        authority = self._same_task_repair_authority(self.state, evidence_refs)
        if any(e.get('authorization_id') == authority[1]['authorization_id'] for e in self.state.human_events):
            raise WorkflowError('same-task Owner authorization was already used')
        return authority

    def owner_event(self, event: str, *, direction: str, evidence_refs: list[str]) -> WorkflowState:
        self.state.validate()
        node = Node(self.state.current_node)
        if (self._busy or not isinstance(direction, str) or not direction.strip() or not isinstance(evidence_refs, list)
                or not evidence_refs or any(not isinstance(ref, str) or not ref.strip() for ref in evidence_refs) or self.state.owner_accepted):
            raise WorkflowError("explicit Owner direction/evidence required")
        allowed = {Node.HUMAN_GATE: {"APPROVE_STAGE", "REJECT_STAGE", "REQUEST_MORE_WORK"},
                   Node.SOFT_ACCEPTANCE_WAIT: {"APPROVE_STAGE", "REJECT_STAGE", "REQUEST_MORE_WORK"},
                   Node.HUMAN_BLOCK: {"RESOLVE_HUMAN_BLOCK", "REQUEST_SAME_TASK_REPAIR"},
                   Node.RECOVERY_REQUIRED: {"RESOLVE_HUMAN_BLOCK", "REQUEST_SAME_TASK_REPAIR"}}
        if event not in allowed.get(node, set()):
            raise WorkflowError("Owner event is invalid at this node")
        repair_authority = (self.validate_same_task_repair_request(direction=direction, evidence_refs=evidence_refs)
                            if event == 'REQUEST_SAME_TASK_REPAIR' else None)
        state = copy.deepcopy(self.state)
        self.executor.suspend()
        state.human_events.append({"event": event, "direction": direction, "evidence": json.dumps(evidence_refs)})
        if event == 'REQUEST_SAME_TASK_REPAIR':
            state.human_events[-1]['authorization_id'] = repair_authority[1]['authorization_id']
            prior_stop, prior_mediation = state.decision_handoff_ref, state.mediation_result_ref
            ref = self._save_artifact(state, 'DECISION', json.dumps({
                'origin': 'HOST_OWNER_SAME_TASK_REPAIR_REQUEST', 'task_id': state.task_id,
                'authorization_ref': repair_authority[0], 'evidence_refs': evidence_refs,
                'prior_handoff_ref': prior_stop, 'prior_mediation_ref': prior_mediation,
                'direction': direction, 'owner_accepted': False}, ensure_ascii=False))
            self._prepare_mediation(state, node, Role.DECISION, ref, {
                'origin_role': Role.DECISION.value, 'origin_activity': node.value,
                'stage_id': state.stage_id, 'task_id': state.task_id, 'category': 'OWNER_INPUT',
                'reason': direction, 'evidence_refs': list(dict.fromkeys([
                    *evidence_refs, repair_authority[1]['owner_source_ref'],
                    repair_authority[1]['admission_ref'], prior_stop, prior_mediation,
                    state.formal_task_intent_ref, state.formal_constraint_ref, state.latest_execution_report_ref])),
                'requested_treatment': 'SAME_TASK_REPAIR'}, owner_event=event)
            state.latest_decision_notice_ref = None
            self._move(state, Node.DECISION_MEDIATION)
        elif event == "APPROVE_STAGE":
            if not state.machine_close_ready:
                raise WorkflowError("Owner acceptance requires machine close evidence")
            state.owner_accepted = True
            state.stage_closed = bool(state.stage_closeout_ref and state.stage_knowledge_ref)
            self._move(state, Node.COMPLETED)
        elif event == "REJECT_STAGE":
            self._move(state, Node.HUMAN_BLOCK, direction)
        else:
            # Directed recovery restarts with read-only actual-state review, never old writes/commit.
            state.machine_close_ready = False
            state.stage_closed = False
            state.memory_completed_roles = []
            state.stage_acceptance_ref = state.stage_knowledge_ref = state.stage_closeout_ref = None
            state.latest_decision_notice_ref = None
            state.in_flight_activity = None
            state.last_result = {"owner_direction": direction, "evidence_refs": evidence_refs}
            self._clear_override(state)
            self._move(state, Node.STAGE_REVIEW if event == 'RESOLVE_HUMAN_BLOCK' else Node.STAGE_ACCEPTANCE)
        self.store.save(state)
        self.state = state
        return state
