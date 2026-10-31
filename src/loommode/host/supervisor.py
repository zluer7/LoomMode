"""Live event-driven mechanics around one retained DecisionHost, never a role."""
from __future__ import annotations

import copy
import hashlib
import json
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue
from threading import Condition, Event, Thread, current_thread
from typing import Any
from uuid import uuid4

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import identity
from loommode.workflow.transitions import Node, Role, STOP_NODES
from .driver import DecisionHost
from .requests import DelegationRequest, OwnerRequest
from .state_view import _digest
from .terminal import classify_managed, render_final_reply
from .ownership import WorkspaceLease
from loommode.workflow.governance import scope_name, digest
from loommode.workflow.transitions import WINDOW_NODES


@dataclass(frozen=True)
class SupervisorEvent:
    """A one-use, ordered input to this live run, bound to displayed facts."""
    run_id: str
    project: str
    stage_id: str
    delegation_request_id: str
    task_id: str | None
    sequence: int
    expected_revision: str
    kind: str = "ADVANCE"
    owner_request: OwnerRequest | None = None


@dataclass
class _Operation:
    event: SupervisorEvent
    operation_id: str = field(default_factory=lambda: "W" + uuid4().hex)
    thread: Thread | None = None
    finished: Event = field(default_factory=Event)
    outcome: dict[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True)
class _Completion:
    operation: _Operation


_CLOSE = object()
_WINDOW_WAKE = object()
_OWNER_STOP = object()


class SupervisorHost:
    """Same-process retention; explicit events perform one existing bounded call.

    Both threads are non-daemon. The caller must close/join this Host before
    exiting. Saved artifacts cannot construct or resume a managed run.
    """
    def __init__(self, host: DecisionHost, *, run_id: str | None = None,
                 history_limit: int = 25, renewal_every: int = 0) -> None:
        if not isinstance(host, DecisionHost):
            raise WorkflowError("Supervisor requires the existing bound DecisionHost")
        if type(history_limit) is not int or not 1 <= history_limit <= 100:
            raise WorkflowError("managed event history limit must be 1..100")
        if type(renewal_every) is not int or not 0 <= renewal_every <= 10000:
            raise WorkflowError("renewal threshold must be 0..10000 joined Workers")
        self.host, self.entry = host, host.entry
        self.run_id = identity(run_id if run_id is not None else "M" + uuid4().hex)
        self._condition = Condition()
        self._queue = Queue()
        self._history = deque(maxlen=history_limit)
        self._binding: dict[str, Any] | None = None
        self._selection = None
        self._phase = "NEW"
        self._sequence = 0
        self._pending: SupervisorEvent | None = None
        self._operation: _Operation | None = None
        self._last_operation = None
        self._last_owner_response = None
        self._thread: Thread | None = None
        self._loop_waiting = False
        self._closing = False
        self._failure: str | None = None
        self._lease_released = False
        self._automatic = False
        self._update_cursor = 0
        self._final_delivery = None
        self._reached_boundary = None
        self._workspace_lease = None
        self._external_workspace_lease = False
        self._started_workers = self._joined_workers = 0
        self._renewal_every = renewal_every
        self._renewal_requested = False
        self._last_renewal = None
        self._stage_candidates = {}
        self._completed_stages = []
        self.host.windows.notify = lambda: self._queue.put(_WINDOW_WAKE)

    def register_stage_candidate(self, engine):
        """Trusted startup registers a pinned unit; registration is not permission."""
        with self._condition:
            if self._selection is not None:
                raise WorkflowError('Stage candidates must be pinned before live run starts')
            if engine is self.host.engine or engine.state.current_node != Node.STAGE_START.value:
                raise WorkflowError('candidate must be a distinct unstarted Stage binding')
            if engine.state.project != self.host.engine.state.project or engine.stage_grant.workspace != str(self.entry.projection.workspace):
                raise WorkflowError('candidate Project/workspace differs')
            if engine.stage_grant.major_phase != self.host.engine.stage_grant.major_phase:
                raise WorkflowError('candidate crosses Major Phase')
            if engine.owned_adapters() != self.host.engine.owned_adapters():
                raise WorkflowError('handoff must retain same Adapter ownership')
            self._validate_candidate_runtime(engine)
            if engine.state.stage_id in self._stage_candidates:
                raise WorkflowError('duplicate Stage candidate')
            self._stage_candidates[engine.state.stage_id] = (engine, self._candidate_digest(engine))

    def _candidate_digest(self, engine):
        policy = getattr(engine.executor, 'stage_policy', None)
        return _digest({'state': engine.state.as_dict(), 'authority': engine.authority,
            'store': str(engine.store.path), 'artifacts': str(engine.artifacts.root),
            'targets': {k: str(v) for k, v in engine.artifacts.targets.items()},
            'target_digests': dict(engine.artifacts.target_digests),
            'maintenance_authorities': {k: sorted(v) for k, v in engine.artifacts.authorities.items()},
            'role_id': id(engine.roles), 'executor_id': id(engine.executor),
            'role_files': self._candidate_role_files(engine),
            'role_stage': getattr(engine.roles, 'stage_id', None),
            'role_adapter': id(getattr(engine.roles, 'adapter', None)),
            'executor_adapter': id(getattr(engine.executor, 'adapter', None)),
            'registry': id(getattr(getattr(engine.roles, 'adapter', None), 'registry', None)),
            'policy_provider': id(getattr(engine.executor, 'policy_provider', None)),
            'scope_grants': {k: v.as_dict() for k, v in engine.scope_grants.items()},
            'stage_policy': repr(policy), 'task_policies': repr(getattr(engine.executor, 'task_policies', None)),
            'role_policy': repr(getattr(engine.roles, 'policy', None)),
            'role_profiles': repr(getattr(getattr(engine.roles, 'profiles', None), 'defaults', None))})

    def _candidate_role_files(self, engine):
        """Pin exposed consumed paths, allowing lawful experience changes in place."""
        mapping = getattr(engine.roles, 'role_files', None)
        if mapping is None:
            return None
        roles = (Role.PROMOTER, Role.CONSTRAINT, Role.DISCUSSANT, Role.DECISION)
        if not isinstance(mapping, Mapping) or set(mapping) != set(roles):
            raise WorkflowError('candidate actual role-file mapping differs from four corresponding roles')
        return {role.value: str(Path(mapping[role]).resolve()) for role in roles}

    def _verify_candidate_binding(self, candidate, expected):
        self._validate_candidate_runtime(candidate)
        if (self._candidate_digest(candidate) != expected
                or json.loads(candidate.store.path.read_text(encoding='utf-8')) != candidate.state.as_dict()):
            raise WorkflowError('registered successor binding changed; handoff fenced')

    def _validate_candidate_runtime(self, engine):
        active = self.host.engine
        if getattr(engine.roles, 'stage_id', engine.state.stage_id) != engine.state.stage_id:
            raise WorkflowError('candidate role Stage identity mismatch')
        for component in ('roles', 'executor'):
            adapter = getattr(getattr(engine, component), 'adapter', None)
            if adapter is not getattr(getattr(active, component), 'adapter', None):
                raise WorkflowError('candidate must retain same Adapter/provider identity')
            if adapter is not None and adapter.registry is not self.entry.projection.registry:
                raise WorkflowError('candidate Registry differs from retained live binding')
        for policy in (getattr(engine.roles, 'policy', None), getattr(engine.executor, 'stage_policy', None)):
            if policy is not None and policy.workspace.resolve() != self.entry.projection.workspace:
                raise WorkflowError('candidate runtime policy workspace differs')

    def active_stage_binding(self):
        engine = self.host.engine
        return {'project': engine.state.project, 'stage_id': engine.state.stage_id,
                'workspace': str(self.entry.projection.workspace), 'stage_authorization_ref': engine.state.stage_input_ref,
                'stage_authorization_sha256': digest(engine.authority[engine.state.stage_input_ref]),
                'grants': self._grants(), 'registered_handoff': bool(self._completed_stages)}

    def _successor_target_reconciliation(self, candidate):
        """Accept only a verified predecessor promotion chain, never a blind refresh."""
        engine = self.host.engine
        key = 'MAJOR_PHASE_ISSUE_LEDGER'
        path = candidate.artifacts.targets.get(key)
        if path is None:
            return None
        pinned = candidate.artifacts.target_digests.get(key)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if pinned == actual:
            return None
        if engine.artifacts.targets.get(key) != path:
            raise WorkflowError('changed successor target lacks a shared predecessor binding')
        current, receipts, updated_ref = pinned, [], None
        for completed in self._completed_stages:
            for ref in completed.get('promotion_refs', []):
                row = engine.artifacts.read_json(ref)
                if (row.get('origin') != 'HOST_MAJOR_PHASE_PROMOTION' or row.get('source_stage') != completed['stage_id']
                        or row.get('previous_sha256') != current):
                    raise WorkflowError('successor target promotion receipt chain mismatch')
                updated_ref = row.get('updated_ref')
                target, current = updated_ref.rsplit('#sha256=', 1)
                if Path(target).resolve() != path:
                    raise WorkflowError('successor promotion receipt names a different target')
                receipts.append(ref)
        if not receipts or current != actual:
            raise WorkflowError('changed successor target lacks verified predecessor promotion evidence')
        engine.artifacts.read(updated_ref)
        return {'target': key, 'previous_sha256': pinned, 'updated_ref': updated_ref,
                'promotion_refs': receipts, 'source_stage': engine.state.stage_id}

    def pause_owner(self, request):
        with self._condition:
            value = self.host.request_stop(request)
            self._queue.put(_OWNER_STOP)
            self._condition.notify_all()
            return value

    def _successor_program_input(self, candidate):
        """Carry one explicitly shared current Program target through verified sync receipts."""
        engine, key = self.host.engine, 'PROGRAM_NOTE'
        path = candidate.artifacts.targets.get(key)
        if path is None:
            return None
        if engine.artifacts.targets.get(key) != path:
            raise WorkflowError('successor Program target lacks shared predecessor binding')
        current = pinned = candidate.artifacts.target_digests.get(key)
        refs, latest, source_stage = [], None, None
        for completed in self._completed_stages:
            for ref in completed.get('sync_application_refs', []):
                receipt = engine.artifacts.read_json(ref)
                if receipt.get('origin') != 'HOST_SYNC_RECEIPT' or receipt.get('stage_id') != completed['stage_id']:
                    raise WorkflowError('successor Program application receipt identity mismatch')
                for item in receipt['sync']:
                    if item['target'] != key or not item['updated_ref']:
                        continue
                    target, updated_sha = item['updated_ref'].rsplit('#sha256=',1)
                    authority = item['authority_ref']
                    if (Path(target).resolve()!=path or item.get('previous_sha256')!=current
                            or authority not in candidate.artifacts.authorities.get(key,set())
                            or not engine.authority.get(authority)
                            or engine.authority.get(authority)!=candidate.authority.get(authority)
                            or item.get('authority_sha256')!=digest(candidate.authority[authority])):
                        raise WorkflowError('successor Program sync chain/authority/target mismatch')
                    current, latest, source_stage = updated_sha, item, completed['stage_id']
                    refs.append(ref)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=current:
            raise WorkflowError('successor current Program target changed without verified sync evidence')
        if not latest:
            return None
        engine.artifacts.read(latest['updated_ref'])
        return {'target':key,'updated_ref':latest['updated_ref'],'source_stage':source_stage,
            'previous_sha256':pinned,'application_refs':refs,'authority_ref':latest['authority_ref'],
            'authority_sha256':latest['authority_sha256']}

    def _handoff(self):
        """Called only by serialized loop after join and actual soft close."""
        engine = self.host.engine
        grant = engine.grant()
        if not engine.state.stage_closed or self.host.stop_requested:
            return False
        completed = {row['stage_id'] for row in self._completed_stages}
        if engine.state.stage_id not in completed:
            self._completed_stages.append({'stage_id': engine.state.stage_id, 'closeout_ref': engine.state.stage_closeout_ref,
                'knowledge_ref': engine.state.stage_knowledge_ref, 'store': str(engine.store.path),
                'promotion_refs': list(engine.state.artifact_refs.get('MAJOR_PHASE_PROMOTION', [])),
                'sync_application_refs': list(engine.state.artifact_refs.get('SYNC_APPLICATION', [])),
                'owner_accepted': engine.state.owner_accepted, 'checkpoints': dict(engine.state.task_checkpoint_refs)})
        if grant.scope not in {'MAJOR_PHASE', 'EXPLICIT_BOUNDED_SCOPE'}:
            return False
        remaining = [stage for stage in grant.stage_ids if stage not in {row['stage_id'] for row in self._completed_stages}]
        if not remaining:
            if len(grant.stage_ids) > 1 and not engine.state.scope_completion:
                self._complete_broader_scope(grant)
            return False
        if self._operation or self._pending:
            raise WorkflowError('Stage handoff requires joined Worker and empty dispatch slot')
        pair = self._stage_candidates.get(remaining[0])
        if not pair:
            raise WorkflowError('authorized successor is not explicitly registered/pinned')
        candidate, expected = pair
        self._verify_candidate_binding(candidate, expected)
        if candidate.scope_grants.get(grant.authority_ref) != grant:
            raise WorkflowError('successor lacks the same actual broader Owner grant')
        if candidate.commit_authorized != engine.commit_authorized:
            raise WorkflowError('successor changes checkpoint permission')
        reconciled_target = self._successor_target_reconciliation(candidate)
        program_input = self._successor_program_input(candidate)
        engine.artifacts.read(engine.state.stage_closeout_ref)
        engine.artifacts.read(engine.state.stage_knowledge_ref)
        for component in (engine.roles, engine.executor):
            renew = getattr(component, 'renew_contexts', None)
            if renew:
                outcome = renew()
                if outcome.get('preserved'):
                    raise WorkflowError('old Stage contexts remain protected; no relabel/handoff')
        from .state_view import StateProjection
        registry = self.entry.projection.registry
        workspace = self.entry.projection.workspace
        owner = getattr(engine, '_managed_host_owner', None)
        with self.host._managed_operation(self), self.host._exclusive():
            # Retirement can run callbacks; verify again before adopting any binding.
            self._verify_candidate_binding(candidate, expected)
            for key in ('state', 'store', 'artifacts', 'roles', 'executor', 'authority', 'commit_authorized',
                        'memory_authority', 'scope_grants', 'stage_grant'):
                setattr(engine, key, getattr(candidate, key))
            engine.state.active_grant = grant.as_dict()
            if reconciled_target:
                engine.artifacts.target_digests[reconciled_target['target']] = reconciled_target['updated_ref'].rsplit('#sha256=', 1)[1]
                engine._save_artifact(engine.state, 'DECISION', json.dumps({
                    'origin': 'HOST_SUCCESSOR_TARGET_REBIND', 'target_stage': engine.state.stage_id, **reconciled_target}))
            if program_input:
                engine.artifacts.target_digests[program_input['target']] = program_input['updated_ref'].rsplit('#sha256=',1)[1]
                ref = engine._save_artifact(engine.state,'DECISION',json.dumps({
                    'origin':'HOST_SUCCESSOR_PROGRAM_INPUT','target_stage':engine.state.stage_id,**program_input}))
                engine.state.artifact_refs.setdefault('PROGRAM_INPUT',[]).append(ref)
            engine.store.save(engine.state)
            self.entry.projection = StateProjection(project=engine.state.project, stage_id=engine.state.stage_id,
                workspace=workspace, artifacts=engine.artifacts, registry=registry, state_provider=lambda: engine.state,
                source_ref=str(engine.store.path), authority_materials=engine.authority, is_busy=lambda: engine._busy)
            self.entry.roles = engine.roles if hasattr(engine.roles, 'explain_status') else None
            self.host.windows.next_stage()
            target = self.host._delegation['target']
            target.update(stage_id=engine.state.stage_id, stage_authorization_ref=engine.state.stage_input_ref,
                          stage_authorization_sha256=digest(engine.authority[engine.state.stage_input_ref]))
            self.host._delegation.update(status='PENDING', expected_state=_digest(engine.state.as_dict()), active_task=(None, None, None))
            self.host._persist_delegation()
            self._binding.update(stage_id=target['stage_id'], stage_authorization_ref=target['stage_authorization_ref'],
                                 stage_authorization_sha256=target['stage_authorization_sha256'], series=None)
        assert getattr(engine, '_managed_host_owner', None) is owner
        return True

    def _complete_broader_scope(self, grant):
        engine = self.host.engine
        rows = copy.deepcopy(self._completed_stages)
        if {row['stage_id'] for row in rows} != set(grant.stage_ids):
            raise WorkflowError('broader completion omits declared Stage membership')
        for row in rows:
            row['checkpoints'] = {task: ref for task, ref in row['checkpoints'].items()
                                  if grant.contains(task, stage=row['stage_id'], relationship_check=False)}
        checkpoints = {task: ref for row in rows for task, ref in row['checkpoints'].items()}
        if grant.scope == 'EXPLICIT_BOUNDED_SCOPE' and set(checkpoints) != set(grant.task_ids):
            raise WorkflowError('broader bounded completion omits declared accepted Task membership')
        references = [ref for row in rows for ref in (row['closeout_ref'], row['knowledge_ref'],
                                                     *row['checkpoints'].values(), *row.get('promotion_refs', []))]
        for ref in references:
            engine.artifacts.read(ref)
        completion = {'origin': 'HOST_BOUND_SCOPE_COMPLETION', 'scope': grant.scope, 'scope_id': grant.scope_id,
            'authority_ref': grant.authority_ref, 'authority_sha256': grant.authority_sha256,
            'stage_results': rows, 'accepted_task_ids': list(checkpoints), 'checkpoint_refs': list(checkpoints.values()),
            'residuals': [f"Actual residual assessment: {row['knowledge_ref']}" for row in rows],
            'remaining_stage_work': ['Declared Stage membership exhausted; further work requires a new actual grant.'],
            'reason': 'All declared Stages reached actual fresh acceptance, Knowledge, final Decision closeout and soft/explicit acceptance boundaries.',
            'owner_accepted': False}
        with self.host._managed_operation(self), self.host._exclusive():
            ref = engine._save_artifact(engine.state, 'DECISION', json.dumps(completion, ensure_ascii=False))
            engine.state.scope_completion = {**completion, 'result_ref': ref}
            engine.store.save(engine.state)
            self.host._delegation.update(status='SCOPE_COMPLETED', stop_boundary=grant.scope,
                reason=completion['reason'], expected_state=_digest(engine.state.as_dict()))
            self.host._persist_delegation()

    def start(self, request: DelegationRequest, *, series_id: str | None = None,
              series_plan_ref: str | None = None, automatic: bool = False) -> dict[str, Any]:
        if not isinstance(request, DelegationRequest):
            raise WorkflowError("explicit live DelegationRequest required")
        request.validate()
        if type(automatic) is not bool:
            raise WorkflowError("automatic continuation must be an explicit boolean")
        selection = (request, series_id, series_plan_ref, automatic)
        with self._condition:
            if self._selection is not None:
                if selection != self._selection:
                    raise WorkflowError("managed run identity/scope cannot be replaced")
                if self._closing or self._phase == "CLOSED":
                    raise WorkflowError("closed managed Host cannot restart")
                return {**self.status(), "status": "ALREADY_STARTED"}
            if self._closing:
                raise WorkflowError("closed managed Host cannot start")
            if self.entry._managed_provider is not None:
                raise WorkflowError("Decision entry already retains a managed run; use its original live Host")
            if (series_id is None) != (series_plan_ref is None):
                raise WorkflowError("Series identity and Plan reference must both be explicit")
            series = None
            if series_id is not None:
                identity(series_id)
                if not isinstance(series_plan_ref, str) or not series_plan_ref:
                    raise WorkflowError("explicit Series Plan authority reference required")
                text = self.host.engine.authority.get(series_plan_ref)
                if not isinstance(text, str) or not text.strip() or self.entry.projection.authority.get(series_plan_ref) != text:
                    raise WorkflowError("Series Plan must already be explicitly registered in Engine and projection authority")
                series = {"series_id": series_id, "plan_ref": series_plan_ref,
                          "plan_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
            self.host._bound_snapshot()
            lease = getattr(self.host.engine, "_workspace_writer_lease", None)
            if lease is None:
                lease = WorkspaceLease(self.entry.projection.workspace)
                if not lease.acquire():
                    raise WorkflowError("workspace already has a live/unknown writer; use its original Host")
                lease.owner = self.host.engine
                self.host.engine._workspace_writer_lease = lease
            else:
                self._external_workspace_lease = True
            self._workspace_lease = lease
            try:
                self.host._claim_managed_run(self)
            except Exception:
                if not self._external_workspace_lease:
                    lease.release()
                    del self.host.engine._workspace_writer_lease
                self._workspace_lease = None
                raise
            self._selection = selection
            self._automatic = automatic
            self._phase = "RUNNING"
            try:
                with self.host._managed_operation(self):
                    self.host.start(request)
                facts, _ = self.host._delegation_facts()
                if facts is None or facts["status"] != "PENDING" or facts["request_id"] != request.request_id:
                    raise WorkflowError("managed start requires this live pending delegation")
                self._binding = {"project": request.project, "stage_id": request.stage_id,
                    "workspace": request.workspace, "stage_authorization_ref": request.stage_authorization_ref,
                    "stage_authorization_sha256": request.stage_authorization_sha256,
                    "delegation_request_id": request.request_id, "scope": request.scope,
                    "target_task_id": request.task_id, "series": series,
                    "grants": self._grants()}
                self.entry.bind_managed_provider(self._managed_projection)
                self._thread = Thread(target=self._run_loop, name=f"loommode-supervisor-{self.run_id}")
                self._thread.start()
                self._condition.wait_for(lambda: self._loop_waiting or self._failure is not None)
            except Exception as exc:
                self._failure, self._phase = f"Managed startup failed; inspect actual effects: {exc}", "STOPPED"
                raise
        return {**self.status(), "status": "MANAGED_STARTED"}

    def _grants(self):
        return {"allow_progress": self.host.allow_progress, "allow_owner_events": self.host.allow_owner_events,
                "local_commit_authorized": self.host.engine.commit_authorized}

    def _queue_automatic(self) -> None:
        """Initial kick or a joined completion, never a timer or business choice."""
        if not self._automatic or self._closing or self._failure or self._pending or self._operation or self.host.stop_requested:
            return
        facts, _ = self.host._delegation_facts()
        if Node(self.host.engine.state.current_node) in WINDOW_NODES:
            return
        if facts["status"] != "PENDING" or Node(self.host.engine.state.current_node) in STOP_NODES:
            return
        try:
            self.submit(self.event())
        except Exception as exc:
            self._failure = f"Automatic continuation stopped before dispatch; inspect bound facts: {exc}"
            self._phase = "STOPPED"

    def resume(self) -> dict[str, Any]:
        """Idempotent automatic wake-up; manual callers explicitly submit events."""
        with self._condition:
            if self._selection is None or not self._automatic:
                raise WorkflowError("resume/run requires an explicitly started automatic managed run")
            if self._closing:
                raise WorkflowError("closed managed Host cannot resume")
            self._queue_automatic()
            return {**self.status(), "status": "AUTO_RUNNING" if self._phase == "RUNNING" else "STOPPED"}

    def run(self) -> dict[str, Any]:
        return self.resume()

    def wait_for_update(self, after_cursor: int = 0, timeout: float | None = None) -> dict[str, Any]:
        """Wait for a new completion/close fact without model or state polling."""
        if type(after_cursor) is not int or after_cursor < 0:
            raise WorkflowError("update cursor must be a nonnegative integer")
        with self._condition:
            self._condition.wait_for(lambda: self._update_cursor > after_cursor or self._phase == "CLOSED", timeout)
            return {**self.status(), "status": "MANAGED_UPDATE", "cursor": self._update_cursor,
                    "changed": self._update_cursor > after_cursor}

    def _managed_projection(self):
        facts, materials = self._managed_facts(), {}
        completion = self.host.engine.state.scope_completion or {}
        if completion.get('origin') == 'HOST_BOUND_SCOPE_COMPLETION':
            for row in completion['stage_results']:
                for ref in (row['closeout_ref'], row['knowledge_ref'], *row['checkpoints'].values(), *row.get('promotion_refs', [])):
                    try:
                        materials[ref] = self.host.engine.artifacts.read(ref)
                    except (WorkflowError, OSError, ValueError) as exc:
                        facts['failure'] = 'Broader completion predecessor evidence is unverified: ' + str(exc)
        series = facts["binding"]["series"] if facts["binding"] else None
        if series:
            text = self.host.engine.authority.get(series["plan_ref"])
            verified = (isinstance(text, str) and hashlib.sha256(text.encode("utf-8")).hexdigest() == series["plan_sha256"]
                        and self.entry.projection.authority.get(series["plan_ref"]) == text)
            series["verification"] = "VERIFIED" if verified else "UNVERIFIED"
            if verified:
                materials[series["plan_ref"]] = text
        return facts, materials

    def _managed_facts(self) -> dict[str, Any]:
        with self._condition:
            operation, state = self._operation, self.host.engine.state
            alive = bool(self._thread and self._thread.is_alive())
            state_sha256 = _digest(state.as_dict())
            known_owner = next((record for record in reversed(list(self.host._requests.values()))
                if record.get("state_sha256") == state_sha256 and record["status"] in
                {"OWNER_EVENT_APPLIED", "QUEUED_FOR_PROMOTER", "NOT_DELIVERED_STAGE_COMPLETED"}), None)
            expected_state = (known_owner["state_sha256"] if known_owner else
                (self.host._delegation["expected_state"] if self.host._delegation else None))
            return {"run_id": self.run_id, "binding": copy.deepcopy(self._binding),
                'completed_stages': copy.deepcopy(self._completed_stages),
                "phase": self._phase, "runtime_alive": alive,
                "waiting_for_event": alive and self._loop_waiting,
                "accepting_events": alive and not self._closing and self._failure is None,
                "sequence": self._sequence, "pending_event": self._pending.kind if self._pending else None,
                "automatic": self._automatic, "update_cursor": self._update_cursor,
                "delivery": {"consumed": self._final_delivery is not None,
                             "notification_id": self._final_delivery["notification_id"] if self._final_delivery else None},
                "current_grants": self._grants(),
                "expected_state_sha256": expected_state,
                "known_owner_event": {"event": known_owner["request"]["event"], "node": known_owner["node"],
                                      "state_sha256": known_owner["state_sha256"]}
                                     if known_owner and known_owner["status"] == "OWNER_EVENT_APPLIED" else None,
                "reached_boundary": copy.deepcopy(self._reached_boundary),
                "cleanup": {"active_blocker_id": state.active_blocker_id,
                            "pending_override_task_id": state.pending_override_task_id},
                "in_flight": {"operation_id": operation.operation_id, "kind": operation.event.kind,
                              "sequence": operation.event.sequence,
                              "worker_alive": bool(operation.thread and operation.thread.is_alive())}
                             if operation else None,
                "current": {"task_id": state.task_id, "task_intent_ref": state.formal_task_intent_ref,
                            "final_ref": state.formal_constraint_ref, "report_ref": state.latest_execution_report_ref,
                            "stage_input_ref": state.stage_input_ref, "node": state.current_node,
                            "engine_in_flight": state.in_flight_activity},
                "last_operation": copy.deepcopy(self._last_operation),
                "last_owner_response": copy.deepcopy(self._last_owner_response), "failure": self._failure,
                "events": copy.deepcopy(list(self._history)),
                "resume_boundary": "SAME_LIVE_HOST_ONLY", "permissions_expanded": False,
                "lease_retained": getattr(self.host.engine, "_managed_host_owner", None) is self,
                "workspace_lease": {"held": bool(self._workspace_lease and self._workspace_lease.held),
                                    "workspace": self._workspace_lease.workspace if self._workspace_lease else None},
                "cancellation_supported": False}

    def status(self) -> dict[str, Any]:
        value = self.host.status()
        if "managed_run" not in value["facts"]:
            value["facts"]["managed_run"] = self._managed_facts()
            value["facts"]["managed_run"]["presentation"] = classify_managed(value["facts"], {})
        health = self.host.engine.resource_health()
        health.update({"supervisor_count": int(bool(self._thread and self._thread.is_alive())),
            "writer_count": int(bool(self._workspace_lease and self._workspace_lease.held)),
            "worker_count": int(bool(self._operation and self._operation.thread and self._operation.thread.is_alive())),
            "worker_limit": 1, "started_workers": self._started_workers, "joined_workers": self._joined_workers,
            "history_count": len(self._history), "history_limit": self._history.maxlen,
            "renewal_every": self._renewal_every, "last_renewal": copy.deepcopy(self._last_renewal)})
        if self._failure:
            health["reasons"] = [*health["reasons"], self._failure]
            health["status"] = "DEGRADED"
        value["resource_health"] = health
        return value

    def request_renewal(self) -> dict[str, Any]:
        """Queue maintenance for the joined boundary; automatic dispatch stays intact."""
        with self._condition:
            if self._closing or self._failure or self._binding is None:
                raise WorkflowError("renewal requires a healthy started live Host")
            self._renewal_requested = True
            if self._operation is None and self._pending is None:
                self._renew_at_boundary()
            return {**self.status(), "status": "RENEWAL_QUEUED" if self._renewal_requested else "CONTEXTS_RENEWED"}

    def verify_caller_relay(self):
        """Trusted caller supplies evidence at a joined, live review boundary.

        No model Worker is dispatched, no Owner event or new Grant is created.
        The configured provider supplies the actual pin; this call is a wake-up.
        """
        with self._condition:
            if (self._closing or self._failure or self._binding is None
                    or self._operation is not None or self._pending is not None
                    or not self._thread or not self._thread.is_alive()):
                raise WorkflowError('relay verification requires a healthy joined live Host boundary')
            self._validate_binding()
            with self.host._managed_operation(self):
                return self.host.verify_caller_relay()

    def _renew_at_boundary(self) -> None:
        if self._operation or self._pending or self._closing or self._failure:
            raise WorkflowError("renewal is not at a joined Worker boundary")
        self._validate_binding()
        with self.host._managed_operation(self), self.host._exclusive():
            self._last_renewal = self.host.engine.renew_contexts()
        self._renewal_requested = bool(self._last_renewal.get("deferred"))

    def take_final_reply(self) -> dict[str, Any] | None:
        """Atomically consume one actually retired, verified selected-run reply."""
        with self._condition:
            if self._final_delivery is not None:
                return None
            snapshot = self.entry.query()
            presentation = snapshot.view.get("managed_run", {}).get("presentation")
            if not presentation or not presentation["terminal"]:
                return None
            try:
                self.host.engine.assert_resource_health()
                self._validate_binding()
            except Exception as exc:
                presentation = {**presentation, "state": "BLOCKED", "notification_status": "BLOCKED",
                    "reason": f"{presentation['reason']}\nTerminal evidence is unverified; inspect without replay: {exc}",
                    "attention": "SAFE_INSPECTION"}
            if presentation["state"] == "BLOCKED" and presentation["attention"] == "SAFE_INSPECTION":
                self._failure = self._failure or presentation["reason"]
                if not self._closing:
                    self._phase = "STOPPED"
            delivery = {"notification_id": "T" + uuid4().hex, "run_id": self.run_id,
                "scope": self._binding["scope"], "series": copy.deepcopy(self._binding["series"]),
                "status": presentation["notification_status"], "attention": presentation["attention"],
                "boundary": presentation["boundary"], "evidence_refs": list(presentation["evidence_refs"]),
                "revision": snapshot.revision, "body": render_final_reply(presentation["notification_status"], presentation["reason"])}
            self._final_delivery = delivery
            return copy.deepcopy(delivery)

    def event(self, *, kind: str = "ADVANCE", owner_request: OwnerRequest | None = None) -> SupervisorEvent:
        """Prepare an explicit input from current facts; this does not dispatch."""
        with self._condition:
            if self._binding is None:
                raise WorkflowError("managed event requires a started live run")
            snapshot = self.entry.query()
            return SupervisorEvent(self.run_id, self._binding["project"], self._binding["stage_id"],
                self._binding["delegation_request_id"], self.host.engine.state.task_id,
                self._sequence + 1, snapshot.revision, kind, owner_request)

    def _reject(self, reason: str) -> None:
        self._history.append({"status": "REJECTED", "reason": reason})
        raise WorkflowError(reason)

    def _validate_binding(self) -> None:
        snapshot = self.host._bound_snapshot()
        binding, engine = self._binding, self.host.engine
        if self._grants() != binding["grants"]:
            raise WorkflowError("managed Host/Stage grants changed; inspect before continuing")
        text = engine.authority.get(binding["stage_authorization_ref"])
        if (snapshot.view["issues"] or snapshot.view["project"] != binding["project"]
                or snapshot.view["stage_id"] != binding["stage_id"]
                or snapshot.view["workspace"] != binding["workspace"]
                or engine.state.stage_input_ref != binding["stage_authorization_ref"]
                or not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != binding["stage_authorization_sha256"]
                or snapshot.view["stage_input"]["content"] != text):
            raise WorkflowError("managed Stage/workspace binding or saved evidence is stale/unverified")
        series = binding["series"]
        if series:
            text = engine.authority.get(series["plan_ref"])
            if (not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != series["plan_sha256"]
                    or self.entry.projection.authority.get(series["plan_ref"]) != text):
                raise WorkflowError("managed Series Plan authority changed or is unavailable")
        self.host._assert_input_effects_known()
        facts, _ = self.host._delegation_facts()
        if not facts or facts["request_id"] != binding["delegation_request_id"] or facts["persistence"]["verification"] != "VERIFIED":
            raise WorkflowError("managed live delegation evidence is unavailable/mismatched")

    def submit(self, event: SupervisorEvent) -> dict[str, Any]:
        with self._condition:
            if not isinstance(event, SupervisorEvent):
                self._reject("explicit SupervisorEvent required; completion payloads are not role results")
            if event.kind == 'OWNER' and isinstance(event.owner_request, OwnerRequest) and event.owner_request.kind == 'GATE' and event.owner_request.event in {'PAUSE', 'OBJECT'}:
                if (not self._binding or not self._thread or not self._thread.is_alive() or self._closing
                        or (event.run_id, event.project, event.delegation_request_id) != (
                            self.run_id, self._binding['project'], self._binding['delegation_request_id'])
                        or event.stage_id != event.owner_request.stage_id):
                    self._reject('urgent event belongs to a different live run/project/delegation')
                return self.pause_owner(event.owner_request)
            if self._closing or not self._thread or not self._thread.is_alive() or self._failure:
                self._reject("managed Host is closed/stopped; no new dispatch")
            if (event.run_id, event.project, event.stage_id, event.delegation_request_id) != (
                    self.run_id, self._binding["project"], self._binding["stage_id"], self._binding["delegation_request_id"]):
                self._reject("event belongs to a different live run/Stage/delegation")
            if type(event.sequence) is not int or event.sequence != self._sequence + 1:
                self._reject("event sequence is duplicate/stale/out of order")
            if not isinstance(event.kind, str) or event.kind not in {"ADVANCE", "OWNER"} or (event.kind == "ADVANCE" and event.owner_request is not None):
                self._reject("unsupported/conflicting event; worker completion is Host-owned")
            if self._pending is not None or self._operation is not None:
                self._reject("one managed operation is already pending/in flight")
            snapshot = self.entry.query()
            if event.expected_revision != snapshot.revision or event.task_id != self.host.engine.state.task_id:
                self._reject("event snapshot/Task identity is stale or mismatched")
            if event.kind == "OWNER":
                if not isinstance(event.owner_request, OwnerRequest):
                    self._reject("OWNER event requires an explicit validated OwnerRequest")
                event.owner_request.validate()
                if (event.owner_request.project, event.owner_request.stage_id) != (event.project, event.stage_id):
                    self._reject("Owner request does not belong to this managed Stage")
                if event.owner_request.kind in {"STATUS", "ARTIFACT"}:
                    self._reject("factual reads use status/Decision entry and need no worker")
            try:
                self._validate_binding()
                if event.kind == "ADVANCE":
                    facts, _ = self.host._delegation_facts()
                    if not self.host.allow_progress or facts["status"] != "PENDING" or Node(self.host.engine.state.current_node) in STOP_NODES:
                        raise WorkflowError("managed delegation has no pending authorized progression")
            except WorkflowError as exc:
                self._reject(str(exc))
            if (event.kind == 'OWNER' and event.owner_request.kind in {'DIRECTION', 'CHECK'}
                    and Node(self.host.engine.state.current_node) in WINDOW_NODES):
                request = event.owner_request
                if (request.expected_revision != snapshot.revision or not self.host.allow_progress
                        or not request.evidence_refs or any(ref not in snapshot.materials for ref in request.evidence_refs)
                        or (request.scope == 'TASK' and request.task_id != self.host.engine.state.task_id)):
                    self._reject('Owner window input lacks current revision/target/evidence/progress authority')
                # Admit the current Owner input before an already queued old expiry.
                # Cancellation changes no workflow revision or permission.
                self.host.windows.cancel()
            self._sequence = event.sequence
            self._pending, self._phase = event, "RUNNING"
            self._history.append({"sequence": event.sequence, "kind": event.kind, "status": "QUEUED"})
            self._queue.put(event)
            self._condition.notify_all()
        return {**self.status(), "status": "EVENT_QUEUED", "sequence": event.sequence}

    def _work(self, operation: _Operation) -> None:
        try:
            with self.host._managed_operation(self):
                # Recheck after queueing; external changes cannot turn an old event into authority.
                self.host.engine.assert_resource_health()
                self._validate_binding()
                if (operation.event.expected_revision != self.entry.query().revision
                        or operation.event.task_id != self.host.engine.state.task_id):
                    raise WorkflowError("queued event snapshot/Task changed before dispatch")
                if operation.event.kind == "ADVANCE":
                    operation.outcome = self.host.advance(1)
                else:
                    before_state = _digest(self.host.engine.state.as_dict())
                    before_requests = copy.deepcopy(self.host._requests)
                    before_delegation = copy.deepcopy(self.host._delegation)
                    try:
                        operation.outcome = self.host.handle(operation.event.owner_request)
                    except WorkflowError as exc:
                        # A rejected stale/busy Owner input with no observed
                        # mutation is not an unknown worker/Engine failure.
                        if (before_state != _digest(self.host.engine.state.as_dict())
                                or before_requests != self.host._requests or before_delegation != self.host._delegation):
                            raise
                        operation.outcome = {**self.host.status(), "status": "OWNER_REJECTED", "error": str(exc)}
        except Exception as exc:
            operation.error = f"Operation failed; inspect saved facts/effects before continuing: {exc}"
        finally:
            operation.finished.set()
            try:
                self._notify_completion(operation)
            except Exception as exc:
                with self._condition:
                    self._failure = f"Worker completion callback failed; no replay: {exc}"
                    self._closing = True
                    self._phase = "DRAINING"
                    self._condition.notify_all()
                self._queue.put(_CLOSE)

    def _notify_completion(self, operation: _Operation) -> None:
        # Only this actual operation can signal. There is no supplied result body.
        self._queue.put(_Completion(operation))

    def _retire(self, operation: _Operation) -> None:
        with self._condition:
            if operation is not self._operation or not operation.finished.is_set():
                self._history.append({"status": "REJECTED", "reason": "duplicate/stale/unfinished worker completion"})
                return
        if operation.thread.ident is not None:
            operation.thread.join()
        if operation.thread.is_alive():
            raise WorkflowError("Worker join did not prove exit; ownership retained")
        with self._condition:
            self._joined_workers += int(operation.thread.ident is not None)
            self._operation = None
            self._last_operation = {"operation_id": operation.operation_id, "sequence": operation.event.sequence,
                "status": (operation.outcome or {}).get("status"), "error": operation.error,
                "steps": (operation.outcome or {}).get("steps", 0),
                "node": self.host.engine.state.current_node,
                "state_sha256": (operation.outcome or {}).get("facts", {}).get("source", {}).get("state_sha256"),
                "result_ref": (self.host.engine.state.last_result or {}).get("result_ref")}
            self._last_operation["worker_joined"] = not operation.thread.is_alive()
            if operation.event.kind == "OWNER":
                # Retain only the most recent actual response and known fields.
                # Facts are supplied by the enclosing live snapshot; copying
                # them here would recursively retain old managed snapshots.
                fields = {"status", "mode", "revision", "factual_summary", "explanation", "invocation", "error",
                          "stale", "current_revision", "current_factual_summary", "request_id", "reference",
                          "needs_gate_event"}
                response = {key: copy.deepcopy(value) for key, value in (operation.outcome or {}).items() if key in fields}
                if operation.error:
                    response.update(status="FAILED", error=operation.error)
                self._last_owner_response = {"operation_id": operation.operation_id,
                    "sequence": operation.event.sequence, "request_id": operation.event.owner_request.request_id,
                    "kind": operation.event.owner_request.kind, "response": response}
            if operation.error:
                self._failure = operation.error
            try:
                if (not operation.error
                        and (operation.outcome or {}).get("facts", {}).get("source", {}).get("state_sha256")
                        != _digest(self.host.engine.state.as_dict())):
                    raise WorkflowError("actual Engine state differs from the saved Host completion outcome")
                self._validate_binding()
            except Exception as exc:
                self._failure = self._failure or f"Completion evidence is unverified; no replay: {exc}"
            facts, _ = self.host._delegation_facts()
            if not self._failure:
                try:
                    with self.host._managed_operation(self):
                        self.host.process_windows()
                    self._handoff()
                    facts, _ = self.host._delegation_facts()
                except Exception as exc:
                    self._failure = 'Joined Stage/window boundary failed; no next dispatch: ' + str(exc)
            if (not self._failure and operation.event.kind == "ADVANCE" and facts["status"] == "HUMAN_GATE"
                    and self._reached_boundary is None):
                actual = operation.outcome["facts"]
                self._reached_boundary = {"node": actual["node"], "gate": copy.deepcopy(actual["gate"]),
                    "last_completed": actual["activity"]["last_completed"],
                    "last_result": copy.deepcopy(actual["activity"]["last_result"]),
                    "state_sha256": actual["source"]["state_sha256"]}
            self._phase = ("DRAINING" if self._closing else "STOPPED" if self._failure or facts["status"] != "PENDING" or self.host.stop_requested
                           or Node(self.host.engine.state.current_node) in STOP_NODES else "WAITING")
            self._history.append({**self._last_operation, "kind": operation.event.kind, "status": "RETIRED"})
            self._update_cursor += 1
            if (not self._failure and not self._closing and
                    (self._renewal_requested or self.host.engine.resource_renewal_due() or
                     self._renewal_every and self._joined_workers % self._renewal_every == 0)):
                try:
                    self._renew_at_boundary()
                except Exception as exc:
                    self._failure = "Joined-boundary renewal failed; no new dispatch: " + str(exc)
                    self._phase = "STOPPED"
            self._queue_automatic()
            self._condition.notify_all()

    def _run_loop(self) -> None:
        try:
            with self._condition:
                self._queue_automatic()
            while True:
                with self._condition:
                    if self._closing and self._operation is None:
                        return
                    if self._phase == "RUNNING" and self._operation is None and self._pending is None:
                        self._phase = "WAITING"
                    self._loop_waiting = True
                    self._condition.notify_all()
                event = self._queue.get()  # No timeout, heartbeat, model polling or replay.
                with self._condition:
                    self._loop_waiting = False
                if event is _CLOSE:
                    if self._operation:
                        self._operation.thread.join()
                        self._retire(self._operation)
                    return
                if isinstance(event, _Completion):
                    self._retire(event.operation)
                    continue
                if event in {_WINDOW_WAKE, _OWNER_STOP}:
                    if self._operation:
                        continue  # Latched stop/expiry stays queued in Host until join.
                    with self._condition:
                        with self.host._managed_operation(self):
                            self.host.process_windows()
                        self._handoff()
                        self._phase = 'STOPPED' if self.host.stop_requested or self.host._delegation['status'] != 'PENDING' else 'WAITING'
                        self._update_cursor += 1
                        self._queue_automatic()
                        self._condition.notify_all()
                    continue
                with self._condition:
                    self._pending = None
                    if self._closing:
                        self._history.append({"sequence": event.sequence, "status": "NOT_DISPATCHED_CLOSE"})
                        continue
                    operation = self._operation = _Operation(event)
                    operation.thread = Thread(target=self._work, args=(operation,),
                                              name=f"loommode-worker-{operation.operation_id}")
                    operation.thread.start()
                    self._started_workers += 1
        except Exception as exc:
            with self._condition:
                self._failure, self._closing = f"Supervisor loop failed; inspect actual effects: {exc}", True
            if self._operation and self._operation.thread and self._operation.thread.is_alive():
                self._operation.thread.join()
            if self._operation:
                self._operation.error = self._operation.error or self._failure
                self._operation.finished.set()
                self._retire(self._operation)
        finally:
            with self._condition:
                self._pending = None
                self._loop_waiting = False
                self._phase = "CLOSED" if self._closing else "STOPPED"
                self._update_cursor += 1
                self._condition.notify_all()

    def wait_for_idle(self, timeout: float | None = None) -> dict[str, Any]:
        """Blocking caller wait; a timeout leaves RUNNING/DRAINING facts intact."""
        with self._condition:
            self._condition.wait_for(lambda: self._pending is None and self._operation is None
                                     and self._phase != "RUNNING", timeout)
        return self.status()

    def close(self, *, wait: bool = True, timeout: float | None = None, diagnostic_only: bool = False) -> dict[str, Any]:
        if type(diagnostic_only) is not bool:
            raise WorkflowError('explicit diagnostic close flag required')
        if type(wait) is not bool:
            raise WorkflowError("close wait must be an explicit boolean")
        with self._condition:
            self._closing = True  # Fence before any join or callback.
            self.host.windows.close()
            if self._phase != "CLOSED":
                self._phase = "DRAINING" if self._operation is not None else "CLOSED" if self._thread is None else "STOPPING"
                self._queue.put(_CLOSE)
                self._update_cursor += 1
            self._condition.notify_all()
            thread = self._thread
            worker = self._operation.thread if self._operation else None
        if wait and thread and thread.ident is not None and current_thread() not in {thread, worker}:
            thread.join(timeout)
        with self._condition:
            if wait and (thread is None or not thread.is_alive()) and self._operation is None:
                try:
                    self.host.engine.close_resources()
                except Exception as exc:
                    self._failure = "Owned resource closure failed; writer lease retained: " + str(exc)
                    self._phase = "STOPPED"
                    raise WorkflowError(self._failure) from exc
            # A nonblocking close retains ownership until an explicit join proves
            # that both the event loop and its worker have actually exited.
            if (wait and (thread is None or not thread.is_alive()) and self._operation is None
                    and not self._lease_released and getattr(self.host.engine, "_managed_host_owner", None) is self):
                self.host._release_managed_run(self)
                self._lease_released = True
                self._phase = "CLOSED"
                if self._workspace_lease and not self._external_workspace_lease:
                    self._workspace_lease.release()
                    del self.host.engine._workspace_writer_lease
        if diagnostic_only:
            return {'status':'SAFE_CLOSURE','phase':self._phase,'worker_pending':self._operation is not None}
        return self.status()
