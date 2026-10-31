"""One explicit Stage Host for Owner inputs and bounded existing Engine progression."""
import copy
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from threading import Event, Lock, local
from typing import Any

from loommode.workflow.errors import WorkflowError
from loommode.workflow.owner_requests import OWNER_INPUT_NODES
from loommode.workflow.transitions import Node, STOP_NODES, TASK_REQUIRED_NODES
from .decision import DecisionEntry
from .requests import DelegationRequest, OwnerRequest, request_from_text
from .state_view import _digest
from .ownership import writer_operation
from .windows import SoftWindows
from loommode.workflow.governance import scope_name
from loommode.workflow.transitions import WINDOW_NODES
from loommode.workflow.engine import ScopeRejected

_BINDING_LOCK = Lock()


class DecisionHost:
    def __init__(self, entry: DecisionEntry, engine: Any, *, allow_progress: bool = False,
                 allow_owner_events: bool = False, window_clock=None, window_scheduler=None,
                 test_window_durations=None, model_routing=None) -> None:
        if entry.projection.artifacts is not engine.artifacts:
            raise WorkflowError("Decision Host must bind the existing Engine ArtifactStore")
        if hasattr(engine.roles, "adapter") and engine.roles.adapter.registry is not entry.projection.registry:
            raise WorkflowError("Decision Host Registry mismatch")
        if type(allow_progress) is not bool or type(allow_owner_events) is not bool:
            raise WorkflowError("Host grants must be explicit booleans")
        self.entry, self.engine = entry, engine
        self.allow_progress, self.allow_owner_events = allow_progress, allow_owner_events
        self._managed_native = None
        self._managed_context = local()
        # All finite Hosts for this live Engine share operation ownership.
        with _BINDING_LOCK:
            if not hasattr(engine, "_decision_host_lock"):
                engine._decision_host_lock = Lock()
            self._lock = engine._decision_host_lock
            if not hasattr(engine, "_decision_explanation_lock"):
                engine._decision_explanation_lock = entry._explanation_lock
            elif entry._explanation_lock is not engine._decision_explanation_lock:
                old_lock = entry._explanation_lock
                if not old_lock.acquire(blocking=False):
                    raise WorkflowError("cannot bind an alias Entry while its explanation is in flight")
                try:
                    entry._explanation_lock = engine._decision_explanation_lock
                finally:
                    old_lock.release()
            entry._model_guard = self._model_explanation_guard
        self._requests: dict[str, dict[str, Any]] = {}
        self._delegations: dict[str, dict[str, Any]] = {}
        self._delegation = None
        self._delegation_receipts: dict[str, str] = {}
        self._stop_latch = Event()
        self._stop_request = None
        window_options = {'test_durations': test_window_durations}
        if test_window_durations is None and hasattr(engine, '_test_window_configuration'):
            window_options.update(engine._test_window_configuration)
            engine._test_bound_host = self
        if window_clock is not None:
            window_options['clock'] = window_clock
        if window_scheduler is not None:
            window_options['scheduler'] = window_scheduler
        self.windows = SoftWindows(self, **window_options)
        self.engine.dispatch_fence = lambda: self.stop_requested
        # Cover the interval after Engine's early fence and before Adapter/IO
        # admission, including preflight and RPC lock waits. Original Host
        # recovery clears this same latch; no future-generation cancel latch.
        for adapter in self.engine.owned_adapters():
            adapter.client.stop_guard = lambda: self.stop_requested
        self._bound_snapshot()
        self.engine.assert_resource_health()
        if model_routing is not None:
            from .model_routing import HostModelRouting
            if not isinstance(model_routing, HostModelRouting):
                raise WorkflowError('explicit trusted HostModelRouting configuration required')
            if engine._busy or engine.state.in_flight_activity:
                raise WorkflowError('model routing requires an idle Host before Task dispatch')
            model_routing.bind(engine.roles, engine.executor)
        entry.bind_delegation_provider(self._delegation_facts)
        self.engine.host_continuation_facts = self._delegation_facts

    @property
    def stop_requested(self):
        return self._stop_latch.is_set()

    def request_stop(self, request):
        """Urgent stop ignores stale display revision and never grants permission."""
        request.validate()
        if (request.kind != 'GATE' or request.event not in {'PAUSE', 'OBJECT'}
                or request.project != self.engine.state.project
                or request.stage_id not in set((self.engine.state.active_grant or {}).get('stage_ids', [])) | {self.engine.state.stage_id}
                or not request.direction.strip()):
            raise WorkflowError('explicit current-Stage Owner pause/objection required')
        self._stop_request = request
        self._stop_latch.set()
        cancel = getattr(self.engine.executor, 'cancel_active', None)
        if cancel:
            from loommode.workflow.executor import ExecutorRuntime
            if isinstance(self.engine.executor, ExecutorRuntime):
                cancel(cancel_adapter=False)
            else:
                cancel()
        for adapter in self.engine.owned_adapters():
            adapter.cancel_active()
        return {**self.status(), 'status': 'OWNER_STOP_LATCHED', 'request_id': request.request_id}

    def _apply_stop(self):
        if not self.stop_requested or self.engine._busy or self.engine.state.in_flight_activity:
            return
        self.windows.cancel()
        if self.engine.state.current_node != Node.HUMAN_BLOCK.value:
            state = copy.deepcopy(self.engine.state)
            self.engine.executor.suspend()
            prior_node = state.current_node
            self.engine._move(state, Node.HUMAN_BLOCK, self._stop_request.direction)
            ref = self.engine._save_artifact(state, 'DECISION', json.dumps({
                'origin': 'HOST_URGENT_OWNER_STOP', 'request': self._stop_request.as_dict(),
                'permissions_expanded': False, 'prior_node': prior_node}, ensure_ascii=False))
            state.last_result = {'owner_stop_ref': ref, 'explanation': self._stop_request.direction}
            state.latest_decision_notice_ref = ref
            state.artifact_refs.setdefault('DECISION_NOTICE', []).append(ref)
            self.engine.store.save(state)
            self.engine.state = state
        if self._delegation and self._delegation['status'] == 'PENDING':
            self._delegation['expected_state'] = _digest(self.engine.state.as_dict())
            self._stop_delegation('HUMAN_BLOCK', self._stop_request.direction, 'OWNER_STOP')

    def process_windows(self):
        """Serialized finite/managed boundary; timer callbacks never enter here."""
        with self._exclusive():
            self._apply_stop()
            self.windows.arm()
            self._capture_caller_relay()
            changed = self.windows.consume()
            if changed and self._delegation:
                self._delegation['expected_state'] = _digest(self.engine.state.as_dict())
                self._persist_delegation()
                self._observe_engine_stop(Node(self.engine.state.current_node))
            return changed

    def require_caller_relay(self, *, task_id, caller_id, source_provider):
        """Trusted caller setup before progression; provider returns a raw-file pin.

        The provider runs only at serialized live review-window boundaries. It
        returns None while no actual relay capture exists. No model output,
        Owner event, role name or authority text can configure this hook.
        """
        from .caller_relay import CallerRelayVerification
        with self._exclusive():
            verifier = CallerRelayVerification(self, task_id, caller_id, source_provider)
            self.engine.caller_relay_verification = verifier
            self.engine.roles.caller_relay_verification = verifier
        return verifier

    def _capture_caller_relay(self):
        verifier = getattr(self.engine, 'caller_relay_verification', None)
        if verifier is not None:
            verifier.capture_if_ready()

    def require_native_executor_admission(self, *, task_id, caller_id, reserve, seal):
        """Initial trusted factory opt-in; never a model tool or authority text."""
        from .native_admission import NativeExecutorAdmission
        with self._exclusive():
            admission = NativeExecutorAdmission(self, task_id, caller_id, reserve, seal)
            self.engine.executor.native_admission = admission
        return admission

    def verify_caller_relay(self):
        """Explicit caller wake-up during a finite Host's idle review window."""
        with self._exclusive():
            self._apply_stop()
            self._assert_input_effects_known()
            self.windows.arm()
            verifier = getattr(self.engine, 'caller_relay_verification', None)
            if verifier is None:
                raise WorkflowError('caller relay requirement is not configured')
            verifier.capture_if_ready()
            if verifier.receipt_ref is None:
                raise WorkflowError('actual caller relay source is not yet available')
            verifier._check(self.engine.state.as_dict(), require_expiry=False)
            return verifier.receipt_ref

    def _model_explanation_guard(self) -> str | None:
        owner = getattr(self.engine, "_managed_host_owner", None)
        if owner is not None and getattr(self._managed_context, "owner", None) is not owner:
            return "The live managed Host retains model operations; submit a serialized OWNER EXPLAIN or read factual status."
        return None

    @contextmanager
    def _exclusive(self):
        if not self._lock.acquire(blocking=False):
            raise WorkflowError("a Host input/progress operation is already in flight")
        try:
            owner = getattr(self.engine, "_managed_host_owner", None)
            if owner is not None and getattr(self._managed_context, "owner", None) is not owner:
                raise WorkflowError("this Engine is retained by its live managed Host; submit an explicit managed event")
            with writer_operation(self.engine, self.entry.projection.workspace):
                yield
        finally:
            self._lock.release()

    def _claim_managed_run(self, owner) -> None:
        with self._exclusive():
            self.engine.assert_resource_health()
            if not self.entry._explanation_lock.acquire(blocking=False):
                raise WorkflowError("an explanation is already in flight; cannot start a managed run")
            try:
                if getattr(self.engine, "_managed_host_owner", None) is not None:
                    raise WorkflowError("this Engine already has a managed Host binding")
                if self.engine._busy or self.engine.state.in_flight_activity:
                    raise WorkflowError("cannot retain a busy or unknown Engine operation")
                self.engine._managed_host_owner = owner
            finally:
                self.entry._explanation_lock.release()

    def _release_managed_run(self, owner) -> None:
        with self._managed_operation(owner), self._exclusive():
            self.engine._managed_host_owner = None

    @contextmanager
    def _managed_operation(self, owner):
        if getattr(self.engine, "_managed_host_owner", None) is not owner:
            raise WorkflowError("managed operation does not own this live Engine")
        previous = getattr(self._managed_context, "owner", None)
        self._managed_context.owner = owner
        try:
            yield
        finally:
            self._managed_context.owner = previous

    def _bound_snapshot(self):
        # A supported Worker can finish between projection capture and this
        # comparison. Re-read a small bounded number of times; every returned
        # view must still match the actual current State. A stable wrong source,
        # missing authority or sustained change is never accepted as current.
        for _ in range(3):
            snapshot = self.entry.query()
            if (snapshot.view["availability"] == "AVAILABLE"
                    and snapshot.view["source"]["state_sha256"] == _digest(self.engine.state.as_dict())):
                if self.engine.state.stage_input_ref not in self.engine.authority:
                    raise WorkflowError("Host requires the existing explicit Stage authorization")
                return snapshot
        raise WorkflowError("Decision Host does not observe this Engine's current state")

    def status(self) -> dict[str, Any]:
        snapshot = self.entry.query()
        return {"status": "FACTS", "facts": snapshot.as_dict(), "revision": snapshot.revision,
                "summary": snapshot.summary(), "owner_requests": copy.deepcopy(list(self._requests.values())),
                "resource_health": self.engine.resource_health()}

    def close(self) -> dict[str, Any]:
        with self._exclusive():
            self.windows.close()
            self.engine.close_resources()
        return self.status()

    def _assert_input_effects_known(self) -> None:
        if any(r["status"] in {"REGISTER_FAILED_UNKNOWN", "EVENT_FAILED_UNKNOWN", "DISPATCH_FAILED_UNKNOWN"}
               for r in self._requests.values()):
            raise WorkflowError("an Owner input/event has unknown effects; inspect before continuing")
        if self._delegation and self._delegation["status"] in {"SAVE_FAILED_UNKNOWN", "UNKNOWN_EFFECTS", "UNKNOWN_EVIDENCE"}:
            raise WorkflowError("delegation has unknown effects/evidence; inspect before a new scope selection")

    def _delegation_facts(self):
        record = self._delegation
        if record is None:
            return None, {}
        materials, error = {}, None
        for ref in record["references"]:
            try:
                text = self.engine.artifacts.read(ref)
                if text != self._delegation_receipts[ref]:
                    raise WorkflowError("delegation receipt differs from the bound Host facts")
                materials[ref] = text
            except (WorkflowError, OSError, ValueError) as exc:
                error = str(exc)
        if not record["references"]:
            error = "delegation selection was not saved"
        input_unknown = any(item["status"] in {"REGISTER_FAILED_UNKNOWN", "EVENT_FAILED_UNKNOWN", "DISPATCH_FAILED_UNKNOWN"}
                            for item in self._requests.values())
        status = "UNKNOWN_EVIDENCE" if error else "UNKNOWN_EFFECTS" if input_unknown else record["status"]
        reason = error or ("Owner input/event has unknown effects; inspect before continuing." if input_unknown else record["reason"])
        if status == "PENDING" and not self.allow_progress:
            status, reason = "NO_PROGRESS_GRANT", "Host has no Stage progress grant; dispatch is not permitted."
        if status == "HUMAN_GATE" and self.engine.state.current_node != "HUMAN_GATE":
            if self.engine.state.owner_accepted and self.engine.state.current_node == "COMPLETED":
                reason = "Delegation reached Human Gate; Owner approval was applied and this Stage is completed. No further dispatch or next Stage."
            else:
                reason = (f"Delegation previously reached Human Gate; Owner event now leaves Engine at {self.engine.state.current_node}. "
                          "The previous delegation stays stopped; any further work needs a new explicit legal scope selection.")
        return {"scope": record["request"]["scope"], "request_id": record["request"]["request_id"],
                "target": copy.deepcopy(record["target"]), "status": status,
                "continuing": status == "PENDING", "stop_boundary": record["stop_boundary"],
                "reason": reason, "steps": record["steps"],
                "dispatch_counts": dict(record["dispatch_counts"]),
                "checkpoint_refs": dict(record["checkpoint_refs"]),
                "persistence": {"verification": "UNVERIFIED" if error else "VERIFIED",
                                "references": list(record["references"]), "error": error},
                "resume_boundary": "SAME_LIVE_HOST_ONLY", "permissions_expanded": False}, materials

    def _persist_delegation(self) -> None:
        record = self._delegation
        payload = {"origin": "HOST_DELEGATION", "schema_version": 1,
            **{key: copy.deepcopy(record[key]) for key in
               ("request", "target", "status", "stop_boundary", "reason", "steps", "dispatch_counts", "trace", "checkpoint_refs")},
            "node": self.engine.state.current_node, "last_completed_activity": self.engine.state.last_completed_activity,
            "state_sha256": _digest(self.engine.state.as_dict()),
            "host_grants": {"allow_progress": self.allow_progress, "allow_owner_events": self.allow_owner_events},
            "prior_ref": record["references"][-1] if record["references"] else None}
        text = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        try:
            ref = self.engine.artifacts.save("DECISION", text, task_id=record["request"]["task_id"])
            record["references"].append(ref)
            self._delegation_receipts[ref] = text
            if self.engine.artifacts.read(ref) != text:
                raise WorkflowError("saved delegation evidence could not be verified")
        except Exception as exc:
            record.update(status="SAVE_FAILED_UNKNOWN", reason=f"Delegation evidence saving failed; inspect actual effects: {exc}")
            raise WorkflowError(record["reason"]) from exc

    def _stop_delegation(self, status: str, reason: str, boundary: str | None = None) -> None:
        self._delegation.update(status=status, reason=reason, stop_boundary=boundary,
                                checkpoint_refs=dict(self.engine.state.task_checkpoint_refs))
        self._persist_delegation()

    def start(self, request: DelegationRequest) -> dict[str, Any]:
        self.engine.assert_resource_health()
        """Retain an explicit Owner scope selection; dispatch only via resume/advance."""
        if not isinstance(request, DelegationRequest):
            raise WorkflowError("explicit DelegationRequest required")
        request.validate()
        with self._exclusive():
            if request.request_id in self._delegations:
                previous = self._delegations[request.request_id]
                if previous["request"] != request.as_dict():
                    raise WorkflowError("delegation request id reused for different input")
                return {**self.status(), "status": "ALREADY_HANDLED", "steps": 0}
            self._assert_input_effects_known()
            if not self.allow_progress:
                raise WorkflowError("Host has no Stage progress/delegation grant")
            if len(self._delegations) >= 32 or request.request_id in self._requests:
                raise WorkflowError("delegation request limit/identity conflict")
            if self._delegation and self._delegation["status"] == "PENDING":
                raise WorkflowError("an existing delegation is pending; resume its original scope")
            snapshot = self._bound_snapshot()
            state = self.engine.state
            if snapshot.view["issues"]:
                raise WorkflowError("delegation has unverified current evidence; inspect the displayed issues before selection")
            if self.engine._busy or state.in_flight_activity:
                raise WorkflowError("current effects are busy/in flight/unknown; no delegation")
            if Node(state.current_node) in STOP_NODES:
                raise WorkflowError("current Engine is stopped; use the existing legal Owner event first")
            expected = DelegationRequest.from_snapshot(snapshot, request.scope, request_id=request.request_id,
                scope_id=request.scope_id, authority_ref=request.authority_ref, authority_sha256=request.authority_sha256)
            if request != expected:
                raise WorkflowError("delegation snapshot/Stage authority/workspace/Task identity is stale or mismatched")
            if (state.stage_input_ref != request.stage_authorization_ref or
                    hashlib.sha256(self.engine.authority[state.stage_input_ref].encode("utf-8")).hexdigest() != request.stage_authorization_sha256):
                raise WorkflowError("delegation Stage authorization bytes mismatch")
            policy = getattr(self.engine.executor, "stage_policy", None)
            if policy is not None and policy.workspace.resolve() != Path(request.workspace).resolve():
                raise WorkflowError("delegation Engine workspace mismatch")
            if request.task_id is not None:
                formal = snapshot.view["task"]["formal_refs"].get("TASK_INTENT")
                if not formal or formal["verification"] != "VERIFIED":
                    raise WorkflowError("delegation requires a verified current formal Task Intent")
            same_task_mediation = (scope_name(request.scope) == "TASK"
                and Node(state.current_node) == Node.DECISION_MEDIATION
                and self.engine.validate_same_task_repair_delegation() == request.task_id)
            if scope_name(request.scope) == "TASK" and (not request.task_id or
                    (Node(state.current_node) not in TASK_REQUIRED_NODES and not same_task_mediation)):
                raise WorkflowError("current_task requires an active current Task; selection is a separate Owner choice")
            if request.authority_ref and (request.authority_ref not in self.engine.authority or
                    hashlib.sha256(self.engine.authority[request.authority_ref].encode('utf-8')).hexdigest() != request.authority_sha256):
                raise ScopeRejected('actual selected Owner scope authority bytes mismatch')
            selected = self.engine.scope_grants.get(request.authority_ref)
            if selected and len(selected.stage_ids) > 1 and getattr(self.engine, '_managed_host_owner', None) is None:
                raise ScopeRejected('multi-Stage delegation requires a live Supervisor with registered successor candidates')
            grant = self.engine.select_grant(request.scope, reference=request.authority_ref,
                scope_id=request.scope_id, task_id=request.task_id)
            if Path(grant.workspace).resolve() != Path(request.workspace).resolve():
                raise ScopeRejected('actual Owner grant workspace mismatch')
            target = {"project": request.project, "stage_id": request.stage_id, "workspace": request.workspace,
                "stage_authorization_ref": request.stage_authorization_ref,
                "stage_authorization_sha256": request.stage_authorization_sha256,
                "task_id": request.task_id, "task_intent_ref": request.task_intent_ref, "task_goal": request.task_goal}
            record = {"request": request.as_dict(), "target": target, "status": "PENDING", "stop_boundary": None,
                "reason": "Scope selected; resume within the existing Stage/Task permissions.",
                "steps": 0, "dispatch_counts": {}, "trace": [], "references": [], "checkpoint_refs": {},
                "expected_state": _digest(self.engine.state.as_dict()),
                "active_task": (state.task_id, state.formal_task_intent_ref, snapshot.view["task"]["goal"])}
            self._delegations[request.request_id] = self._delegation = record
            self._persist_delegation()
            return {**self.status(), "status": "DELEGATION_SELECTED", "steps": 0}

    def resume(self, max_steps: int = 100) -> dict[str, Any]:
        if self._delegation is None:
            raise WorkflowError("resume requires an explicit live Host delegation selection")
        return self.advance(max_steps)

    def run(self, max_steps: int = 100) -> dict[str, Any]:
        return self.resume(max_steps)

    def _delegation_guard(self, snapshot) -> bool:
        record, state = self._delegation, self.engine.state
        if record is None:
            return True
        if record["status"] != "PENDING":
            return False
        facts, _ = self._delegation_facts()
        if facts["persistence"]["verification"] != "VERIFIED":
            record.update(status="UNKNOWN_EVIDENCE", reason=facts["reason"])
            return False
        target = record["target"]
        text = self.engine.authority.get(state.stage_input_ref)
        if (state.stage_input_ref != target["stage_authorization_ref"] or not isinstance(text, str)
                or hashlib.sha256(text.encode("utf-8")).hexdigest() != target["stage_authorization_sha256"]
                or snapshot.view["stage_input"]["content"] != text
                or snapshot.view["workspace"] != target["workspace"]):
            self._stop_delegation("STALE_AUTHORITY", "Stage/workspace authorization changed; inspect and select an authorized scope.")
            return False
        active = (state.task_id, state.formal_task_intent_ref, snapshot.view["task"]["goal"])
        if active != record["active_task"]:
            self._stop_delegation("TARGET_CHANGED", "Task identity/goal changed outside the delegated loop; a new explicit selection is required.")
            return False
        if self.engine._busy or state.in_flight_activity:
            self._stop_delegation("UNKNOWN_EFFECTS", "Current activity is busy/in flight with unknown effects; inspect without replay.")
            return False
        if _digest(state.as_dict()) != record["expected_state"]:
            self._stop_delegation("UNKNOWN_EFFECTS", "Engine state changed outside this Host operation; inspect without replay.")
            return False
        return True

    def _observe_delegated_step(self, before: Node, task_before) -> None:
        record, state = self._delegation, self.engine.state
        if record is None:
            return
        record["steps"] += 1
        record["dispatch_counts"][before.value] = record["dispatch_counts"].get(before.value, 0) + 1
        record["trace"].append({"before": before.value, "after": state.current_node,
            "task_before": task_before[0], "task_after": state.task_id,
            "last_completed_activity": state.last_completed_activity, "state_sha256": _digest(state.as_dict())})
        record["trace"] = record["trace"][-100:]
        record["expected_state"] = _digest(state.as_dict())
        snapshot = self._bound_snapshot()
        active = (state.task_id, state.formal_task_intent_ref, snapshot.view["task"]["goal"])
        if active != task_before:
            if scope_name(record["request"]["scope"]) != "TASK" and before in {Node.TASK_SELECTION, Node.STAGE_SETTLEMENT,
                                                                                  Node.PROMOTER_IMPLEMENTATION_PLAN, Node.STAGE_ISSUE_TRIAGE}:
                record["active_task"] = active
            else:
                self._stop_delegation("TARGET_CHANGED", "Promoter/Decision selected a different Task or goal; select a new explicit delegation before execution.")
                return
        if before == Node.TASK_COMPLETE and scope_name(record["request"]["scope"]) == "TASK":
            checkpoint = snapshot.view["checkpoints"].get(state.task_id)
            if (state.current_node != Node.TASK_SELECTION.value or state.last_completed_activity != Node.TASK_COMPLETE.value
                    or state.active_blocker_id is not None or state.pending_override_task_id == state.task_id
                    or state.in_flight_activity or not checkpoint or checkpoint["verification"] != "VERIFIED"
                    or snapshot.view["task"]["acceptance_status"] != "ACCEPTED"):
                self._stop_delegation("UNKNOWN_EVIDENCE", "Task cleanup/checkpoint completion cannot be verified; inspect before continuing.")
            else:
                self._stop_delegation("TASK_COMPLETED", "Current Task accepted, checkpoint verified and cleanup complete; next Task selection was not called.", "TASK_COMPLETE")

    def _observe_engine_stop(self, node: Node) -> None:
        if self._delegation is None or self._delegation["status"] != "PENDING":
            return
        if node == Node.COMPLETED and (self.engine.state.stage_closed or self.engine.state.scope_completion):
            status = 'STAGE_COMPLETED' if self.engine.state.stage_closed else 'SCOPE_COMPLETED'
            self._stop_delegation(status, 'Actual delegated boundary completed; further work requires an existing broader grant or a new grant.', status)
        elif node == Node.HUMAN_GATE:
            state = self.engine.state
            if (self._delegation["request"]["scope"] == "current_stage" and state.machine_close_ready
                    and state.last_completed_activity == Node.OWNER_SUMMARY.value and state.artifact_refs.get("STAGE_RECORD")):
                self._stop_delegation("HUMAN_GATE", "Stage machine close and Owner Summary complete; existing Owner Human Gate awaits a legal event.", "HUMAN_GATE")
            else:
                self._stop_delegation("UNKNOWN_EVIDENCE", "Human Gate does not prove the selected delegation boundary; inspect the formal close evidence.", node.value)
        elif node in STOP_NODES:
            status = "UNKNOWN_EFFECTS" if self.engine.state.in_flight_activity else node.value
            reason = self.engine.state.human_gate_reason or (self.engine.state.last_result or {}).get("error") or node.value
            self._stop_delegation(status, f"Engine stopped at {node.value}: {reason}. Inspect/use the existing legal Owner event; no replay.", node.value)

    def handle_text(self, text: str, *, displayed: Any) -> dict[str, Any]:
        from .requests import urgent_stop_from_text
        state = self.engine.state
        urgent = urgent_stop_from_text(text, project=state.project, stage_id=state.stage_id,
                                      task_id=state.task_id, expected_revision=getattr(displayed, 'revision', None))
        if urgent:
            return self.request_stop(urgent)
        if isinstance(text, str) and text.strip() in {"RESUME", "RUN"}:
            return self.resume()
        if isinstance(text, str) and text.strip() in {"DELEGATE current_task", "DELEGATE current_stage", "只完成当前 Task", "托管当前 Stage 到 Human Gate"}:
            scope = "current_task" if text.strip() in {"DELEGATE current_task", "只完成当前 Task"} else "current_stage"
            return self.start(DelegationRequest.from_snapshot(displayed, scope))
        request = request_from_text(text, displayed)
        if request is None:
            return {**self.status(), "status": "NEEDS_SPECIFIC_REQUEST",
                    "message": "请明确状态/解释/记录、Gate、CHECK/DIRECTION 或 DELEGATE current_task/current_stage、RESUME 请求。"}
        return self.handle(request)

    def handle(self, request: OwnerRequest) -> dict[str, Any]:
        if not isinstance(request, OwnerRequest):
            raise WorkflowError("explicit OwnerRequest required")
        request.validate()
        if request.kind == 'GATE' and request.event in {'PAUSE', 'OBJECT'}:
            return self.request_stop(request)
        if (request.project, request.stage_id) != (self.entry.projection.project, self.entry.projection.stage_id):
            raise WorkflowError("Owner request Project/Stage mismatch")
        if request.kind == "STATUS":
            return self.status()
        if request.kind == "EXPLAIN":
            with self._exclusive():
                self.engine.assert_resource_health()
                return {"status": "EXPLANATION", **self.entry.explain(request.direction)}
        if request.kind == "ARTIFACT":
            if not isinstance(request.artifact_ref, str) or not request.artifact_ref:
                raise WorkflowError("explicit Artifact reference required")
            return {"status": "ARTIFACT", "reference": request.artifact_ref,
                    "content": self.entry.read_artifact(request.artifact_ref)}
        with self._exclusive():
            if request.request_id in self._delegations:
                raise WorkflowError("Owner request id conflicts with a delegation selection")
            if request.request_id in self._requests:
                previous = self._requests[request.request_id]
                if previous["request"] != request.as_dict():
                    raise WorkflowError("Owner request id reused for different input")
                return {"status": "ALREADY_HANDLED", "request": copy.deepcopy(previous), "facts": self.entry.query().as_dict()}
            self._assert_input_effects_known()
            if len(self._requests) >= 32:
                raise WorkflowError("bounded Host request limit reached")
            snapshot = self._bound_snapshot()
            if request.expected_revision != snapshot.revision:
                raise WorkflowError("Owner request snapshot is stale or unspecified; inspect current facts")
            if self.engine._busy or (self.engine.state.in_flight_activity and
                    not (request.kind == "GATE" and request.event == "RESOLVE_HUMAN_BLOCK"
                         and self.engine.state.current_node == "RECOVERY_REQUIRED")):
                raise WorkflowError("current effects are in flight/unknown; no new Owner operation")
            if not request.direction.strip() or not request.evidence_refs or any(
                    ref not in snapshot.materials for ref in request.evidence_refs):
                raise WorkflowError("Owner operation needs explicit direction and verified snapshot evidence")
            if request.kind == "GATE":
                if not self.allow_owner_events or request.task_id != snapshot.view["task"]["task_id"]:
                    raise WorkflowError("Owner Gate grant/Task identity mismatch")
                if request.event not in snapshot.view["gate"]["available_events"]:
                    raise WorkflowError("Owner event is not legal at this Gate")
                if request.event == 'REQUEST_SAME_TASK_REPAIR':
                    self.engine.validate_same_task_repair_request(
                        direction=request.direction, evidence_refs=list(request.evidence_refs))
                record = {"request": request.as_dict(), "status": "APPLYING_OWNER_EVENT", "reference": None}
                self._requests[request.request_id] = record
                try:
                    self.windows.cancel()
                    if request.event == 'COMPLETE_STAGE_REVIEW':
                        state = self.engine.state
                        ref = self.engine._save_artifact(state, 'DECISION', json.dumps({
                            'origin': 'HOST_OWNER_WINDOW_REVIEW', 'request': request.as_dict(),
                            'notice_ref': state.stage_notice_ref, 'owner_accepted': False}, ensure_ascii=False))
                        record['reference'] = ref
                        self.engine.queue_owner_mediation(ref, event=request.event)
                    else:
                        self.engine.owner_event(request.event, direction=request.direction, evidence_refs=list(request.evidence_refs))
                    if request.event in {'RESOLVE_HUMAN_BLOCK', 'REQUEST_SAME_TASK_REPAIR'}:
                        self._stop_latch.clear()
                        self._stop_request = None
                except Exception as exc:
                    record.update(status="EVENT_FAILED_UNKNOWN", error=str(exc))
                    raise
                record.update(status="OWNER_EVENT_APPLIED", node=self.engine.state.current_node,
                              state_sha256=_digest(self.engine.state.as_dict()))
                if self._delegation and self._delegation['status'] == 'PENDING':
                    self._delegation['expected_state'] = _digest(self.engine.state.as_dict())
                    self._persist_delegation()
                    self._observe_engine_stop(Node(self.engine.state.current_node))
                if self.engine.state.current_node == "COMPLETED":
                    for old in self._requests.values():
                        if old["status"] == "QUEUED_FOR_PROMOTER":
                            old["status"] = "NOT_DELIVERED_STAGE_COMPLETED"
                return {**self.status(), "status": "OWNER_EVENT_APPLIED", "request_id": request.request_id}
            if not self.allow_progress:
                raise WorkflowError("Host has no Stage work/input grant")
            if request.scope == "TASK" and request.task_id != snapshot.view["task"]["task_id"]:
                raise WorkflowError("Owner request targets a different Task")
            record = {"request": request.as_dict(), "status": "SAVING_OWNER_INPUT", "reference": None}
            self._requests[request.request_id] = record
            try:
                in_window = Node(self.engine.state.current_node) in WINDOW_NODES
                if in_window:
                    self.windows.cancel()
                ref = self.engine.artifacts.save("DECISION", json.dumps(request.packet(), ensure_ascii=False),
                                                task_id=request.task_id)
                record["reference"] = ref
                self.engine.register_owner_request(ref)
                if in_window:
                    self.engine.queue_owner_mediation(ref)
            except Exception as exc:
                record.update(status="REGISTER_FAILED_UNKNOWN", error=str(exc))
                raise
            record.update(status="QUEUED_FOR_DECISION" if in_window else "QUEUED_FOR_PROMOTER", state_sha256=_digest(self.engine.state.as_dict()))
            if self._delegation and self._delegation["status"] == "PENDING":
                self._delegation["expected_state"] = _digest(self.engine.state.as_dict())
            return {**self.status(), "status": record['status'], "reference": ref,
                    "needs_gate_event": self.engine.state.current_node in {"HUMAN_GATE", "HUMAN_BLOCK", "RECOVERY_REQUIRED", 'SOFT_ACCEPTANCE_WAIT'}}

    def advance(self, max_steps: int = 1) -> dict[str, Any]:
        if type(max_steps) is not int or not 1 <= max_steps <= 100:
            raise WorkflowError("explicit Host step bound must be 1..100")
        with self._exclusive():
            self._apply_stop()
            if not self.allow_progress:
                raise WorkflowError("Host has no Stage progress grant")
            if self._delegation and self._delegation["status"] != "PENDING":
                return {**self.status(), "status": "STOPPED", "steps": 0}
            if self._delegation is None and Node(self.engine.state.current_node) in STOP_NODES:
                self._bound_snapshot()
                return {**self.status(), "status": "STOPPED", "steps": 0}
            self._assert_input_effects_known()
            steps = 0
            for _ in range(max_steps):
                if self.stop_requested:
                    self._apply_stop()
                    break
                if Node(self.engine.state.current_node) in WINDOW_NODES:
                    self.windows.arm()
                    self._capture_caller_relay()
                    if not self.windows.consume():
                        break
                    if self._delegation:
                        self._delegation['expected_state'] = _digest(self.engine.state.as_dict())
                    self._observe_engine_stop(Node(self.engine.state.current_node))
                try:
                    snapshot = self._bound_snapshot()
                except WorkflowError as exc:
                    if not self._delegation:
                        raise
                    self._stop_delegation("UNKNOWN_EVIDENCE", f"Bound Engine/Stage facts cannot be verified; inspect before continuing: {exc}")
                    break
                node = Node(self.engine.state.current_node)
                if node in {Node.FAILED, Node.HUMAN_BLOCK, Node.RECOVERY_REQUIRED, Node.COMPLETED}:
                    self._observe_engine_stop(node)
                    break
                if not self._delegation_guard(snapshot):
                    break
                if node in STOP_NODES:
                    self._observe_engine_stop(node)
                    break
                pending = []
                if node in OWNER_INPUT_NODES:
                    for record in self._requests.values():
                        if record["status"] not in {"QUEUED_FOR_PROMOTER", 'QUEUED_FOR_DECISION'}:
                            continue
                        if record["request"]["scope"] == "TASK" and record["request"]["task_id"] != self.engine.state.task_id:
                            record["status"] = "STALE_TARGET"
                        else:
                            pending.append(record)
                try:
                    task_before = (self.engine.state.task_id, self.engine.state.formal_task_intent_ref, snapshot.view["task"]["goal"])
                    if self._managed_native is not None and node == Node.EXECUTOR_IMPLEMENT:
                        self._managed_native.bind_actual_task(self.engine)
                    self.engine.step(owner_request_refs=tuple(r["reference"] for r in pending))
                except ScopeRejected as exc:
                    if self._delegation:
                        self._stop_delegation('UNAUTHORIZED_SELECTION', str(exc), node.value)
                        break
                    raise
                except Exception as exc:
                    for record in pending:
                        record.update(status="DISPATCH_FAILED_UNKNOWN", error=str(exc))
                    if self._delegation:
                        status = "UNKNOWN_EFFECTS" if self.engine.state.in_flight_activity else "FAILED"
                        self._stop_delegation(status, f"Engine dispatch failed; inspect actual effects before any continuation: {exc}", self.engine.state.current_node)
                    raise
                for record in pending:
                    record.update(status="DELIVERED_TO_DECISION" if node == Node.DECISION_MEDIATION else "DELIVERED_TO_PROMOTER", activity=node.value,
                                  result_ref=(self.engine.state.last_result or {}).get("result_ref"))
                steps += 1
                self._observe_delegated_step(node, task_before)
                self._observe_engine_stop(Node(self.engine.state.current_node))
                self.windows.arm()
                if (getattr(self.engine, "_managed_host_owner", None) is None
                        and self.engine.resource_renewal_due()):
                    self.engine.renew_contexts()  # Finite entry has no owned Worker to join.
                if self._delegation and self._delegation["status"] != "PENDING":
                    break
            if self._delegation:
                if self._delegation["status"] == "PENDING":
                    self._delegation["reason"] = "Step budget exhausted; delegation remains pending. Resume the same scope; no successful boundary claimed."
                    self._persist_delegation()
                status = ("PENDING" if self._delegation["status"] == "PENDING" else
                          "BOUNDARY_REACHED" if self._delegation["status"] in {"TASK_COMPLETED", "HUMAN_GATE", "STAGE_COMPLETED", "SCOPE_COMPLETED"} else "STOPPED")
            else:
                status = "PROGRESSED" if steps else "STOPPED"
            return {**self.status(), "status": status, "steps": steps}
