"""Small versioned checkpoint. Restart stops; it never replays side effects."""
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any
from .errors import WorkflowError
from .transitions import Node, Role, TASK_REQUIRED_NODES

IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*$")


def identity(value: str) -> str:
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise WorkflowError("invalid project/stage/task identity")
    return value


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".loommode-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowError("duplicate checkpoint JSON key")
        result[key] = value
    return result


@dataclass
class WorkflowState:
    project: str
    stage_id: str
    stage_input_ref: str | None = None
    task_id: str | None = None
    schema_version: int = 1
    workflow_path: str | None = None
    current_node: str = Node.STAGE_START.value
    status: str = "RUNNING"
    formal_task_intent_ref: str | None = None
    formal_constraint_ref: str | None = None
    latest_execution_report_ref: str | None = None
    role_context_refs: dict[str, str] = field(default_factory=dict)
    executor_context_ref: str | None = None
    active_review_context_ref: str | None = None
    normal_repair_used: bool = False
    decision_new_basis_used: bool = False
    decision_treatment_used: bool = False
    waiting_human: bool = False
    human_gate_reason: str | None = None
    last_completed_activity: str | None = None
    last_result: dict[str, Any] | None = None
    in_flight_activity: str | None = None
    used_task_ids: list[str] = field(default_factory=list)
    artifact_refs: dict[str, list[str]] = field(default_factory=dict)
    blocker_ledger: dict[str, dict[str, Any]] = field(default_factory=dict)
    active_blocker_id: str | None = None
    decision_re_review_used: bool = False
    arbitration_used: bool = False
    independent_review_used: bool = False
    acceptance_ref: str | None = None
    commit_receipt: dict[str, Any] | None = None
    task_checkpoint_refs: dict[str, str] = field(default_factory=dict)
    pending_override: dict[str, Any] | None = None
    pending_override_task_id: str | None = None
    machine_close_ready: bool = False
    owner_accepted: bool = False
    memory_completed_roles: list[str] = field(default_factory=list)
    human_events: list[dict[str, str]] = field(default_factory=list)
    active_grant: dict[str, Any] | None = None
    stage_plan_ref: str | None = None
    stage_plan_decision_ref: str | None = None
    stage_acceptance_ref: str | None = None
    stage_notice_ref: str | None = None
    stage_knowledge_ref: str | None = None
    stage_closeout_ref: str | None = None
    stage_closed: bool = False
    scope_completion: dict[str, Any] | None = None
    stage_issues: dict[str, dict[str, Any]] = field(default_factory=dict)
    issue_triage: list[dict[str, Any]] = field(default_factory=list)
    soft_window_events: list[dict[str, Any]] = field(default_factory=list)
    task_relationships: dict[str, dict[str, Any]] = field(default_factory=dict)
    decision_handoff_ref: str | None = None
    mediation_counts: dict[str, int] = field(default_factory=dict)
    mediation_result_ref: str | None = None
    latest_decision_notice_ref: str | None = None
    owner_window_refs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise WorkflowError("unsupported workflow state schema")
        identity(self.project)
        identity(self.stage_id)
        if self.task_id is not None:
            identity(self.task_id)
        try:
            node = Node(self.current_node)
        except (ValueError, TypeError) as exc:
            raise WorkflowError("unknown workflow node") from exc
        if self.workflow_path not in {None, "NORMAL", "FAST"}:
            raise WorkflowError("unknown workflow path")
        if self.status not in {"RUNNING", "WAITING_HUMAN", "FAILED", "COMPLETED", "RECOVERY_REQUIRED"}:
            raise WorkflowError("unknown workflow status")
        for key in ("normal_repair_used", "decision_new_basis_used", "decision_treatment_used", "waiting_human", "decision_re_review_used",
                    "arbitration_used", "independent_review_used", "machine_close_ready", "owner_accepted", "stage_closed"):
            if type(getattr(self, key)) is not bool:
                raise WorkflowError("invalid boolean state")
        for key in ("task_id", "stage_input_ref", "formal_task_intent_ref", "formal_constraint_ref", "latest_execution_report_ref",
                    "executor_context_ref", "active_review_context_ref", "human_gate_reason", "last_completed_activity",
                    "in_flight_activity", "active_blocker_id", "acceptance_ref"):
            if getattr(self, key) is not None and not isinstance(getattr(self, key), str):
                raise WorkflowError("invalid state reference")
        for key in ("role_context_refs", "artifact_refs", "blocker_ledger", "task_checkpoint_refs"):
            if not isinstance(getattr(self, key), dict):
                raise WorkflowError("invalid state map")
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.role_context_refs.items()):
            raise WorkflowError("invalid context refs")
        if any(k not in {r.value for r in Role if r != Role.EXECUTOR} for k in self.role_context_refs):
            raise WorkflowError("unknown role context")
        for task_id, ref in self.task_checkpoint_refs.items():
            identity(task_id)
            if not isinstance(ref, str) or not ref:
                raise WorkflowError("invalid Task checkpoint reference")
        if any(not isinstance(k, str) or not isinstance(v, list) or any(not isinstance(r, str) for r in v)
               for k, v in self.artifact_refs.items()):
            raise WorkflowError("invalid artifact refs")
        for key, entry in self.blocker_ledger.items():
            if not isinstance(key, str) or not isinstance(entry, dict) or set(entry) != {"repair_used", "new_basis_used", "decision_treatment_used", "decision_flow_used", "basis_id"}:
                raise WorkflowError("invalid retry ledger")
            if any(type(entry[k]) is not bool for k in ("repair_used", "new_basis_used", "decision_treatment_used", "decision_flow_used")):
                raise WorkflowError("invalid retry counters")
            if entry["basis_id"] is not None and not isinstance(entry["basis_id"], str):
                raise WorkflowError("invalid basis id")
        for key in ("used_task_ids", "memory_completed_roles"):
            values = getattr(self, key)
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values) or len(values) != len(set(values)):
                raise WorkflowError("invalid state list")
        for value in self.used_task_ids:
            identity(value)
        for key in ("last_result", "commit_receipt", "pending_override"):
            if getattr(self, key) is not None and not isinstance(getattr(self, key), dict):
                raise WorkflowError("invalid state summary")
        if not isinstance(self.human_events, list) or any(not isinstance(v, dict) for v in self.human_events):
            raise WorkflowError("invalid human event history")
        if self.waiting_human != (node in {Node.HUMAN_GATE, Node.HUMAN_BLOCK, Node.RECOVERY_REQUIRED}):
            raise WorkflowError("human wait flag disagrees with node")
        if self.waiting_human and not self.human_gate_reason:
            raise WorkflowError("human wait has no explicit reason")
        expected_status = {Node.HUMAN_GATE: "WAITING_HUMAN", Node.HUMAN_BLOCK: "WAITING_HUMAN",
                           Node.RECOVERY_REQUIRED: "RECOVERY_REQUIRED", Node.FAILED: "FAILED", Node.COMPLETED: "COMPLETED"}.get(node, "RUNNING")
        if self.status != expected_status:
            raise WorkflowError("status disagrees with node")
        if self.owner_accepted and (node != Node.COMPLETED or not self.machine_close_ready):
            raise WorkflowError("invalid Owner acceptance")
        if self.active_grant is not None:
            from .governance import ScopeGrant
            values = dict(self.active_grant)
            values['stage_ids'] = tuple(values['stage_ids'])
            values['series_ids'] = tuple(values['series_ids'])
            values['task_ids'] = tuple(values['task_ids'])
            values['relationships'] = tuple(values['relationships'].items())
            ScopeGrant(**values).validate()
        if not isinstance(self.stage_issues, dict) or not isinstance(self.issue_triage, list) or not isinstance(self.soft_window_events, list):
            raise WorkflowError("invalid governance state")
        if (not isinstance(self.mediation_counts, dict) or any(not isinstance(key, str) or type(value) is not int or value < 0
                for key, value in self.mediation_counts.items()) or not isinstance(self.owner_window_refs, list)
                or any(not isinstance(ref, str) for ref in self.owner_window_refs)):
            raise WorkflowError('invalid Decision mediation state')
        for key in ('decision_handoff_ref', 'mediation_result_ref', 'latest_decision_notice_ref'):
            if getattr(self, key) is not None and not isinstance(getattr(self, key), str):
                raise WorkflowError('invalid Decision mediation reference')
        if node == Node.DECISION_MEDIATION and not self.decision_handoff_ref:
            raise WorkflowError('Decision mediation lacks actual saved handoff')
        if self.stage_closed and (not self.machine_close_ready or not self.stage_closeout_ref or not self.stage_knowledge_ref):
            raise WorkflowError("Stage close lacks actual final closeout/knowledge")
        if node == Node.HUMAN_GATE and not self.machine_close_ready:
            raise WorkflowError("human gate without machine close")
        if node in {Node.COMMIT_AUTHORIZATION, Node.EXECUTOR_LOCAL_COMMIT, Node.TASK_COMPLETE}:
            if not self.acceptance_ref or not self.latest_execution_report_ref or not self.formal_constraint_ref:
                raise WorkflowError("commit state lacks acceptance/input/report")
        if node == Node.TASK_COMPLETE and self.task_id not in self.task_checkpoint_refs:
            raise WorkflowError("Task completion state lacks a formal checkpoint reference")
        if self.commit_receipt is not None:
            receipt = self.commit_receipt
            if (set(receipt) != {"commit_hash", "message", "staged_files", "final_status"}
                    or not isinstance(receipt["commit_hash"], str)
                    or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", receipt["commit_hash"])
                    or not isinstance(receipt["message"], str) or not receipt["message"]
                    or not isinstance(receipt["final_status"], str) or not isinstance(receipt["staged_files"], list)
                    or not receipt["staged_files"] or any(not isinstance(p, str) or not p for p in receipt["staged_files"])):
                raise WorkflowError("invalid actual commit receipt state")
        if node in TASK_REQUIRED_NODES and (not self.task_id or not self.formal_task_intent_ref):
            raise WorkflowError("task node lacks explicit task identity/Intent")
        if self.active_blocker_id and self.active_blocker_id not in self.blocker_ledger:
            raise WorkflowError("active blocker absent from retry ledger")
        if self.pending_override:
            from loommode.roles.contracts import OVERRIDE_SCHEMA, validate
            validate(self.pending_override, OVERRIDE_SCHEMA)
        if self.pending_override_task_id is not None:
            identity(self.pending_override_task_id)
            if self.pending_override is None or self.pending_override_task_id != self.task_id:
                raise WorkflowError("override owner disagrees with current Task")
        for activity in (self.last_completed_activity, self.in_flight_activity):
            if activity is not None and activity not in {n.value for n in Node}:
                raise WorkflowError("unknown activity checkpoint")


class StateStore:
    def __init__(self, dev_env_root: Path, project: str, stage_id: str) -> None:
        self.project, self.stage_id = identity(project), identity(stage_id)
        self.path = dev_env_root.resolve() / "workflow" / project / stage_id / "state.json"

    def save(self, state: WorkflowState) -> None:
        state.validate()
        if (state.project, state.stage_id) != (self.project, self.stage_id):
            raise WorkflowError("checkpoint identity mismatch")
        atomic_json(self.path, state.as_dict())

    def load_for_restart(self) -> WorkflowState:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object)
            if not isinstance(payload, dict) or set(payload) != {f.name for f in fields(WorkflowState)}:
                raise WorkflowError("checkpoint fields missing or unknown")
            state = WorkflowState(**payload)
            state.validate()
            if (state.project, state.stage_id) != (self.project, self.stage_id):
                raise WorkflowError("checkpoint identity mismatch")
        except (TypeError, ValueError, OSError) as exc:
            raise WorkflowError("invalid checkpoint; recovery requires actual evidence") from exc
        if Node(state.current_node) != Node.COMPLETED:
            state.current_node = Node.RECOVERY_REQUIRED.value
            state.status = "RECOVERY_REQUIRED"
            state.waiting_human = True
            state.human_gate_reason = "Process restarted; inspect actual effects and provide directed recovery. No context resume or replay."
            self.save(state)
        return state
