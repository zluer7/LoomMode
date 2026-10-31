"""Explicit Owner requests and a finite text command front end; never role actions."""
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from loommode.workflow.errors import WorkflowError
from loommode.workflow.owner_requests import parse_owner_request
from loommode.workflow.state import identity
import json
import hashlib
from pathlib import Path
import re

KINDS = {"STATUS", "EXPLAIN", "ARTIFACT", "GATE", "CHECK", "DIRECTION"}


@dataclass(frozen=True)
class DelegationRequest:
    """An explicit scope selection against the Owner's displayed facts."""
    project: str
    stage_id: str
    scope: str
    expected_revision: str
    workspace: str
    stage_authorization_ref: str
    stage_authorization_sha256: str
    task_id: str | None
    task_intent_ref: str | None
    task_goal: str | None
    request_id: str = field(default_factory=lambda: "D" + uuid4().hex)
    scope_id: str | None = None
    authority_ref: str | None = None
    authority_sha256: str | None = None

    @classmethod
    def from_snapshot(cls, snapshot: Any, scope: str, *, request_id: str | None = None,
                      scope_id=None, authority_ref=None, authority_sha256=None):
        view = snapshot.view
        if view["availability"] != "AVAILABLE" or view["stage_input"]["verification"] not in {"VERIFIED", "HOST_SUPPLIED"}:
            raise WorkflowError("delegation requires verified displayed Stage facts")
        values = dict(project=view["project"], stage_id=view["stage_id"], scope=scope,
            expected_revision=snapshot.revision, workspace=view["workspace"],
            stage_authorization_ref=view["stage_input"]["reference"],
            stage_authorization_sha256=hashlib.sha256(view["stage_input"]["content"].encode("utf-8")).hexdigest(),
            task_id=view["task"]["task_id"], task_intent_ref=view["task"]["intent_ref"], task_goal=view["task"]["goal"])
        if request_id is not None:
            values["request_id"] = request_id
        values.update(scope_id=scope_id, authority_ref=authority_ref, authority_sha256=authority_sha256)
        return cls(**values)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_frame(cls, snapshot, frame):
        return cls.from_snapshot(snapshot, frame['scope'], request_id=frame.get('request_id'),
            scope_id=frame.get('scope_id'), authority_ref=frame.get('authority_ref'),
            authority_sha256=frame.get('authority_sha256'))

    def validate(self) -> None:
        for value in (self.project, self.stage_id, self.request_id):
            identity(value)
        from loommode.workflow.governance import scope_name
        scope = scope_name(self.scope)
        if scope in {'SERIES', 'MAJOR_PHASE', 'EXPLICIT_BOUNDED_SCOPE'}:
            if not self.scope_id or not self.authority_ref or not self.authority_sha256 or not re.fullmatch('[0-9a-f]{64}', self.authority_sha256):
                raise WorkflowError('broader scope requires explicit scope identity and Owner authority digest')
            identity(self.scope_id)
        for value in (self.expected_revision, self.stage_authorization_sha256):
            if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
                raise WorkflowError("explicit snapshot/Stage authorization digest required")
        if not isinstance(self.workspace, str) or not Path(self.workspace).is_absolute():
            raise WorkflowError("delegation requires the explicit absolute workspace")
        if not isinstance(self.stage_authorization_ref, str) or not self.stage_authorization_ref:
            raise WorkflowError("explicit Stage authorization reference required")
        if self.task_id is not None:
            identity(self.task_id)
            if any(not isinstance(value, str) or not value.strip() for value in (self.task_intent_ref, self.task_goal)):
                raise WorkflowError("delegation requires the current Task's formal Intent and goal")
        elif self.task_intent_ref is not None or self.task_goal is not None:
            raise WorkflowError("Task-free Stage selection must not invent a Task")


@dataclass(frozen=True)
class OwnerRequest:
    project: str
    stage_id: str
    kind: str
    request_id: str = field(default_factory=lambda: "O" + uuid4().hex)
    task_id: str | None = None
    scope: str = "STAGE"
    direction: str = ""
    evidence_refs: tuple[str, ...] = ()
    check_focus: tuple[str, ...] = ()
    expected_revision: str | None = None
    artifact_ref: str | None = None
    event: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        identity(self.project)
        identity(self.stage_id)
        identity(self.request_id)
        if self.task_id is not None:
            identity(self.task_id)
        if self.kind not in KINDS or self.scope not in {"TASK", "STAGE"}:
            raise WorkflowError("unknown Owner request kind/scope")
        if not isinstance(self.direction, str) or not isinstance(self.evidence_refs, tuple) or any(
                not isinstance(ref, str) or not ref for ref in self.evidence_refs):
            raise WorkflowError("Owner direction/evidence must be explicit text")
        if not isinstance(self.check_focus, tuple):
            raise WorkflowError("Owner check focus must be explicit")
        if self.kind in {"CHECK", "DIRECTION"}:
            self.packet()

    def packet(self) -> dict[str, Any]:
        packet = {"origin": "HOST_OWNER_REQUEST", "request_id": self.request_id,
            "project": self.project, "stage_id": self.stage_id, "task_id": self.task_id,
            "kind": self.kind, "scope": self.scope, "direction": self.direction,
            "evidence_refs": list(self.evidence_refs), "check_focus": list(self.check_focus)}
        return parse_owner_request(json.dumps(packet, ensure_ascii=False))


def urgent_stop_from_text(text, *, project, stage_id, task_id=None, expected_revision=None):
    if not isinstance(text, str):
        return None
    raw = text.strip()
    event = {'PAUSE': 'PAUSE', 'OBJECT': 'OBJECT', '暂停': 'PAUSE', '反对': 'OBJECT'}.get(raw.split(' ', 1)[0].rstrip('?？。'))
    if event:
        return OwnerRequest(project=project, stage_id=stage_id, task_id=task_id, kind='GATE',
                            event=event, direction=raw, expected_revision=expected_revision)
    return None


def request_from_text(text: str, displayed: Any) -> OwnerRequest | None:
    """Convert only finite, explicit commands against the last displayed snapshot."""
    if not isinstance(text, str) or not text.strip() or displayed.view["availability"] != "AVAILABLE":
        return None
    raw = text.strip()
    clean = raw.rstrip("?？。")
    view = displayed.view
    base = {"project": view["project"], "stage_id": view["stage_id"]}
    urgent = urgent_stop_from_text(raw, **base, task_id=view['task']['task_id'], expected_revision=displayed.revision)
    if urgent:
        return urgent
    if clean.lower() in {"status", "history", "状态", "查看活动历史", "现在到哪里了", "上一 Task 是否接受", "上一Task是否接受"}:
        return OwnerRequest(**base, kind="STATUS")
    if clean in {"为什么停了", "现在需要我做什么"}:
        return OwnerRequest(**base, kind="EXPLAIN", direction=raw)
    for prefix in ("EXPLAIN ", "解释 ", "解释："):
        if raw.startswith(prefix):
            return OwnerRequest(**base, kind="EXPLAIN", direction=raw[len(prefix):].strip())
    if clean in {"查看报告", "查看最近结果", "REPORT"}:
        ref = view["task"]["report_ref"] or view["latest_accepted"]["report_ref"]
        return OwnerRequest(**base, kind="ARTIFACT", artifact_ref=ref) if ref else None
    for prefix in ("ARTIFACT ", "查看记录 "):
        if raw.startswith(prefix):
            return OwnerRequest(**base, kind="ARTIFACT", artifact_ref=raw[len(prefix):].strip())
    events = {"批准当前阶段": "APPROVE_STAGE", "拒绝当前阶段": "REJECT_STAGE", "请求更多工作": "REQUEST_MORE_WORK"}
    event = events.get(clean)
    for name in ("APPROVE_STAGE", "REJECT_STAGE", "REQUEST_MORE_WORK", "RESOLVE_HUMAN_BLOCK", "REQUEST_SAME_TASK_REPAIR", "COMPLETE_STAGE_REVIEW", "PAUSE", "OBJECT"):
        if raw == name or raw.startswith(name + " "):
            event = name
    refs = tuple(view["stage_input"]["reference"] for _ in [0] if view["stage_input"]["verification"] in {"VERIFIED", "HOST_SUPPLIED"})
    if event:
        return OwnerRequest(**base, kind="GATE", task_id=view["task"]["task_id"], event=event,
            direction=raw, evidence_refs=refs, expected_revision=displayed.revision)
    for prefix, kind in (("CHECK ", "CHECK"), ("请检查", "CHECK"), ("定向检查", "CHECK"),
                         ("DIRECTION ", "DIRECTION"), ("方向：", "DIRECTION")):
        if raw.startswith(prefix) and raw[len(prefix):].strip():
            task = view["task"]["task_id"]
            return OwnerRequest(**base, kind=kind, task_id=task, scope="TASK" if task else "STAGE",
                direction=raw[len(prefix):].strip(), evidence_refs=refs, expected_revision=displayed.revision,
                check_focus=("CODE", "TESTS") if kind == "CHECK" else ())
    return None
