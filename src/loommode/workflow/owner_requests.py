"""Exact Owner-input receipt, separate from role results and permissions."""
import json
from typing import Any

from loommode.roles.contracts import array, enum, nullable, obj, text, validate
from .errors import WorkflowError
from .state import identity, unique_json_object
from .transitions import Node

OWNER_INPUT_NODES = {Node.DECISION_MEDIATION, Node.STAGE_PLANNING, Node.TASK_SELECTION, Node.PROMOTER_RESULT_REVIEW, Node.PROMOTER_ARBITRATION,
                     Node.PROMOTER_IMPLEMENTATION_PLAN, Node.PROMOTER_DECISION_ACCEPTANCE, Node.STAGE_SETTLEMENT}
CHECK_FOCUS = ["CODE", "TESTS", "AUTHORITY", "ENVIRONMENT"]
OWNER_REQUEST_SCHEMA = obj({"origin": enum(["HOST_OWNER_REQUEST"]), "request_id": text(),
    "project": text(), "stage_id": text(), "task_id": nullable(text()),
    "kind": enum(["CHECK", "DIRECTION"]), "scope": enum(["TASK", "STAGE"]),
    "direction": text(), "evidence_refs": array(text()), "check_focus": array(enum(CHECK_FOCUS))})


def parse_owner_request(raw: str) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=unique_json_object)
    validate(value, OWNER_REQUEST_SCHEMA)
    for key in ("request_id", "project", "stage_id"):
        identity(value[key])
    if value["scope"] == "TASK":
        identity(value["task_id"])
    elif value["task_id"] is not None:
        raise WorkflowError("Stage request cannot carry a Task target")
    if not value["direction"].strip() or not value["evidence_refs"]:
        raise WorkflowError("Owner request needs direction and explicit evidence")
    if len(value["evidence_refs"]) != len(set(value["evidence_refs"])):
        raise WorkflowError("duplicate Owner evidence refs")
    if value["kind"] == "CHECK" and not value["check_focus"]:
        raise WorkflowError("directed check needs objective focus")
    if value["kind"] == "DIRECTION" and value["check_focus"]:
        raise WorkflowError("direction is not an automatic check")
    return value
