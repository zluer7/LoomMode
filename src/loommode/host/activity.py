"""Bounded observed activities for presentation; never a dispatch or session journal."""
from __future__ import annotations

import copy
import hashlib
import json
from threading import Lock
from typing import Any

from loommode.roles.contracts import result_schema, validate
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object
from loommode.workflow.transitions import FRESH_NODES, Node, Role, TABLE


def _role(activity: str | None) -> str | None:
    if activity is None or activity == Node.ROLE_MEMORY_CONSOLIDATION.value:
        return None
    node = Node(activity)
    return TABLE[node][0].value if node in TABLE else None


def _context(view: dict[str, Any], activity: str | None) -> dict[str, Any] | None:
    role = _role(activity)
    if role is None:
        return None
    key = "Review" if Node(activity) in FRESH_NODES else role
    return copy.deepcopy(view["contexts"].get(key))


class ActivityView:
    def __init__(self, limit: int = 25) -> None:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise WorkflowError("activity history limit must be between 1 and 100")
        self.limit = limit
        self._recent: list[dict[str, Any]] = []
        self._evicted = 0
        self._lock = Lock()

    def observe(self, view: dict[str, Any], materials: dict[str, str]) -> dict[str, Any]:
        # A managed worker and Owner facts reader can share this presentation
        # cache. Deduplication, eviction and export form one observation.
        with self._lock:
            return self._observe(view, materials)

    def _observe(self, view: dict[str, Any], materials: dict[str, str]) -> dict[str, Any]:
        available = view["availability"] == "AVAILABLE"
        result = {"main_entry": {"role": Role.DECISION.value, "kind": "OWNER_ENTRY"},
                  "active": [], "pending": [], "attention": [],
                  "recent": [], "history": {"coverage": "OBSERVED_COMPLETIONS_ONLY", "limit": self.limit,
                  "evicted": self._evicted, "persistent": False,
                  "source_available": available,
                  "limitation": "Only completions observed by this bound Host are listed. Formal evidence remains separate; no full activity journal or cross-process resume."}}
        if available:
            self._remember(view, materials)
            activity, gate = view["activity"], view["gate"]
            base = {"project": view["project"], "stage_id": view["stage_id"],
                    "task_id": view["task"]["task_id"], "node": view["node"],
                    "source": copy.deepcopy(view["source"]), "dispatch_authorized": False}
            if view["status"] == "FAILED":
                result["attention"].append({**base, "status": activity["status"],
                    "activity": activity["in_flight"], "reason": gate["reason"],
                    "effects": "UNKNOWN" if activity["in_flight"] else "NOT_VERIFIED"})
            elif gate["kind"]:
                result["attention"].append({**base, "status": gate["kind"], "reason": gate["reason"],
                    "activity": activity["in_flight"], "owner_action_needed": True})
            elif activity["in_flight"]:
                current = activity["in_flight"]
                result["active"].append({**base, "activity": current, "role": _role(current),
                    "status": "IN_FLIGHT_OBSERVED", "context": _context(view, current),
                    "native_turn_running": "NOT_VERIFIED_BY_MARKER"})
            elif activity["host_busy"]:
                result["attention"].append({**base, "status": "HOST_BUSY_UNKNOWN_ACTIVITY",
                    "activity": None, "reason": "Host busy without a specific in-flight marker; do not dispatch or infer a native turn."})
            elif view["status"] == "RUNNING":
                result["pending"].append({**base, "activity": view["node"], "role": _role(view["node"]),
                    "status": 'SOFT_WINDOW_WAIT' if view['node'] in {'SOFT_REVIEW_WAIT', 'SOFT_ACCEPTANCE_WAIT'} else "PENDING_DISPATCH", "context": _context(view, view["node"])})
            result["historical_evidence"] = copy.deepcopy(view["evidence"])
        else:
            result["attention"].append({"status": view["availability"],
                                        "reason": view["issues"][0]["problem"], "dispatch_authorized": False})
            result["historical_evidence"] = []
        result["recent"] = copy.deepcopy(list(reversed(self._recent)))
        result["history"]["evicted"] = self._evicted
        return result

    def _remember(self, view: dict[str, Any], materials: dict[str, str]) -> None:
        completed = view["activity"]["last_completed"]
        if completed is None:
            return
        node = Node(completed)
        last = view["activity"]["last_result"] or {}
        result_ref, invocation = None, None
        # Mechanical nodes and the four-role memory group retain a prior last_result.
        # Only a verified, node-valid role receipt can bind that metadata here.
        candidate = last.get("result_ref")
        if node in TABLE and node != Node.ROLE_MEMORY_CONSOLIDATION and isinstance(candidate, str) and candidate in materials:
            try:
                body = json.loads(materials[candidate], object_pairs_hook=unique_json_object)
                validate(body, result_schema(node))
                if body["action"] == last.get("action"):
                    result_ref = candidate
                    invocation = copy.deepcopy(last.get("invocation"))
            except (WorkflowError, ValueError, TypeError):
                pass
        key = {"task": view["task"]["task_id"], "activity": completed, "result_ref": result_ref,
               "turn_id": invocation.get("turn_id") if isinstance(invocation, dict) else None}
        record_id = hashlib.sha256(json.dumps(key, sort_keys=True).encode("utf-8")).hexdigest()
        if any(item["id"] == record_id for item in self._recent):
            return
        task_refs = [value["reference"] for value in view["task"]["formal_refs"].values()
                     if value["verification"] == "VERIFIED"]
        self._recent.append({"id": record_id, "project": view["project"], "stage_id": view["stage_id"],
            "task_id": view["task"]["task_id"], "activity": completed, "role": _role(completed),
            "status": "COMPLETED_OBSERVED", "retired": True, "dispatch_authorized": False,
            "observed_at": view["observed_at"], "source": copy.deepcopy(view["source"]),
            "result_ref": result_ref, "invocation": invocation,
            "context_at_observation": _context(view, completed),
            "freshness_granted_by_history": False, "task_evidence_refs": task_refs})
        if len(self._recent) > self.limit:
            self._recent.pop(0)
            self._evicted += 1
