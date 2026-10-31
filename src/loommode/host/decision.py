"""One reusable Owner entry: query, inspect evidence and optionally explain facts."""
from __future__ import annotations

import copy
from threading import Lock
from typing import Any

from loommode.codex.errors import LoomModeError
from loommode.roles.runtime import RoleRuntime
from loommode.workflow.errors import WorkflowError
from .state_view import StateProjection, StatusSnapshot, _digest
from .terminal import classify_managed


class DecisionEntry:
    def __init__(self, projection: StateProjection, roles: RoleRuntime | None = None) -> None:
        if roles is not None and (roles.stage_id != projection.stage_id or
                                 roles.policy.workspace.resolve() != projection.workspace or
                                 roles.adapter.registry is not projection.registry):
            raise WorkflowError("Decision entry runtime/Registry binding mismatch")
        self.projection, self.roles = projection, roles
        self._explanation_lock = Lock()
        self._delegation_provider = None
        self._managed_provider = None
        self._model_guard = None

    def bind_delegation_provider(self, provider) -> None:
        if self._delegation_provider is not None:
            raise WorkflowError("Decision entry already has a live Host binding")
        self._delegation_provider = provider

    def bind_managed_provider(self, provider) -> None:
        if self._managed_provider is not None:
            raise WorkflowError("Decision entry already has a managed run binding")
        self._managed_provider = provider

    def query(self) -> StatusSnapshot:
        snapshot = self.projection.capture()
        if self._delegation_provider is not None and snapshot.view["availability"] == "AVAILABLE":
            delegation, materials = self._delegation_provider()
            view = snapshot.as_dict()
            view["delegation"] = delegation
            if delegation and not delegation["continuing"]:
                for item in view["activities"]["pending"]:
                    item.update(status="HELD_BY_DELEGATION", reason=delegation["reason"])
            snapshot = StatusSnapshot(view, {**snapshot.materials, **materials},
                                     _digest({"facts_revision": snapshot.revision, "delegation": delegation}))
        if self._managed_provider is not None:
            managed, materials = self._managed_provider()
            view = snapshot.as_dict()
            view["managed_run"] = managed
            managed["presentation"] = classify_managed(view, {**snapshot.materials, **materials})
            # Mechanical queue/worker bookkeeping cannot stale an already
            # displayed OwnerRequest. Sequence ownership guards managed inputs.
            snapshot = StatusSnapshot(view, {**snapshot.materials, **materials}, snapshot.revision)
        return snapshot

    def read_artifact(self, reference: str) -> str:
        snapshot = self.query()
        if reference not in snapshot.materials:
            raise WorkflowError("reference is not verified evidence in this bound snapshot")
        # Recheck the actual bytes at drill-down, rather than return a stale cached body.
        if "#sha256=" in reference:
            return self.projection.artifacts.read(reference)
        return snapshot.materials[reference]

    def explain(self, question: str) -> dict[str, Any]:
        snapshot = self.query()
        response = {"mode": "READ_ONLY", "facts": snapshot.as_dict(), "factual_summary": snapshot.summary(),
                    "revision": snapshot.revision,
                    "explanation": None, "invocation": None, "error": None, "stale": False}
        if self.roles is None:
            response["error"] = "No authorized explanation runtime is bound; factual query remains available."
            return response
        if not self._explanation_lock.acquire(blocking=False):
            response["error"] = "An explanation is already in flight; factual query remains available."
            return response
        try:
            # Check admission after acquiring the same lock that managed
            # startup checks while claiming the shared Host ownership lock.
            # Engine busy flags alone leave an unsafe gap between workers.
            reason = self._model_guard() if self._model_guard is not None else None
            if reason:
                response["error"] = reason
            else:
                invocation = self.roles.explain_status(question=question, projection=snapshot.as_dict(),
                                                       materials=dict(snapshot.materials))
                response["explanation"] = copy.deepcopy(invocation.result)
                response["invocation"] = {"context_ref": invocation.context_ref, **(invocation.metadata or {})}
        except (WorkflowError, LoomModeError, OSError, ValueError, TypeError) as exc:
            response["error"] = str(exc)
        finally:
            self._explanation_lock.release()
        after = self.query()
        response["stale"] = after.revision != snapshot.revision
        if response["stale"]:
            response["current_facts"] = after.as_dict()
            response["current_revision"] = after.revision
            response["current_factual_summary"] = after.summary()
        return response
