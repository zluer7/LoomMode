"""Minimal metadata registry; it does not claim crash-recovery support."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any

from .errors import ErrorCategory, LoomModeError


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ContextPurpose(StrEnum):
    DEVELOPMENT = "development"
    FRESH_REVIEW = "fresh_review"
    READ_ONLY_ROLE = "read_only_role"


class FreshnessState(StrEnum):
    DEVELOPMENT = "development"
    FRESH_REVIEW = "fresh_review"
    READ_ONLY_ROLE = "read_only_role"
    REVIEW_CONVERTED_TO_DEVELOPMENT = "review_converted_to_development"


class ResourceState(StrEnum):
    ACTIVE = "ACTIVE"
    RETAINED = "RETAINED"
    RETIRED = "RETIRED"
    RELEASABLE = "RELEASABLE"
    RELEASED = "RELEASED"


@dataclass
class ContextRecord:
    thread_id: str
    purpose: ContextPurpose
    workspace: str
    model: str
    reasoning_effort: str
    tool_profile: str
    freshness: FreshnessState
    codex_version: str
    created_at: str
    updated_at: str
    last_turn_id: str | None = None
    last_terminal_status: str | None = None
    activity_metadata: dict[str, str] | None = None
    cross_process_resume: str = "NOT_VERIFIED"
    owner_id: str | None = None
    resource_state: ResourceState = ResourceState.RETAINED
    protection: str | None = None
    release_receipt: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["purpose"] = self.purpose.value
        value["freshness"] = self.freshness.value
        value["resource_state"] = self.resource_state.value
        return value


class ContextRegistry:
    def __init__(self, persistence_path: Path | None = None) -> None:
        self.persistence_path = persistence_path
        self._records: dict[str, ContextRecord] = {}
        self._reference_pins: set[str] = set()
        self._lock = RLock()
        if persistence_path and persistence_path.exists():
            self._load()

    def create(
        self,
        *,
        thread_id: str,
        purpose: ContextPurpose,
        workspace: Path,
        model: str,
        reasoning_effort: str,
        tool_profile: str,
        codex_version: str,
        activity_metadata: dict[str, str] | None = None,
        owner_id: str | None = None,
    ) -> ContextRecord:
        with self._lock:
            if thread_id in self._records:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "context already exists")
            now = utc_now()
            freshness = (
                FreshnessState.FRESH_REVIEW
                if purpose == ContextPurpose.FRESH_REVIEW
                else FreshnessState.READ_ONLY_ROLE if purpose == ContextPurpose.READ_ONLY_ROLE
                else FreshnessState.DEVELOPMENT
            )
            record = ContextRecord(
                thread_id=thread_id,
                purpose=purpose,
                workspace=str(workspace),
                model=model,
                reasoning_effort=reasoning_effort,
                tool_profile=tool_profile,
                freshness=freshness,
                codex_version=codex_version,
                created_at=now,
                updated_at=now,
                activity_metadata=dict(activity_metadata or {}),
                owner_id=owner_id,
            )
            self._records[thread_id] = record
            self._save()
            return record

    def get(self, thread_id: str) -> ContextRecord:
        try:
            return self._records[thread_id]
        except KeyError as exc:
            raise LoomModeError(
                ErrorCategory.CONFIG_ERROR,
                "unknown opaque context id",
            ) from exc

    def authorize_development(self, thread_id: str, development_profile: str) -> ContextRecord:
        with self._lock:
            record = self.get(thread_id)
            if record.resource_state not in {ResourceState.ACTIVE, ResourceState.RETAINED}:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "retired context cannot be converted")
            if record.freshness == FreshnessState.FRESH_REVIEW:
                record.freshness = FreshnessState.REVIEW_CONVERTED_TO_DEVELOPMENT
                record.tool_profile = development_profile
                record.updated_at = utc_now()
                self._save()
                return record
            if record.freshness == FreshnessState.REVIEW_CONVERTED_TO_DEVELOPMENT:
                return record
            raise LoomModeError(
                ErrorCategory.CONFIG_ERROR,
                "only a fresh review context can be converted to development",
            )

    def assert_fresh_review(self, thread_id: str) -> None:
        if self.get(thread_id).freshness != FreshnessState.FRESH_REVIEW:
            raise LoomModeError(
                ErrorCategory.CONFIG_ERROR,
                "context is no longer eligible for fresh review",
            )

    def record_turn(self, thread_id: str, turn_id: str | None, status: str) -> None:
        with self._lock:
            record = self.get(thread_id)
            record.last_turn_id = turn_id
            record.last_terminal_status = status
            record.updated_at = utc_now()
            self._save()

    def all(self) -> tuple[ContextRecord, ...]:
        return tuple(self._records.values())

    def retain_current_references(self, thread_ids: set[str]) -> None:
        # Pins preserve only the finite current State references, not old history.
        if len(thread_ids) > 8:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "current Context metadata reference limit exceeded")
        self._reference_pins = set(thread_ids)

    def resource(self, thread_id: str, state: ResourceState, *,
                 protection: str | None = None, receipt: dict[str, Any] | None = None) -> None:
        with self._lock:
            record = self.get(thread_id)
            if record.resource_state == ResourceState.RELEASED and state != ResourceState.RELEASED:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "released context cannot be resurrected")
            record.resource_state = state
            record.protection = protection
            if receipt is not None:
                record.release_receipt = dict(receipt)
            record.updated_at = utc_now()
            # Only released metadata is pruned. Persisted workflow artifacts/history
            # remain authoritative; this registry never adopts their threads.
            released = [key for key, value in self._records.items()
                        if value.resource_state == ResourceState.RELEASED and key not in self._reference_pins]
            for key in released[:-64]:
                del self._records[key]
            self._save()

    def _save(self) -> None:
        if not self.persistence_path:
            return
        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.persistence_path.with_suffix(self.persistence_path.suffix + ".tmp")
        payload = {
            "schema_version": 1,
            "capability": "metadata_only_cross_process_resume_not_verified",
            "contexts": [record.as_dict() for record in self._records.values()],
        }
        temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temp, self.persistence_path)

    def _load(self) -> None:
        assert self.persistence_path is not None
        payload = json.loads(self.persistence_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "unsupported context registry schema")
        for value in payload.get("contexts", []):
            record = ContextRecord(
                **{
                    **value,
                    "purpose": ContextPurpose(value["purpose"]),
                    "freshness": FreshnessState(value["freshness"]),
                    "resource_state": ResourceState(value.get("resource_state", "RETAINED")),
                }
            )
            self._records[record.thread_id] = record
