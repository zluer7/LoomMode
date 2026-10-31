"""Strict LoomMode activity result schema and local validator."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from .errors import ErrorCategory, LoomModeError


RESULT_FIELDS = frozenset(
    {"result", "next_action", "explanation", "artifacts", "failure", "human_required"}
)

TASK_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "LoomModeTaskResult",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "result",
        "next_action",
        "explanation",
        "artifacts",
        "failure",
        "human_required",
    ],
    "properties": {
        "result": {"type": "string"},
        "next_action": {"type": "string"},
        "explanation": {"type": "string"},
        "artifacts": {"type": "array", "items": {"type": "string"}},
        "failure": {"type": ["string", "null"]},
        "human_required": {"type": "boolean"},
    },
}


@dataclass(frozen=True)
class StructuredResult:
    result: str
    next_action: str
    explanation: str
    artifacts: tuple[str, ...]
    failure: str | None
    human_required: bool

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["artifacts"] = list(self.artifacts)
        return value


def validate_result(value: Any) -> StructuredResult:
    if not isinstance(value, dict):
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "structured result must be a JSON object",
        )
    keys = set(value)
    missing = sorted(RESULT_FIELDS - keys)
    extra = sorted(keys - RESULT_FIELDS)
    if missing or extra:
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "structured result has an invalid field set",
            details={"missing": missing, "extra": extra},
        )
    for name in ("result", "next_action", "explanation"):
        if not isinstance(value[name], str):
            raise LoomModeError(
                ErrorCategory.STRUCTURED_OUTPUT_ERROR,
                f"{name} must be a string",
            )
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or not all(isinstance(item, str) for item in artifacts):
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "artifacts must be an array of strings",
        )
    failure = value["failure"]
    if failure is not None and not isinstance(failure, str):
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "failure must be a string or null",
        )
    if type(value["human_required"]) is not bool:
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "human_required must be a boolean",
        )
    return StructuredResult(
        result=value["result"],
        next_action=value["next_action"],
        explanation=value["explanation"],
        artifacts=tuple(artifacts),
        failure=failure,
        human_required=value["human_required"],
    )


def parse_result(text: str | None) -> StructuredResult:
    if text is None:
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "completed turn did not contain a final agent message",
        )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoomModeError(
            ErrorCategory.STRUCTURED_OUTPUT_ERROR,
            "final agent message is not valid JSON",
            details={"line": exc.lineno, "column": exc.colno},
        ) from exc
    return validate_result(value)
