"""Small, stable error vocabulary for the future workflow engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ErrorCategory(StrEnum):
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    PROCESS_ERROR = "PROCESS_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    MODEL_ERROR = "MODEL_ERROR"
    STRUCTURED_OUTPUT_ERROR = "STRUCTURED_OUTPUT_ERROR"
    WORKSPACE_ERROR = "WORKSPACE_ERROR"
    TOOL_PERMISSION_ERROR = "TOOL_PERMISSION_ERROR"
    TOOL_EXECUTION_ERROR = "TOOL_EXECUTION_ERROR"
    TOOL_TIMEOUT = "TOOL_TIMEOUT"
    AUTH_ERROR = "AUTH_ERROR"
    TURN_FAILED = "TURN_FAILED"
    TURN_INTERRUPTED = "TURN_INTERRUPTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"


@dataclass(frozen=True)
class ErrorRecord:
    category: ErrorCategory
    message: str
    retryable: bool = False
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details or {},
        }


class LoomModeError(Exception):
    def __init__(
        self,
        category: ErrorCategory,
        message: str,
        *,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.record = ErrorRecord(category, message, retryable, details)


def error_record(exc: BaseException) -> ErrorRecord:
    if isinstance(exc, LoomModeError):
        return exc.record
    return ErrorRecord(
        ErrorCategory.PROCESS_ERROR,
        f"{type(exc).__name__}: {exc}",
        details={"exception_type": type(exc).__name__},
    )
