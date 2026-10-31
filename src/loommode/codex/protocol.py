"""JSON-RPC message helpers and turn event extraction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import ErrorCategory, LoomModeError


def rpc_request(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"id": request_id, "method": method, "params": params}


def rpc_notification(method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"method": method, "params": params}


def rpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"id": request_id, "result": result}


def rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"id": request_id, "error": {"code": code, "message": message}}


def is_server_request(message: dict[str, Any]) -> bool:
    return (
        "id" in message
        and "method" in message
        and "result" not in message
        and "error" not in message
    )


def is_matching_completion(
    message: dict[str, Any], thread_id: str, turn_id: str | None
) -> bool:
    if message.get("method") != "turn/completed":
        return False
    params = message.get("params") or {}
    if params.get("threadId") != thread_id:
        return False
    return isinstance(turn_id, str) and bool(turn_id) and (params.get("turn") or {}).get("id") == turn_id


def extract_final_text(events: list[dict[str, Any]], completion: dict[str, Any]) -> str | None:
    candidates: list[str] = []
    params = completion.get("params") or {}
    thread_id, turn_id = params.get("threadId"), (params.get("turn") or {}).get("id")
    for event in events:
        if event.get("method") != "item/completed":
            continue
        fields = event.get("params") or {}
        if not thread_id or not turn_id or fields.get("threadId") != thread_id or fields.get("turnId") != turn_id:
            continue
        item = fields.get("item") or {}
        if item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
            candidates.append(item["text"])
    turn = (completion.get("params") or {}).get("turn") or {}
    for item in turn.get("items") or []:
        if item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
            candidates.append(item["text"])
    return candidates[-1] if candidates else None


def event_methods(events: list[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(event.get("method", "jsonrpc/response")) for event in events))


@dataclass(frozen=True)
class TerminalTurn:
    thread_id: str
    turn_id: str | None
    status: str
    error: Any
    final_text: str | None
    event_methods: tuple[str, ...]


def terminal_turn(
    *, thread_id: str, turn_id: str | None, events: list[dict[str, Any]], completion: dict[str, Any]
) -> TerminalTurn:
    turn = (completion.get("params") or {}).get("turn") or {}
    actual_turn_id = turn.get("id")
    if not is_matching_completion(completion, thread_id, turn_id):
        raise LoomModeError(
            ErrorCategory.TRANSPORT_ERROR,
            "turn completion correlation failed",
            details={"expected_turn_id": turn_id, "actual_turn_id": actual_turn_id},
        )
    return TerminalTurn(
        thread_id=thread_id,
        turn_id=actual_turn_id,
        status=str(turn.get("status") or "unknown"),
        error=turn.get("error"),
        final_text=extract_final_text(events, completion),
        event_methods=event_methods(events),
    )
