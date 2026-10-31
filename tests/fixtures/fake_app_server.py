#!/usr/bin/env python3
"""Deterministic JSON-RPC peer for Adapter protocol tests."""

from __future__ import annotations

import json
import sys
import time
from uuid import uuid4
from pathlib import Path
from typing import Any


for stream in (sys.stdin, sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")


next_thread = 1
next_turn = 1
loaded_threads: set[str] = set()
unsubscribe_mode = "success"
resume_history_bytes = 0
process_epoch = uuid4().hex


def send(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def result(request: dict[str, Any], value: dict[str, Any]) -> None:
    send({"id": request["id"], "result": value})


def structured(prompt: str) -> str:
    if "\nPURPOSE: OWNER_STATUS_EXPLANATION\n" in prompt:
        value = {"summary": "deterministic status explanation", "evidence_refs": [], "limitations": []}
        if "EXPLANATION_EXTRA_FIELD" in prompt:
            value["action"] = "TASK_ACCEPTED"
        return json.dumps(value)
    if "ROLE_RESULT" in prompt or "\nACTIVITY: " in prompt:
        return json.dumps({"action": "HUMAN_REQUIRED", "explanation": "deterministic role response",
                           "handoff": None, "intent": None, "artifacts": [], "evidence": None,
                           "blocker_id": None, "new_basis": None, "model_override": None, "repair_from_review": False,
                           "sync": [], "experiences": [], "owner_summary": None,
                           'issues': [], 'triage': [], 'knowledge': None, 'completion': None, 'stage_plan': None,
                           'escalation': None, 'mediation': None})
    value: dict[str, Any] = {
        "result": "OK",
        "next_action": "NONE",
        "explanation": "deterministic fake result",
        "artifacts": [],
        "failure": None,
        "human_required": False,
    }
    if "MISSING_FIELD" in prompt:
        value.pop("failure")
    if "EXTRA_FIELD" in prompt:
        value["unexpected"] = True
    if "INVALID_JSON" in prompt:
        return "{not-json"
    return json.dumps(value, separators=(",", ":"))


def tool_call(thread_id: str, turn_id: str, prompt: str) -> None:
    if "USE_TIMEOUT_THEN_NATIVE" in prompt:
        tool = "loommode_run_test"
        arguments = {"test_id": "timeout"}
    elif "USE_READ_TOOL" in prompt:
        tool = "loommode_read_file"
        arguments = {"path": "calc.py"}
    elif "USE_WRITE_TOOL" in prompt:
        tool = "loommode_replace_file"
        arguments = {
            "path": "calc.py",
            "expected": "return left - right",
            "replacement": "return left + right",
        }
    else:
        return
    send(
        {
            "id": 9000 + int(turn_id.rsplit("-", 1)[1]),
            "method": "item/tool/call",
            "params": {
                "threadId": thread_id,
                "turnId": turn_id,
                "callId": f"call-{turn_id}",
                "tool": tool,
                "arguments": arguments,
            },
        }
    )
    callback = sys.stdin.readline()
    if not callback:
        raise SystemExit(0)
    json.loads(callback)
    if "USE_TIMEOUT_THEN_NATIVE" in prompt:
        # Represents native work enabled by replying to the timeout callback.
        Path("calc.py").write_text("native action after timeout\n", encoding="utf-8")


def handle(request: dict[str, Any]) -> None:
    global next_thread, next_turn
    method = request.get("method")
    if "id" not in request:
        return
    if method == "initialize":
        result(
            request,
            {"userAgent": "fake-app-server/1", "platformFamily": "test", "platformOs": "test"},
        )
    elif method == "account/read":
        result(
            request,
            {"requiresOpenaiAuth": True, "account": {"type": "chatgpt", "planType": "test"}},
        )
    elif method == "model/list":
        result(
            request,
            {
                "data": [
                    {
                        "id": "gpt-6.1-sol",
                        "model": "gpt-6.1-sol",
                        "defaultReasoningEffort": "low",
                        "supportedReasoningEfforts": [
                            {"reasoningEffort": "low"},
                            {"reasoningEffort": "medium"},
                        ],
                    }
                ]
            },
        )
    elif method == "thread/start":
        config = request.get("params", {}).get("config", {}).get("features", {})
        if config.get("shell_tool") is not False or config.get("unified_exec") is not False:
            send({"id": request["id"], "error": {"code": -32000, "message": "shell guard missing"}})
            return
        thread_id = f"fake-thread-{process_epoch}-{next_thread}"
        loaded_threads.add(thread_id)
        next_thread += 1
        result(
            request,
            {
                "thread": {"id": thread_id},
                "model": request["params"].get("model"),
                "reasoningEffort": "low",
                "cwd": request["params"].get("cwd"),
            },
        )
    elif method == "fixture/unsubscribe-mode":
        global unsubscribe_mode
        unsubscribe_mode = request["params"]["mode"]
        result(request, {})
    elif method == "thread/loaded/list":
        result(request, {"data": sorted(loaded_threads), "nextCursor": None})
    elif method == "thread/unsubscribe":
        thread_id = request["params"]["threadId"]
        if unsubscribe_mode == "notSubscribed":
            result(request, {"status": "notSubscribed"})
        elif unsubscribe_mode == "fail":
            send({"id": request["id"], "error": {"code": -32000, "message": "fixture unsubscribe failed"}})
        else:
            present = thread_id in loaded_threads
            if unsubscribe_mode != "retain":
                loaded_threads.discard(thread_id)
                send({"method": "thread/closed", "params": {"threadId": thread_id}})
            result(request, {"status": "unsubscribed" if present else "notLoaded"})
    elif method == "fixture/flood":
        for number in range(request["params"]["count"]):
            send({"method": "fixture/late", "params": {"number": number}})
        result(request, {})
    elif method == "fixture/resume-history":
        global resume_history_bytes
        resume_history_bytes = request["params"]["bytes"]
        result(request, {})
    elif method == "thread/resume":
        thread_id = request["params"]["threadId"]
        loaded_threads.add(thread_id)
        thread = {"id": thread_id}
        if resume_history_bytes and not request["params"].get("excludeTurns"):
            thread["turns"] = [{"text": "x" * resume_history_bytes}]
        result(
            request,
            {
                "thread": thread,
                "model": request["params"].get("model"),
                "reasoningEffort": "low",
                "cwd": request["params"].get("cwd"),
            },
        )
    elif method == "turn/start":
        params = request["params"]
        prompt = params["input"][0]["text"]
        if not isinstance(params.get("outputSchema"), dict):
            send({"id": request["id"], "error": {"code": -32000, "message": "schema missing"}})
            return
        turn_id = f"fake-turn-{next_turn}"
        next_turn += 1
        thread_id = params["threadId"]
        result(request, {"turn": {"id": turn_id, "status": "inProgress"}})
        if "EXIT_AFTER_START" in prompt:
            raise SystemExit(7)
        if "NO_COMPLETE" in prompt:
            time.sleep(2)
            return
        tool_call(thread_id, turn_id, prompt)
        if "TERMINAL_FAILED" in prompt:
            status = "failed"
        elif "TERMINAL_INTERRUPTED" in prompt:
            status = "interrupted"
        else:
            status = "completed"
        text = structured(prompt)
        send(
            {
                "method": "item/completed",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "item": {"type": "agentMessage", "text": text},
                },
            }
        )
        send(
            {
                "method": "turn/completed",
                "params": {
                    "threadId": thread_id,
                    "turn": {
                        "id": turn_id,
                        "status": status,
                        "error": {"message": f"fake {status}"} if status != "completed" else None,
                        "items": [{"type": "agentMessage", "text": text}],
                    },
                },
            }
        )
    else:
        send({"id": request["id"], "error": {"code": -32601, "message": "unknown method"}})


for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    handle(message)
