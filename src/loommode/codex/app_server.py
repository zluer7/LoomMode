"""Thin stdio JSON-RPC client for a pinned Codex app-server process."""

from __future__ import annotations

import json
import io
import math
import os
import queue
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Sequence

from loommode.version import __version__
from .errors import ErrorCategory, LoomModeError, error_record
from loommode.tools.process_stop import stop_owned_process
from loommode.tools.owned_job import OwnedJob
from loommode.tools.test_runner import test_execution_control
from .protocol import (
    is_matching_completion,
    is_server_request,
    rpc_error,
    rpc_notification,
    rpc_request,
    rpc_result,
    terminal_turn,
    TerminalTurn,
)


DynamicToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class BinaryInfo:
    path: str
    version: str
    version_output: str
    tested: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "version": self.version,
            "version_output": self.version_output,
            "tested": self.tested,
        }


@dataclass(frozen=True)
class BinaryPolicy:
    executable: Path
    supported_versions: tuple[str, ...]
    tested_versions: tuple[str, ...] = ("0.159.2", "0.160.0")
    version_timeout_seconds: float = 10.0

    def inspect(self) -> BinaryInfo:
        try:
            executable = self.executable.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "configured Codex binary does not exist") from exc
        if not executable.is_file():
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "configured Codex binary is not a file")
        try:
            process = subprocess.run(
                [str(executable), "--version"],
                cwd=str(executable.parent),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.version_timeout_seconds,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "unable to inspect Codex version") from exc
        output = (process.stdout or process.stderr).strip()
        match = re.search(r"\b(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\b", output)
        if process.returncode != 0 or not match:
            raise LoomModeError(
                ErrorCategory.CONFIG_ERROR,
                "Codex version output is not recognized",
                details={"exit_code": process.returncode},
            )
        version = match.group(1)
        if version not in self.supported_versions:
            raise LoomModeError(
                ErrorCategory.CONFIG_ERROR,
                "Codex version is outside the configured support policy",
                details={"version": version, "supported_versions": list(self.supported_versions)},
            )
        return BinaryInfo(
            path=str(executable),
            version=version,
            version_output=output,
            tested=version in self.tested_versions,
        )


@dataclass(frozen=True)
class RawTurnResult:
    terminal: TerminalTurn
    elapsed_ms: int
    events: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class FailureLimits:
    write_seconds: float = 2.0
    diagnosis_seconds: float = 2.0
    interrupt_seconds: float = 2.0
    termination_seconds: float = 2.0
    io_join_seconds: float = 2.0
    frame_bytes: int = 1024 * 1024

    def __post_init__(self):
        for name, value in asdict(self).items():
            if name == "frame_bytes":
                if type(value) is not int or not 1024 <= value <= 16 * 1024 * 1024:
                    raise ValueError("frame byte limit outside 1KiB..16MiB")
            elif not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 30:
                raise ValueError("failure operation limit outside 0..30 seconds")


@dataclass
class _ActiveTurn:
    generation: int
    thread_id: str
    started: float
    deadline: float
    event_start: int
    cancel: threading.Event = field(default_factory=threading.Event)
    turn_id: str | None = None
    request_id: int | None = None
    start_sent: bool = False
    recovering: bool = False
    last_activity: float | None = None
    sequence: int = 0
    trace: list[dict[str, Any]] = field(default_factory=list)
    wait_phase: str = 'ADMISSION'


def _safe_turn_error_summary(params: dict[str, Any]) -> dict[str, Any]:
    """Only fixed 0.160.1 error fields; never preserve peer-supplied prose."""
    error = params.get("error")
    error = error if isinstance(error, dict) else {}
    info = error.get("codexErrorInfo")
    string_categories = {
        "contextWindowExceeded", "sessionBudgetExceeded", "usageLimitExceeded",
        "rateLimitExceeded", "flexUnavailable", "serverOverloaded", "cyberPolicy",
        "misalignmentPolicyViolation", "tooManyDenials", "internalServerError",
        "unauthorized", "badRequest", "threadRollbackFailed", "sandboxError", "other",
    }
    status_categories = {
        "httpConnectionFailed", "responseStreamConnectionFailed",
        "responseStreamDisconnected", "responseTooManyFailedAttempts",
    }
    object_categories = status_categories | {"activeTurnNotSteerable"}
    detail = None
    if isinstance(info, str) and info in string_categories:
        category = info
    elif isinstance(info, dict) and len(info) == 1:
        category, detail = next(iter(info.items()))
        if category not in object_categories or not isinstance(detail, dict):
            category, detail = "UNKNOWN", None
    else:
        category = "UNKNOWN"
    retry = params.get("willRetry")
    status = detail.get("httpStatusCode") if category in status_categories and detail else None
    return {"category": category,
            "will_retry": retry if type(retry) is bool else None,
            "http_status": status if type(status) is int and 100 <= status <= 599 else None}


class AppServerClient:
    def __init__(self, command: Sequence[str], cwd: Path, *, binary_info: BinaryInfo | None = None,
                 environment: dict[str, str] | None = None, failure_limits: FailureLimits | None = None,
                 protocol_operations: tuple[str, ...] | None = None) -> None:
        if not command:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "app-server command is empty")
        self.command = tuple(command)
        self.cwd = cwd.resolve(strict=True)
        self.binary_info = binary_info
        self.environment = dict(environment) if environment is not None else None
        self._launch_app_tools_bridge_present: bool | None = None
        self.failure_limits = failure_limits or FailureLimits()
        # Verified locally from pinned 0.160.1 JSON schema. Other native versions
        # stay UNKNOWN; fixture peers may explicitly supply their tested methods.
        self.protocol_operations = (tuple(protocol_operations) if protocol_operations is not None else
                                    ("thread/read", "turn/interrupt") if binary_info and binary_info.version == "0.160.1" else ())
        self.process: subprocess.Popen[str] | None = None
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=4096)
        self.events: list[dict[str, Any]] = []
        self.stderr_lines: list[str] = []
        self.dynamic_tool_handler: DynamicToolHandler | None = None
        self._next_id = 1
        self._write_lock = threading.Lock()
        self._request_lock = threading.RLock()
        self._started = False
        self._initialized = False
        self._reader_threads: list[threading.Thread] = []
        self._writer_threads: list[threading.Thread] = []
        self._callback_threads: list[threading.Thread] = []
        self._callback_resource_unknown = False
        self._callback_resource_receipts: list[dict[str, Any]] = []
        self.stop_guard: Callable[[], bool] = lambda: False
        self._state_lock = threading.Lock()
        self._turn_state: _ActiveTurn | None = None
        self._generation = 0
        self._job: OwnedJob | None = None
        self.last_turn_diagnostics: dict[str, Any] | None = None
        self._stderr_warnings: set[str] = set()
        self._stderr_count = 0
        self.last_timeout_stop: dict[str, Any] | None = None
        self._closed = False
        self._active_turn = False
        self._transport_failure: str | None = None
        self.close_receipt: dict[str, Any] | None = None
        self.event_limit = 256
        self.turn_event_limit = 20000

    @classmethod
    def from_binary_policy(cls, policy: BinaryPolicy, cwd: Path) -> "AppServerClient":
        info = policy.inspect()
        return cls((info.path, "app-server", "--stdio"), cwd, binary_info=info)

    @property
    def launch_app_tools_bridge_present(self) -> bool | None:
        """Actual launch fact only; never expose the desktop pipe value/path."""
        return self._launch_app_tools_bridge_present

    def start(self) -> None:
        if self._closed:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "closed app-server cannot reconnect")
        if self._started:
            return
        try:
            launch_environment = dict(self.environment) if self.environment is not None else dict(os.environ)
            self._launch_app_tools_bridge_present = any(
                key.upper() == 'CODEX_APP_TOOLS_PIPE_PATH' and bool(value)
                for key, value in launch_environment.items())
            if os.name == "nt":
                self._job = OwnedJob()
                self.process = self._job.launch(list(self.command), cwd=self.cwd,
                                               env=launch_environment)
            else:
                # Compatibility only: no claim of POSIX descendant containment.
                self.process = subprocess.Popen(list(self.command), cwd=str(self.cwd), env=launch_environment,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, shell=False)
        except OSError as exc:
            if self._job is not None:
                self.process = self._job.process
                self._cleanup_process()
            raise LoomModeError(ErrorCategory.PROCESS_ERROR, "failed to start Codex app-server") from exc
        self._started = True
        self._reader_threads = [
            threading.Thread(target=self._read_stdout, name="loommode-app-server-stdout", daemon=True),
            threading.Thread(target=self._read_stderr, name="loommode-app-server-stderr", daemon=True),
        ]
        try:
            for thread in self._reader_threads:
                thread.start()
        except BaseException:
            self._cleanup_process()
            raise

    def initialize(self, timeout: float = 30.0) -> dict[str, Any]:
        if not self._started:
            self.start()
        result = self.request(
            "initialize",
            {
                "clientInfo": {"name": "loommode", "version": __version__},
                "capabilities": {"experimentalApi": True},
            },
            timeout=timeout,
        )
        self.notify("initialized", {})
        self._initialized = True
        return result

    def close(self, timeout: float = 5.0) -> None:
        if self._active_turn:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "cannot close app-server during a turn")
        self._closed = True
        self._initialized = False
        self._cleanup_process(graceful=True)
        if not self.close_receipt or not self.close_receipt.get("released"):
            raise LoomModeError(ErrorCategory.PROCESS_ERROR, "owned app-server cleanup is unproved",
                                details={"cleanup": self.close_receipt})

    def _stop_process(self) -> dict[str, Any]:
        if self._job is not None:
            return self._job.stop(wait_seconds=self.failure_limits.termination_seconds / 2)
        if self.process is None:
            return {"root_terminated": True, "tree_terminated_confirmed": True, "unknown_side_effect": False,
                    "ownership": "NEVER_STARTED"}
        return {**stop_owned_process(self.process, wait_seconds=self.failure_limits.termination_seconds / 2),
                "ownership": "POSIX_ROOT_ONLY_UNVERIFIED_DESCENDANTS"}

    def _cleanup_process(self, *, graceful: bool = False) -> None:
        process = self.process
        if process is None:
            termination = self._stop_process()
            self.close_receipt = {"released": not termination.get("unknown_side_effect", True),
                                  "process": "NEVER_STARTED", "readers_alive": 0, "writers_alive": 0,
                                  "termination": termination}
            return
        if self.close_receipt and self.close_receipt.get("released"):
            return
        natural = {"attempted": False, "exit_code": None}
        if (graceful and not self._active_turn and not any(t.is_alive() for t in self._writer_threads)
                and type(process.stdin) is io.FileIO and not process.stdin.closed):
            # Raw unbuffered FileIO has no Python flush lock or buffered bytes.
            # An idle peer gets a bounded EOF opportunity before Job cleanup.
            natural["attempted"] = True
            process.stdin.close()
            try:
                process.wait(timeout=self.failure_limits.termination_seconds / 2)
            except subprocess.TimeoutExpired:
                natural["timed_out"] = True
            natural["exit_code"] = process.poll()
        # Stop the owned tree before touching a pipe that a blocked writer or
        # descendant may hold. No synchronous buffered stdin.close/flush here.
        try:
            termination = self._stop_process()
        except BaseException as exc:
            termination = {"root_terminated": process.poll() is not None, "tree_terminated_confirmed": False,
                           "unknown_side_effect": True, "error": type(exc).__name__}
        deadline = time.monotonic() + self.failure_limits.io_join_seconds
        for thread in (*self._reader_threads, *self._writer_threads, *self._callback_threads):
            if thread.ident is not None:
                thread.join(timeout=max(0, deadline - time.monotonic()))
        readers = sum(thread.is_alive() for thread in self._reader_threads)
        writers = sum(thread.is_alive() for thread in self._writer_threads)
        callbacks = sum(thread.is_alive() for thread in self._callback_threads)
        errors = []
        handle_closed = None
        if not readers and not writers:
            for stream in (process.stdout, process.stderr, process.stdin):
                try:
                    if stream and not stream.closed:
                        stream.close()
                except OSError as exc:
                    errors.append(type(exc).__name__)
            handle = getattr(process, "_handle", None)
            if handle is not None and process.poll() is not None:
                try:
                    handle.Close()
                    handle_closed = bool(handle.closed)
                except OSError as exc:
                    errors.append(type(exc).__name__)
        pipes = [bool(p is None or p.closed) for p in (process.stdin, process.stdout, process.stderr)]
        released = (not termination.get("unknown_side_effect", True) and not readers and not writers and not callbacks
                    and not self._callback_resource_unknown
                    and all(pipes) and not errors and (os.name != "nt" or handle_closed is True))
        self.close_receipt = {"released": released, "pid": process.pid, "exit_code": process.poll(),
            "readers_alive": readers, "writers_alive": writers, "pipes_closed": pipes,
            "callbacks_alive": callbacks,
            "callback_resource_unknown": self._callback_resource_unknown,
            "callback_resources": list(self._callback_resource_receipts),
            "process_handle_closed": handle_closed, "termination": termination, "errors": errors,
            "graceful_eof": natural,
            "process_handle_scope": "OWNED_POPEN" if os.name == "nt" else "NOT_APPLICABLE"}
        self._started = False
        self._initialized = False
        if not released:
            self._transport_failure = "owned process/tree/IO cleanup is unproved"

    def cancel_active(self, generation: int | None = None) -> bool:
        """Signal only this live generation; never wait for RPC/lifecycle locks."""
        with self._state_lock:
            state = self._turn_state
            if state is None or (generation is not None and generation != state.generation):
                return False
            state.cancel.set()
            return True

    def replacement(self) -> "AppServerClient":
        client = AppServerClient(self.command, self.cwd, binary_info=self.binary_info,
            environment=self.environment, failure_limits=self.failure_limits, protocol_operations=self.protocol_operations)
        client.stop_guard = self.stop_guard
        return client

    def assert_usable(self) -> None:
        if self._closed or self._transport_failure:
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR,
                                self._transport_failure or "app-server is finally closed")
        if self.last_timeout_stop is not None:
            raise LoomModeError(ErrorCategory.TOOL_TIMEOUT, "app-server stopped after host test timeout",
                                details=self.last_timeout_stop)

    def _enqueue(self, message: dict[str, Any]) -> bool:
        try:
            self.messages.put_nowait(message)
            return True
        except queue.Full:
            # Never continue after loss of a possible RPC/tool/completion event.
            self._transport_failure = "app-server notification queue overflow; evidence is uncertain"
            return False

    def _event(self, message: dict[str, Any]) -> None:
        if self._active_turn and len(self.events) >= self.turn_event_limit:
            self._transport_failure = "current-turn event limit exceeded; evidence is uncertain"
            self.assert_usable()
        self.events.append(message)
        state = self._turn_state
        if state is not None:
            state.last_activity = time.monotonic()
            state.sequence += 1
            params = message.get("params") or {}
            if not isinstance(params, dict):
                params = {}
            turn = params.get("turn") or {}
            if not isinstance(turn, dict):
                turn = {}
            def identifier(value):
                return value if type(value) is int else value[:128] if isinstance(value, str) else None
            method = message.get("method", "jsonrpc/response")
            trace = {"sequence": state.sequence,
                "elapsed_ms": round((state.last_activity - state.started) * 1000),
                "method": method if isinstance(method, str) and re.fullmatch(r"[A-Za-z0-9_/.-]{1,128}", method) else "UNKNOWN_METHOD",
                "request_id": identifier(message.get("id")), "thread_id": identifier(params.get("threadId")),
                "turn_id": identifier(params.get("turnId", turn.get("id"))),
                "status": turn.get("status") if isinstance(turn.get("status"), str) and turn.get("status") in {"completed", "interrupted", "failed", "inProgress"} else None}
            if (method == "error" and state.turn_id is not None
                    and params.get("threadId") == state.thread_id
                    and params.get("turnId") == state.turn_id):
                trace["error_summary"] = _safe_turn_error_summary(params)
            state.trace.append(trace)
        if not self._active_turn:
            del self.events[:-self.event_limit]

    def __enter__(self) -> "AppServerClient":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _read_stdout(self) -> None:
        assert self.process and self.process.stdout
        try:
            while True:
                line = self.process.stdout.readline(self.failure_limits.frame_bytes + 1)
                if not line:
                    return
                if len(line) > self.failure_limits.frame_bytes or not line.endswith(b"\n"):
                    self._transport_failure = "oversized/incomplete app-server frame"
                    self._enqueue({"_transport_error": "oversized/incomplete app-server frame"})
                    return
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    message = json.loads(stripped)
                except (json.JSONDecodeError, UnicodeError):
                    self._enqueue({"_transport_error": "non-JSON app-server stdout"})
                    continue
                if not isinstance(message, dict):
                    self._enqueue({"_transport_error": "non-object app-server message"})
                    continue
                if not self._enqueue(message):
                    return
        except OSError:
            self._enqueue({"_transport_error": "app-server stdout read failed"})
        finally:
            self._enqueue({"_transport_eof": True})

    def _read_stderr(self) -> None:
        assert self.process and self.process.stderr
        try:
            while True:
                line = self.process.stderr.readline(4096)
                if not line:
                    return
                self._stderr_count += 1
                # Keep fixed classifications only, never raw possibly sensitive stderr.
                text = line.decode("utf-8", errors="replace").lower()
                for marker, label in (("request timed out", "REQUEST_TIMEOUT_SEEN"),
                                      ("falling back to http", "HTTP_FALLBACK_SEEN"),
                                      ("shell snapshot", "SHELL_SNAPSHOT_WARNING_SEEN")):
                    if marker in text:
                        self._stderr_warnings.add(label)
        except OSError:
            self._stderr_warnings.add("STDERR_READ_FAILED")

    @contextmanager
    def _locked(self, lock, deadline):
        while not lock.acquire(timeout=max(0, min(.05, deadline - time.monotonic()))):
            self._check_wait(deadline, "operation lock")
        try:
            self._check_wait(deadline, "operation lock")
            yield
        finally:
            lock.release()

    def _check_wait(self, deadline, description):
        state = self._turn_state
        if (state is None or not state.recovering) and self.stop_guard():
            raise LoomModeError(ErrorCategory.TURN_INTERRUPTED, "Host stop fence prevents invocation admission/continuation")
        if state is not None and not state.recovering and state.cancel.is_set():
            raise LoomModeError(ErrorCategory.TURN_INTERRUPTED, "Owner stop requested for active generation")
        if time.monotonic() >= deadline:
            raise LoomModeError(ErrorCategory.DEADLINE_EXCEEDED, "timed out waiting for " + description)

    def _send(self, payload: dict[str, Any], *, deadline: float | None = None) -> None:
        self.assert_usable()
        if self.last_timeout_stop is not None:
            raise LoomModeError(ErrorCategory.TOOL_TIMEOUT, "app-server stopped after host test timeout",
                                details=self.last_timeout_stop)
        process = self.process
        if process is None or process.stdin is None or process.poll() is not None:
            raise LoomModeError(ErrorCategory.PROCESS_ERROR, "app-server process is not running")
        deadline = min(deadline if deadline is not None else float("inf"),
                       time.monotonic() + self.failure_limits.write_seconds)
        encoded = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > self.failure_limits.frame_bytes:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "outgoing app-server frame exceeds bound")
        done, errors = threading.Event(), []
        def write():
            try:
                remaining = memoryview(encoded)
                while remaining:
                    count = process.stdin.write(remaining)
                    if not count:
                        raise BrokenPipeError("stdin write made no progress")
                    remaining = remaining[count:]
                process.stdin.flush()
            except BaseException as exc:
                errors.append(type(exc).__name__)
            finally:
                done.set()
        with self._locked(self._write_lock, deadline):
            if any(thread.is_alive() for thread in self._writer_threads):
                raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "previous app-server writer is unjoined")
            self._writer_threads.clear()
            thread = threading.Thread(target=write, name="loommode-app-server-stdin", daemon=True)
            self._writer_threads.append(thread)
            self._check_wait(deadline, "app-server writer admission")
            state = self._turn_state
            if state is not None and payload.get("method") == "turn/start" and payload.get("id") == state.request_id:
                state.start_sent = True  # Bytes may leave only after local validation.
            thread.start()
            while not done.wait(timeout=max(0, min(.05, deadline - time.monotonic()))):
                self._check_wait(deadline, "app-server stdin write/flush")
            thread.join(timeout=max(0, deadline - time.monotonic()))
            if thread.is_alive():
                raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "app-server writer join unproved")
            self._check_wait(deadline, "app-server stdin write/flush")
            if errors:
                raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "app-server stdin failed", details={"exception_type": errors[0]})

    def notify(self, method: str, params: dict[str, Any]) -> None:
        deadline = time.monotonic() + self.failure_limits.write_seconds
        with self._locked(self._request_lock, deadline):
            self._send(rpc_notification(method, params), deadline=deadline)

    def request(self, method: str, params: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise LoomModeError(ErrorCategory.DEADLINE_EXCEEDED, "RPC deadline exhausted/invalid")
        deadline = time.monotonic() + timeout
        with self._locked(self._request_lock, deadline):
            request_id = self._next_id
            self._next_id += 1
            state = self._turn_state
            if method == "turn/start" and state is not None:
                state.request_id = request_id
            self._send(rpc_request(request_id, method, params), deadline=deadline)
            while True:
                message = self._receive(deadline, f"response to {method}")
                self._event(message)
                if self._handle_server_request(message, deadline=deadline):
                    continue
                if message.get("id") == request_id:
                    if "error" in message:
                        error = message.get("error") or {}
                        text = str(error.get("message") or f"RPC {method} failed")
                        category = self._rpc_category(method, text)
                        raise LoomModeError(
                            category,
                            f"RPC {method} failed",
                            details={"method": method, "code": error.get("code")},
                        )
                    result = message.get("result")
                    return result if isinstance(result, dict) else {}

    def run_turn(
        self, **kwargs: Any,
    ) -> RawTurnResult:
        started = time.monotonic()
        duration = kwargs["deadline_seconds"]
        if not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "finite positive turn deadline required")
        deadline = started + duration
        with self._locked(self._request_lock, deadline):
            self.assert_usable()
            if self._active_turn:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "another app-server turn is active")
            with self._state_lock:
                self._generation += 1
                self._turn_state = _ActiveTurn(self._generation, kwargs["thread_id"], started, deadline, len(self.events))
                self._active_turn = True
            self.last_turn_diagnostics = None
            try:
                return self._run_turn(**kwargs)
            except LoomModeError as exc:
                if exc.record.category in {ErrorCategory.DEADLINE_EXCEEDED, ErrorCategory.PROCESS_ERROR,
                        ErrorCategory.TRANSPORT_ERROR, ErrorCategory.TURN_INTERRUPTED, ErrorCategory.TOOL_TIMEOUT} or self._turn_state.start_sent:
                    self._recover_failed_turn(exc)
                    self._transport_failure = "turn completion/effect is uncertain; no automatic replay"
                    raise LoomModeError(exc.record.category, "Codex turn failed; bounded diagnosis retained",
                                        details={"turn": self.last_turn_diagnostics}) from exc
                raise
            except BaseException as exc:
                # Malformed peer frames/local callback serialization must not
                # abandon an invocation which may already have side effects.
                failure = LoomModeError(ErrorCategory.TURN_INTERRUPTED if isinstance(exc, KeyboardInterrupt)
                                        else ErrorCategory.TRANSPORT_ERROR, "active invocation failed locally")
                self._recover_failed_turn(failure)
                self._transport_failure = "turn completion/effect is uncertain; no automatic replay"
                raise LoomModeError(failure.record.category, "Codex turn failed; bounded diagnosis retained",
                                    details={"turn": self.last_turn_diagnostics}) from exc
            finally:
                with self._state_lock:
                    self._active_turn = False
                    self._turn_state = None
                # RawTurnResult has already captured its immutable event tuple.
                del self.events[:-self.event_limit]

    def _run_turn(
        self,
        *,
        thread_id: str,
        prompt: str,
        model: str,
        effort: str,
        output_schema: dict[str, Any],
        deadline_seconds: float,
        sandbox_policy: dict[str, Any] | None = None,
        environments: list[dict[str, Any]] | None = None,
    ) -> RawTurnResult:
        state = self._turn_state
        assert state is not None
        started, event_start = state.started, state.event_start
        state.wait_phase = 'TURN_START_RESPONSE'
        response = self.request(
            "turn/start",
            {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
                "model": model,
                "effort": effort,
                "outputSchema": output_schema,
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "sandboxPolicy": sandbox_policy or {"type": "readOnly", "networkAccess": False},
                "environments": environments if environments is not None else [],
                "turnTrigger": "loommode-thin-adapter",
            },
            timeout=min(90.0, max(0, state.deadline - time.monotonic())),
        )
        turn_id = (response.get("turn") or {}).get("id")
        if not isinstance(turn_id, str) or not turn_id:
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "turn/start returned no reliable turn identity")
        state.turn_id = turn_id
        state.wait_phase = 'MATCHING_TERMINAL'
        completion = self._wait_for_turn(
            thread_id=thread_id,
            turn_id=turn_id,
            event_start=event_start,
            deadline=state.deadline,
        )
        relevant = list(self.events[event_start:])
        terminal = terminal_turn(
            thread_id=thread_id,
            turn_id=turn_id,
            events=relevant,
            completion=completion,
        )
        state.wait_phase = 'PUBLICATION'
        self._check_wait(state.deadline, "turn result publication")
        return RawTurnResult(
            terminal=terminal,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            events=tuple(relevant),
        )

    def _wait_for_turn(
        self,
        *,
        thread_id: str,
        turn_id: str | None,
        event_start: int,
        deadline: float,
    ) -> dict[str, Any]:
        index = event_start
        while True:
            self._check_wait(deadline, "matching terminal")
            while index < len(self.events):
                event = self.events[index]
                index += 1
                if is_matching_completion(event, thread_id, turn_id):
                    return event
            message = self._receive(deadline, f"terminal event for turn {turn_id}")
            self._event(message)
            if self._handle_server_request(message, deadline=deadline):
                continue

    def _recover_failed_turn(self, error: LoomModeError) -> None:
        state = self._turn_state
        assert state is not None
        state.recovering = True
        state.cancel.set()  # Cooperatively stop any in-flight host test callback.
        evidence = {"generation": state.generation, "thread_id": state.thread_id, "turn_id": state.turn_id,
            "turn_start_request_id": state.request_id, "turn_start_sent_or_uncertain": state.start_sent,
            "category": error.record.category.value, "effect": "UNKNOWN_EFFECT", "automatic_replay": False,
            "last_activity_elapsed_ms": round((state.last_activity - state.started) * 1000) if state.last_activity else None,
            "received_sequence_count": state.sequence, "state_query": "NOT_SUPPORTED_OR_UNAVAILABLE",
            "interrupt": "NOT_SENT", "terminal_evidence": None, "protocol_errors": []}
        # Fixed scalar diagnostics only. Capture before bounded diagnosis/cleanup
        # so a later close duration cannot be mistaken for the model deadline.
        evidence['transport_timing'] = {
            'wait_phase': state.wait_phase,
            'deadline_seconds': state.deadline - state.started,
            'elapsed_before_diagnosis_ms': max(0, round((time.monotonic() - state.started) * 1000)),
            'turn_start_sent_or_uncertain': state.start_sent,
            'turn_start_acknowledged': state.turn_id is not None}
        def terminal_evidence():
            for event in reversed(self.events[state.event_start:]):
                if is_matching_completion(event, state.thread_id, state.turn_id):
                    return {"source": "turn/completed", "status": (event.get("params") or {}).get("turn", {}).get("status")}
            return None
        try:
            evidence["terminal_evidence"] = terminal_evidence()
            available = (self.process is not None and self.process.poll() is None and not self._transport_failure
                         and not self.last_timeout_stop and not any(t.is_alive() for t in self._writer_threads))
            if available and evidence["terminal_evidence"] is None and "thread/read" in self.protocol_operations:
                try:
                    result = self.request("thread/read", {"threadId": state.thread_id, "includeTurns": True},
                                          timeout=self.failure_limits.diagnosis_seconds)
                    thread = result.get("thread") or {}
                    if thread.get("id") != state.thread_id:
                        raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "diagnostic thread identity mismatch")
                    evidence["state_query"] = "MATCHING_THREAD"
                    matches = [turn for turn in thread.get("turns", []) if isinstance(turn, dict)
                               and state.turn_id is not None and turn.get("id") == state.turn_id]
                    if len(matches) == 1 and matches[0].get("status") in {"completed", "interrupted", "failed", "inProgress"}:
                        evidence["reported_turn_status"] = matches[0]["status"]
                        if matches[0]["status"] != "inProgress":
                            evidence["terminal_evidence"] = {"source": "thread/read", "status": matches[0]["status"]}
                except LoomModeError as exc:
                    evidence["protocol_errors"].append({"operation": "thread/read", "category": exc.record.category.value})
                evidence["terminal_evidence"] = terminal_evidence() or evidence["terminal_evidence"]
            if (available and state.turn_id is not None and evidence["terminal_evidence"] is None
                    and "turn/interrupt" in self.protocol_operations):
                deadline = time.monotonic() + self.failure_limits.interrupt_seconds
                try:
                    self.request("turn/interrupt", {"threadId": state.thread_id, "turnId": state.turn_id},
                                 timeout=max(0, deadline - time.monotonic()))
                    evidence["interrupt"] = "ACKNOWLEDGED_NOT_TERMINAL"
                    self._wait_for_turn(thread_id=state.thread_id, turn_id=state.turn_id,
                                        event_start=state.event_start, deadline=deadline)
                except LoomModeError as exc:
                    evidence["protocol_errors"].append({"operation": "turn/interrupt", "category": exc.record.category.value})
                evidence["terminal_evidence"] = terminal_evidence() or evidence["terminal_evidence"]
        except BaseException as exc:
            evidence["protocol_errors"].append({"operation": "diagnosis", "exception_type": type(exc).__name__})
        finally:
            # Even a late completed event cannot turn this faulted call into PASS.
            evidence["event_methods"] = list(dict.fromkeys(str(e.get("method", "jsonrpc/response"))
                                             for e in self.events[state.event_start:]))[:128]
            evidence["received_sequence_count"] = state.sequence
            evidence["event_trace"] = list(state.trace)
            evidence["last_activity_elapsed_ms"] = round((state.last_activity - state.started) * 1000) if state.last_activity else None
            self._cleanup_process()
            evidence["cleanup"] = self.close_receipt
            self.last_turn_diagnostics = evidence

    def _receive(self, deadline: float, description: str) -> dict[str, Any]:
        while True:
            self.assert_usable()
            self._check_wait(deadline, description)
            try:
                message = self.messages.get(timeout=max(0, min(.05, deadline - time.monotonic())))
                break
            except queue.Empty:
                continue
        if message.get("_transport_error"):
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, str(message["_transport_error"]))
        if message.get("_transport_eof"):
            code = self.process.poll() if self.process else None
            raise LoomModeError(
                ErrorCategory.PROCESS_ERROR,
                "app-server stdout closed unexpectedly",
                details={"exit_code": code},
            )
        return message

    def loaded_threads(self, timeout: float = 15.0) -> set[str]:
        result: set[str] = set()
        cursor: str | None = None
        for _ in range(16):
            page = self.request("thread/loaded/list", {"limit": 100, "cursor": cursor}, timeout=timeout)
            values = page.get("data")
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "invalid loaded-thread membership proof")
            result.update(values)
            next_cursor = page.get("nextCursor")
            if next_cursor is None:
                return result
            if not isinstance(next_cursor, str) or next_cursor == cursor:
                break
            cursor = next_cursor
        raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "loaded-thread proof exceeded bounded pagination")

    def release_thread(self, thread_id: str, timeout: float = 15.0) -> dict[str, Any]:
        if self._active_turn:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "cannot release thread during a turn")
        with self._request_lock:
            before = thread_id in self.loaded_threads(timeout)
            response = self.request("thread/unsubscribe", {"threadId": thread_id}, timeout=timeout)
            status = response.get("status")
            after = thread_id in self.loaded_threads(timeout)
            closed = any(e.get("method") == "thread/closed" and
                         (e.get("params") or {}).get("threadId") == thread_id for e in self.events)
            if status not in {"unsubscribed", "notLoaded"} or status == "notLoaded" and after:
                raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "owned thread resident release is unproved",
                                    details={"status": status, "loaded_before": before, "loaded_after": after})
            return {"proof": "SUBSCRIPTION_REMOVED_RESIDENT_RETAINED" if after else
                    "OWNED_THREAD_RESIDENT_MEMBERSHIP", "released": not after, "thread_id": thread_id,
                    "unsubscribe_status": status, "loaded_before": before, "loaded_after": after,
                    "new_unload": before and not after and status == "unsubscribed",
                    "thread_closed_notification": "OBSERVED" if closed else "NOT_OBSERVED",
                    "durable_thread_history": "UNCHANGED"}

    def _handle_server_request(self, message: dict[str, Any], *, deadline: float | None = None) -> bool:
        if not is_server_request(message):
            return False
        request_id = message["id"]
        method = message.get("method")
        state = self._turn_state
        params = message.get("params") or {}
        foreign = (state is None or not isinstance(params, dict) or params.get("threadId") != state.thread_id
                   or state.turn_id is None or params.get("turnId") != state.turn_id)
        if method != "item/tool/call" or self.dynamic_tool_handler is None or foreign or (state and state.recovering):
            self._send(rpc_error(request_id, -32601, "LoomMode host does not admit this callback"), deadline=deadline)
            return True
        # Only this RPC consumer receives/routes messages. The owned callback
        # worker performs host work, never consumes the app-server queue.
        outcome: list[Any] = []
        handler = self.dynamic_tool_handler
        def invoke():
            try:
                with test_execution_control(state.deadline, state.cancel):
                    if state.cancel.is_set() or self._turn_state is not state:
                        raise LoomModeError(ErrorCategory.TURN_INTERRUPTED, "callback generation is no longer admitted")
                    self._check_wait(state.deadline, "host callback admission")
                    result = handler(params)
                    outcome.append(result)
                    if isinstance(result, dict) and isinstance(result.get("output"), dict):
                        output = result["output"]
                        error = output.get("error")
                        details = error.get("details") if isinstance(error, dict) else None
                        termination = details.get("termination") if isinstance(details, dict) else output.get("termination")
                        if isinstance(termination, dict):
                            self._callback_resource_receipts.append({key: termination.get(key) for key in
                                ("pid", "root_terminated", "tree_terminated_confirmed", "unknown_side_effect",
                                 "output_drained", "pipes_closed", "process_handle_closed", "job_handle_closed", "cleanup_errors")})
                            del self._callback_resource_receipts[:-64]
                            if termination.get("unknown_side_effect", True):
                                self._callback_resource_unknown = True
            except BaseException as exc:
                outcome.append(exc)
        worker = threading.Thread(target=invoke, name="loommode-app-server-callback", daemon=True)
        self._callback_threads = [t for t in self._callback_threads if t.is_alive()]
        self._callback_threads.append(worker)
        worker.start()
        while worker.is_alive():
            self._check_wait(min(state.deadline, deadline) if deadline is not None else state.deadline,
                             "host callback completion")
            worker.join(timeout=.02)
        self._check_wait(state.deadline, "host callback result publication")
        try:
            result = outcome[0]
            if isinstance(result, BaseException):
                raise result
            success = bool(result.get("success", False))
            output = result.get("output", {})
        except BaseException as exc:
            success = False
            output = {"error": error_record(exc).as_dict()}
        if isinstance(output, dict) and isinstance(output.get("error"), dict) and output["error"].get("category") == ErrorCategory.TOOL_TIMEOUT.value:
            params = message.get("params") or {}
            termination = (self._stop_process() if self.process else
                           {"root_terminated": False, "tree_terminated_confirmed": False,
                            "unknown_side_effect": True, "attempts": []})
            self.last_timeout_stop = {"thread_id": params.get("threadId"), "turn_id": params.get("turnId"),
                                      "request_id": request_id, "termination": termination,
                                      "timeout_reply_sent": False, "tool_error": output["error"]}
            # Stop the dedicated server and native work BEFORE replying. A normal
            # timeout tool result would permit this model turn to continue.
            raise LoomModeError(ErrorCategory.TOOL_TIMEOUT, "host timeout stopped the current Codex invocation",
                                details=self.last_timeout_stop)
        self._send(
            rpc_result(
                request_id,
                {
                    "contentItems": [
                        {"type": "inputText", "text": json.dumps(output, ensure_ascii=False)}
                    ],
                    "success": success,
                },
            ), deadline=deadline,
        )
        return True

    @staticmethod
    def _rpc_category(method: str, message: str) -> ErrorCategory:
        lowered = message.lower()
        if "auth" in lowered or "login" in lowered or "unauthorized" in lowered:
            return ErrorCategory.AUTH_ERROR
        if "model" in lowered or "reasoning effort" in lowered:
            return ErrorCategory.MODEL_ERROR
        if method == "turn/start":
            return ErrorCategory.TURN_FAILED
        return ErrorCategory.TRANSPORT_ERROR

    def transport_warnings(self) -> tuple[str, ...]:
        lowered = "\n".join(self.stderr_lines).lower()
        warnings: list[str] = []
        if "request timed out" in lowered:
            warnings.append("REQUEST_TIMEOUT_SEEN")
        if "falling back to http" in lowered:
            warnings.append("HTTP_FALLBACK_SEEN")
        if "shell snapshot" in lowered:
            warnings.append("SHELL_SNAPSHOT_WARNING_SEEN")
        return tuple(sorted(set(warnings) | self._stderr_warnings))

    def transport_metadata(self) -> dict[str, Any]:
        return {
            "interface": "codex app-server --stdio",
            "binary": self.binary_info.as_dict() if self.binary_info else None,
            "stderr_line_count": self._stderr_count,
            "warnings": list(self.transport_warnings()),
            "process_exit_code": self.process.poll() if self.process else None,
            "queue_count": self.messages.qsize(), "queue_limit": self.messages.maxsize,
            "event_count": len(self.events), "event_limit": self.event_limit,
            "active_turn": self._active_turn, "transport_failure": self._transport_failure,
            "close_receipt": self.close_receipt,
            "turn_diagnostics": self.last_turn_diagnostics,
            "failure_limits": asdict(self.failure_limits),
            "protocol_operations": list(self.protocol_operations),
            "callbacks_alive": sum(t.is_alive() for t in self._callback_threads),
            "callback_resource_unknown": self._callback_resource_unknown,
        }
