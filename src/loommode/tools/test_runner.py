"""Host-configured test commands; callers select an ID, never an argv."""

from __future__ import annotations

import os
import subprocess
import shutil
import time
import json
import hashlib
from uuid import uuid4
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Event
from dataclasses import dataclass, replace
from pathlib import Path

from loommode.codex.errors import ErrorCategory, LoomModeError
from .filesystem import WorkspaceGuard, normalize_relative
from .process_stop import stop_owned_process
from .owned_job import OwnedJob


_TEST_CONTROL: ContextVar[tuple[float, Event] | None] = ContextVar("loommode_test_control", default=None)
_TEST_ISOLATION: ContextVar[dict | None] = ContextVar('loommode_test_isolation', default=None)


@contextmanager
def test_isolation(plans):
    from .sandbox_test import SandboxTestPlan
    if not plans or any(type(p) is not SandboxTestPlan for p in plans.values()):
        raise RuntimeError('trusted sandbox plans required; no ordinary fallback')
    token = _TEST_ISOLATION.set(dict(plans))
    try:
        yield
    finally:
        _TEST_ISOLATION.reset(token)


@contextmanager
def test_execution_control(deadline: float, cancel: Event):
    """Scope the existing fixed runner to one owned app-server callback worker."""
    token = _TEST_CONTROL.set((deadline, cancel))
    try:
        yield
    finally:
        _TEST_CONTROL.reset(token)


def check_execution_control() -> None:
    control = _TEST_CONTROL.get()
    if control is not None and (control[1].is_set() or time.monotonic() >= control[0]):
        raise LoomModeError(ErrorCategory.TURN_INTERRUPTED, "host callback generation is cancelled/expired")


@dataclass(frozen=True)
class TestSpec:
    test_id: str
    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: float = 60.0
    output_limit: int = 32_000


@dataclass(frozen=True)
class CommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_ms: int
    timed_out: bool
    truncated: bool
    termination: dict[str, object] | None = None
    launch: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "elapsed_ms": self.elapsed_ms,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "passed": self.exit_code == 0 and not self.timed_out,
            "termination": self.termination,
            "launch": self.launch,
        }


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


class FixedTestRunner:
    def __init__(self, workspace: Path, specs: tuple[TestSpec, ...], *, require_isolation=False) -> None:
        self.require_isolation = require_isolation
        self.workspace = workspace.resolve(strict=True)
        self.specs = {spec.test_id: spec for spec in specs}
        if len(self.specs) != len(specs):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "duplicate test id")
        for spec in specs:
            if not spec.argv or spec.timeout_seconds <= 0 or spec.output_limit <= 0:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, f"invalid test spec: {spec.test_id}")

    def preflight(self, test_id: str | None = None) -> None:
        specs = [self.specs[test_id]] if test_id in self.specs else list(self.specs.values()) if test_id is None else []
        if test_id is not None and not specs:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'test id is not authorized')
        for spec in specs:
            cwd = self._cwd(spec)
            executable = spec.argv[0]
            if not isinstance(executable, str) or not executable:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'declared executable is empty')
            if Path(executable).is_absolute() or '/' in executable or '\\' in executable:
                command = Path(executable) if Path(executable).is_absolute() else cwd / executable
                available = command.is_file() and os.access(command, os.X_OK)
            else:
                search = os.environ.get('PATH', '')
                if os.name == 'nt':
                    search = str(cwd) + os.pathsep + search
                available = shutil.which(executable, path=search) is not None
            if not available:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, f'declared executable unavailable: {executable}')

    def _cwd(self, spec: TestSpec) -> Path:
        if spec.cwd == '.':
            return self.workspace
        _, cwd = WorkspaceGuard.target(self.workspace, normalize_relative(spec.cwd), must_exist=True)
        if not cwd.is_dir():
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'test cwd is not a directory')
        return cwd

    def run(self, test_id: str) -> CommandResult:
        spec = self.specs.get(test_id)
        if spec is None:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "test id is not authorized")
        self.preflight(test_id)
        cwd = self._cwd(spec)
        control = _TEST_CONTROL.get()
        plans = _TEST_ISOLATION.get()
        if self.require_isolation or plans is not None:
            if plans is None or test_id not in plans:
                raise RuntimeError('managed test isolation missing; no ordinary fallback')
            plan = plans[test_id]
            plan.validate(spec, cwd)
            # Persist trusted launch facts before any untrusted execution.
            evidence = plan.evidence()
            directory = Path(dict(plan.environment)['TEMP'])
            for parent in (directory, *directory.parents):
                if parent.exists() and (parent.is_symlink() or parent.is_junction()):
                    raise RuntimeError('sandbox temporary path is linked')
            directory.mkdir(parents=True, exist_ok=True)
            # Control record is outside model writable workspace/output.
            # The builder carries the exact working control path in its deny policy.
            control_dir = Path(evidence['control_directory'])
            for parent in (control_dir, *control_dir.parents):
                if parent.exists() and (parent.is_symlink() or parent.is_junction()):
                    raise RuntimeError('sandbox control path is linked')
            control_dir.mkdir(parents=True, exist_ok=True)
            record = control_dir / ('launch-' + uuid4().hex + '.json')
            raw = (json.dumps(evidence, sort_keys=True, default=str) + '\n').encode()
            with record.open('xb') as stream:
                stream.write(raw)
            evidence['record'] = str(record)
            evidence['record_sha256'] = hashlib.sha256(raw).hexdigest()
            selected = replace(spec, argv=plan.argv)
            result = self._run_controlled(selected, cwd, control or
                (time.monotonic() + spec.timeout_seconds, Event()),
                environment=dict(plan.environment), launch=evidence)
            try:
                with record.with_suffix('.result.json').open('x', encoding='utf-8') as stream:
                    json.dump(result.as_dict(), stream, sort_keys=True, default=str)
            except BaseException as exc:
                evidence['evidence_write_error'] = type(exc).__name__
                termination = dict(result.termination or {})
                termination['unknown_side_effect'] = True
                result = replace(result, timed_out=True, termination=termination)
            return result
        if control is not None:
            return self._run_controlled(spec, cwd, control)
        started = time.monotonic()
        process = subprocess.Popen(
                list(spec.argv),
                cwd=str(cwd),
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        try:
            stdout, stderr = process.communicate(timeout=spec.timeout_seconds)
            combined = len(stdout) + len(stderr)
            limit = spec.output_limit
            truncated = combined > limit
            if truncated:
                stdout = stdout[: limit // 2]
                stderr = stderr[: limit - len(stdout)]
            return CommandResult(
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=round((time.monotonic() - started) * 1000),
                timed_out=False,
                truncated=truncated,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = _text(exc.stdout), _text(exc.stderr)
            termination = stop_owned_process(process)
            try:
                stdout, stderr = process.communicate(timeout=1.0)
                termination["output_drained"] = True
            except subprocess.TimeoutExpired:
                termination["output_drained"] = False
                termination["unknown_side_effect"] = True
            # Never close pipes held by a surviving descendant with an unbounded
            # reader join. Failure to drain remains an explicit unknown effect.
            combined = stdout + stderr
            truncated = len(combined) > spec.output_limit
            combined = combined[: spec.output_limit]
            return CommandResult(
                exit_code=None,
                stdout=combined,
                stderr="test command exceeded its host timeout",
                elapsed_ms=round((time.monotonic() - started) * 1000),
                timed_out=True,
                truncated=truncated,
                termination=termination,
            )

    def _run_controlled(self, spec: TestSpec, cwd: Path, control: tuple[float, Event], *, environment=None, launch=None) -> CommandResult:
        """Poll cancellation/remaining Turn budget; own the test's separate tree."""
        started = time.monotonic()
        deadline, cancel = control
        deadline = min(deadline, started + spec.timeout_seconds)
        if cancel.is_set() or started >= deadline:
            return CommandResult(None, "", "test cancelled before launch", 0, True, False,
                {"root_terminated": True, "tree_terminated_confirmed": True,
                 "unknown_side_effect": False, "ownership": "NEVER_STARTED"}, launch)
        job = OwnedJob() if os.name == "nt" else None
        process = None
        drained = False
        stdout = stderr = ""
        timed_out = False
        launch_failure = None
        termination = None
        try:
            if job is not None:
                process = job.launch(list(spec.argv), cwd=cwd,
                                     env=environment if environment is not None else {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            else:
                process = subprocess.Popen(list(spec.argv), cwd=str(cwd), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            while True:
                if cancel.is_set() or time.monotonic() >= deadline:
                    timed_out = True
                    break
                try:
                    stdout, stderr = process.communicate(timeout=min(.05, max(.001, deadline - time.monotonic())))
                    drained = True
                    break
                except subprocess.TimeoutExpired:
                    continue
        except BaseException as exc:
            launch_failure = type(exc).__name__
            timed_out = True
        finally:
            if process is None and job is not None:
                process = job.process  # launch can fail after creating Popen.
            # App-server Job ownership does not cover this host-created process.
            cleanup_errors = []
            termination = {"root_terminated": False, "tree_terminated_confirmed": False,
                           "unknown_side_effect": True}
            try:
                termination = job.stop(wait_seconds=.5) if job is not None else (
                    stop_owned_process(process, wait_seconds=.5) if process is not None else
                    {"root_terminated": True, "tree_terminated_confirmed": True, "unknown_side_effect": False})
            except BaseException as exc:
                cleanup_errors.append({"operation": "stop_tree", "exception_type": type(exc).__name__})
            if not isinstance(termination, dict):
                cleanup_errors.append({"operation": "stop_receipt", "exception_type": "InvalidReceipt"})
                termination = {"unknown_side_effect": True}
            if process is not None and not drained:
                try:
                    stdout, stderr = process.communicate(timeout=.5)
                    drained = True
                except BaseException as exc:
                    cleanup_errors.append({"operation": "drain_output", "exception_type": type(exc).__name__})
            if process is None:
                drained = True
            termination["output_drained"] = drained
            termination["launch_failure"] = launch_failure
            if process is not None and drained:
                for name, stream in (("stdin", process.stdin), ("stdout", process.stdout), ("stderr", process.stderr)):
                    try:
                        if stream is not None and not stream.closed:
                            stream.close()
                    except BaseException as exc:
                        cleanup_errors.append({"operation": "close_" + name, "exception_type": type(exc).__name__})
                handle = getattr(process, "_handle", None)
                try:
                    if handle is not None and process.poll() is not None:
                        handle.Close()
                except BaseException as exc:
                    cleanup_errors.append({"operation": "close_process_handle", "exception_type": type(exc).__name__})
                closed = []
                for name, stream in (("stdin", process.stdin), ("stdout", process.stdout), ("stderr", process.stderr)):
                    try:
                        closed.append(stream is None or bool(stream.closed))
                    except BaseException as exc:
                        closed.append(False)
                        cleanup_errors.append({"operation": "verify_" + name, "exception_type": type(exc).__name__})
                termination["pipes_closed"] = all(closed)
                try:
                    termination["process_handle_closed"] = bool(handle.closed) if handle is not None else None
                except BaseException as exc:
                    termination["process_handle_closed"] = False
                    cleanup_errors.append({"operation": "verify_process_handle", "exception_type": type(exc).__name__})
            termination["cleanup_errors"] = cleanup_errors
            termination["unknown_side_effect"] = (termination.get("unknown_side_effect", True) or bool(cleanup_errors) or not drained
                or (process is not None and not termination.get("pipes_closed", False))
                or (process is not None and os.name == "nt" and not termination.get("process_handle_closed")))
        stdout, stderr = _text(stdout), _text(stderr)
        truncated = len(stdout) + len(stderr) > spec.output_limit
        stdout = stdout[:spec.output_limit // 2] if truncated else stdout
        stderr = stderr[:spec.output_limit - len(stdout)] if truncated else stderr
        return CommandResult(None if timed_out or process is None else process.returncode, stdout, stderr,
            round((time.monotonic() - started) * 1000),
            timed_out or termination["unknown_side_effect"], truncated, termination, launch)
