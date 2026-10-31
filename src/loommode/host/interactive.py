"""Finite JSONL/stdin interface for an explicitly configured, trusted live Host."""
import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from threading import Lock, Thread

from loommode.codex.errors import LoomModeError
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object
from .driver import DecisionHost
from .requests import DelegationRequest, OwnerRequest, request_from_text, urgent_stop_from_text
from .state_view import StatusSnapshot
from .supervisor import SupervisorHost


def serve(host: DecisionHost, source, destination) -> None:
    displayed = None

    def emit(value):
        nonlocal displayed
        destination.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
        destination.flush()
        if "current_facts" in value and "current_revision" in value:
            displayed = StatusSnapshot(copy.deepcopy(value["current_facts"]), {}, value["current_revision"])
        elif "facts" in value and "revision" in value:
            displayed = StatusSnapshot(copy.deepcopy(value["facts"]), {}, value["revision"])

    emit(host.status())
    for line in source:
        try:
            frame = json.loads(line, object_pairs_hook=unique_json_object)
            if not isinstance(frame, dict):
                raise WorkflowError("Owner frame must be an object")
            if {'text'} <= set(frame) <= {'text', 'expected_revision'}:
                value = host.handle_text(frame["text"], displayed=displayed)
            elif set(frame) <= {"op", "max_steps"} and frame.get("op") == "advance":
                value = host.advance(frame.get("max_steps", 1))
            elif set(frame) <= {"op", "max_steps"} and frame.get("op") in {"resume", "run"}:
                value = host.resume(frame.get("max_steps", 100))
            elif {"op", "scope"} <= set(frame) <= {"op", "scope", "request_id", "task_id", 'scope_id', 'authority_ref', 'authority_sha256'} and frame.get("op") == "start":
                request = DelegationRequest.from_frame(displayed, frame)
                if "task_id" in frame and frame["task_id"] != request.task_id:
                    raise WorkflowError("delegation targets a different displayed Task")
                value = host.start(request)
            elif set(frame) == {"delegation"} and isinstance(frame["delegation"], dict):
                value = host.start(DelegationRequest(**frame["delegation"]))
            elif set(frame) == {"op"} and frame["op"] == "status":
                value = host.status()
            elif set(frame) == {"request"} and isinstance(frame["request"], dict):
                fields = dict(frame["request"])
                for key in ("evidence_refs", "check_focus"):
                    if key in fields:
                        if not isinstance(fields[key], list):
                            raise WorkflowError("request references/focus must be JSON arrays")
                        fields[key] = tuple(fields[key])
                value = host.handle(OwnerRequest(**fields))
            else:
                raise WorkflowError("unsupported finite Owner frame")
            emit(value)
        except (WorkflowError, LoomModeError, OSError, ValueError, TypeError) as exc:
            emit({**host.status(), "status": "ERROR", "error": str(exc)})
            # Retain the snapshot actually displayed, not a newer hidden query.


def serve_managed(supervisor: SupervisorHost, source, destination) -> None:
    """Concurrent factual stdin and completion output for one trusted live run."""
    if not isinstance(supervisor, SupervisorHost):
        raise WorkflowError("managed service requires the bound SupervisorHost")
    output_lock, displayed, output_errors = Lock(), None, []

    def emit(value):
        nonlocal displayed
        with output_lock:
            destination.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
            destination.flush()
            if "facts" in value and "revision" in value:
                displayed = StatusSnapshot(copy.deepcopy(value["facts"]), {}, value["revision"])

    def watch():
        cursor = 0
        try:
            while True:
                update = supervisor.wait_for_update(cursor)
                cursor = update["cursor"]
                emit(update)
                final_reply = supervisor.take_final_reply()
                if final_reply is not None:
                    emit({"status": "MANAGED_FINAL", "final_reply": final_reply})
                if update["facts"]["managed_run"]["phase"] == "CLOSED":
                    return
        except Exception as exc:
            output_errors.append(exc)
            supervisor.close(wait=False)

    def handle(request):
        if request.kind in {"STATUS", "ARTIFACT"}:
            return supervisor.host.handle(request)
        return supervisor.submit(supervisor.event(kind="OWNER", owner_request=request))

    monitor = Thread(target=watch, name=f"loommode-owner-output-{supervisor.run_id}")
    try:
        emit(supervisor.status())
        monitor.start()
        for line in source:
            if output_errors:
                raise WorkflowError(f"managed output failed; run fenced: {output_errors[0]}")
            try:
                frame = json.loads(line, object_pairs_hook=unique_json_object)
                if not isinstance(frame, dict):
                    raise WorkflowError("managed Owner frame must be an object")
                with output_lock:
                    snapshot = displayed
                state = supervisor.host.engine.state
                urgent = urgent_stop_from_text(frame.get('text'), project=state.project, stage_id=state.stage_id,
                                              task_id=state.task_id, expected_revision=frame.get('expected_revision'))
                if urgent and {'text'} <= set(frame) <= {'text', 'expected_revision'}:
                    value = supervisor.pause_owner(urgent)
                elif set(frame) == {"op"} and frame["op"] == "status":
                    value = supervisor.status()
                elif {"op", "scope"} <= set(frame) <= {"op", "scope", "request_id", "task_id", "automatic", "series_id", "series_plan_ref", 'scope_id', 'authority_ref', 'authority_sha256'} and frame.get("op") == "start":
                    request = DelegationRequest.from_frame(snapshot, frame)
                    if "task_id" in frame and frame["task_id"] != request.task_id:
                        raise WorkflowError("delegation targets a different displayed Task")
                    value = supervisor.start(request, automatic=frame.get("automatic", False),
                        series_id=frame.get("series_id"), series_plan_ref=frame.get("series_plan_ref"))
                elif set(frame) == {"op"} and frame["op"] in {"resume", "run"}:
                    value = supervisor.resume()
                elif set(frame) == {"op"} and frame["op"] == "advance":
                    value = supervisor.submit(supervisor.event())
                elif set(frame) <= {"op", "wait"} and frame.get("op") == "close":
                    emit(supervisor.close(wait=frame.get("wait", True)))
                    break
                elif set(frame) == {"request"} and isinstance(frame["request"], dict):
                    fields = dict(frame["request"])
                    for key in ("evidence_refs", "check_focus"):
                        if key in fields:
                            if not isinstance(fields[key], list):
                                raise WorkflowError("request references/focus must be JSON arrays")
                            fields[key] = tuple(fields[key])
                    value = handle(OwnerRequest(**fields))
                elif set(frame) == {"text"}:
                    request = request_from_text(frame["text"], snapshot)
                    if request is None:
                        raise WorkflowError("explicit managed status/request/start/run/close frame required")
                    value = handle(request)
                else:
                    raise WorkflowError("unsupported managed Owner frame")
                emit(value)
            except (WorkflowError, LoomModeError, OSError, ValueError, TypeError) as exc:
                emit({**supervisor.status(), "status": "ERROR", "error": str(exc)})
    finally:
        joined = supervisor.close()  # EOF/close is a fence and actual join, never cancellation.
        if monitor.ident is not None:
            monitor.join()
    if output_errors:
        raise WorkflowError(f"managed output failed; run joined: {output_errors[0]}")
    emit({**joined, "status": "MANAGED_CLOSED"})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Decision live Host JSONL; no implicit saved-state recovery.")
    parser.add_argument("--factory", type=Path, required=True,
                        help="Explicit trusted Python Host configuration exporting create_host().")
    parser.add_argument("--managed", action="store_true",
                        help="Live Supervisor JSONL with explicit per-start automatic opt-in.")
    args = parser.parse_args(argv)
    try:
        path = args.factory.resolve(strict=True)
        if path.suffix != ".py":
            raise WorkflowError("explicit Python Host factory required")
        spec = importlib.util.spec_from_file_location("loommode_authorized_host_factory", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        host = module.create_host()
        if args.managed:
            if isinstance(host, DecisionHost):
                host = SupervisorHost(host)
            if not isinstance(host, SupervisorHost):
                raise WorkflowError("managed factory must return the bound DecisionHost or SupervisorHost")
            serve_managed(host, sys.stdin, sys.stdout)
        else:
            if not isinstance(host, DecisionHost):
                raise WorkflowError("factory must return the bound DecisionHost")
            serve(host, sys.stdin, sys.stdout)
        return 0
    except (WorkflowError, LoomModeError, OSError, ValueError, TypeError, AttributeError, ImportError) as exc:
        print(json.dumps({"status": "UNAVAILABLE", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
