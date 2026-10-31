"""Bounded stop of one Popen owned by this Host; no discovery or recovery."""
import os
import subprocess
from typing import Any


def stop_owned_process(process: subprocess.Popen, *, wait_seconds: float = 1.0) -> dict[str, Any]:
    receipt: dict[str, Any] = {"pid": process.pid, "attempts": [], "root_terminated": False,
                               "tree_terminated_confirmed": False, "unknown_side_effect": True}
    tree_stopped = False
    if process.poll() is None:
        if os.name == "nt":
            # Keep the parent alive until /T targets its descendants. Terminating
            # the parent first would lose the Windows tree association.
            try:
                result = subprocess.run(
                    [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe"),
                     "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True, timeout=3.0, shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                tree_stopped = result.returncode == 0
                receipt["attempts"].append({"operation": "taskkill_tree", "exit_code": result.returncode})
            except (OSError, subprocess.TimeoutExpired) as exc:
                receipt["attempts"].append({"operation": "taskkill_tree", "error": type(exc).__name__})
        else:
            try:
                process.terminate()
                receipt["attempts"].append({"operation": "terminate_root"})
            except OSError as exc:
                receipt["attempts"].append({"operation": "terminate_root", "error": type(exc).__name__})
        try:
            process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            for operation in ("terminate", "kill"):
                try:
                    getattr(process, operation)()
                    receipt["attempts"].append({"operation": operation + "_root"})
                    process.wait(timeout=wait_seconds)
                    break
                except (OSError, subprocess.TimeoutExpired) as exc:
                    receipt["attempts"].append({"operation": operation + "_root", "error": type(exc).__name__})
    receipt["root_terminated"] = process.poll() is not None
    receipt["tree_terminated_confirmed"] = tree_stopped and receipt["root_terminated"]
    receipt["unknown_side_effect"] = not receipt["tree_terminated_confirmed"]
    return receipt
