"""Fixed-shape Git operations with exact staging and local-only commits."""

from __future__ import annotations

import re
import math
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from loommode.codex.errors import ErrorCategory, LoomModeError
from .filesystem import normalize_relative
from .test_runner import CommandResult


@dataclass(frozen=True)
class CommitReceipt:
    commit_hash: str
    message: str
    staged_files: tuple[str, ...]
    final_status: str

    def as_dict(self) -> dict[str, object]:
        return {
            "commit_hash": self.commit_hash,
            "message": self.message,
            "staged_files": list(self.staged_files),
            "final_status": self.final_status,
        }


def _sanitize_remote_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<redacted-invalid-url>"
    if parsed.scheme in {"http", "https"}:
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    return value.split("?", 1)[0].split("#", 1)[0]


class GitRuntime:
    def __init__(
        self,
        workspace: Path,
        *,
        stageable: tuple[str, ...],
        commit_messages: tuple[str, ...],
        timeout_seconds: float = 30.0,
        output_limit: int = 32_000,
    ) -> None:
        self.workspace = workspace.resolve(strict=True)
        self.stageable = frozenset(normalize_relative(path) for path in stageable)
        self.commit_messages = frozenset(commit_messages)
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit
        probe = self._run(("rev-parse", "--is-inside-work-tree"))
        if probe.exit_code != 0 or probe.stdout.strip() != "true":
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "workspace is not a Git worktree")

    def _run(self, args: tuple[str, ...]) -> CommandResult:
        started = time.monotonic()
        try:
            process = subprocess.run(
                ["git", *args],
                cwd=str(self.workspace),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LoomModeError(ErrorCategory.TOOL_TIMEOUT, "Git operation timed out") from exc
        stdout, stderr = process.stdout, process.stderr
        truncated = len(stdout) + len(stderr) > self.output_limit
        if truncated:
            stdout = stdout[: self.output_limit // 2]
            stderr = stderr[: self.output_limit - len(stdout)]
        return CommandResult(
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            timed_out=False,
            truncated=truncated,
        )

    @staticmethod
    def _require_success(result: CommandResult, operation: str) -> CommandResult:
        if result.exit_code != 0:
            raise LoomModeError(
                ErrorCategory.TOOL_EXECUTION_ERROR,
                f"Git {operation} failed",
                details={"exit_code": result.exit_code, "stderr": result.stderr[:1000]},
            )
        return result

    def status(self) -> CommandResult:
        return self._require_success(self._run(("status", "--porcelain=v1")), "status")

    def inventory(self) -> dict[str, object]:
        """Complete, path-only checkpoint facts; unknown directories are not opened.

        Any untracked/ignored directory is a dirty fact, rather than something
        this Host recursively reads to decide who owns it.
        """
        def read(args: tuple[str, ...]) -> str:
            # Read-only inventories neither stage nor convert working files.
            # Avoid safecrlf's conversion warning for legitimate LF edits while
            # retaining autocrlf normalization and rejecting every other stderr.
            result = self._require_success(self._run(("-c", "core.fsmonitor=false", "-c",
                                                       "core.untrackedCache=false", "-c",
                                                       "core.safecrlf=false", *args)), "inventory")
            if result.truncated or result.timed_out or result.stderr.strip() or "\ufffd" in result.stdout:
                raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "Git inventory is incomplete or ambiguous")
            return result.stdout

        root = read(("rev-parse", "--show-toplevel")).strip()
        if Path(root).resolve() != self.workspace:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "inventory workspace is not the repository root")
        head = read(("rev-parse", "--verify", "HEAD")).strip()
        branch = read(("symbolic-ref", "--short", "HEAD")).strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) or not branch:
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "unknown Git baseline identity")
        index = read(("ls-files", "--stage", "-z"))
        tracked = read(("ls-files", "--cached", "-z"))
        flags = read(("ls-files", "-v", "-z"))
        return {"workspace": str(self.workspace), "branch": branch, "head": head,
                "index": [p for p in index.split("\0") if p],
                "tracked": [p for p in tracked.split("\0") if p],
                "flags": [p for p in flags.split("\0") if p],
                "status": read(("status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignored=matching")),
                "index_diff": read(("diff", "--cached", "--name-only", "-z")),
                "worktree_diff": read(("diff", "--name-only", "-z"))}

    def diff(self, *, cached: bool = False) -> CommandResult:
        args = ("diff", "--cached") if cached else ("diff",)
        return self._require_success(self._run(args), "diff")

    def log_head(self) -> CommandResult:
        return self._require_success(
            self._run(("log", "-1", "--format=%H%n%s")),
            "log",
        )

    def remotes(self) -> dict[str, str]:
        names = self._require_success(self._run(("remote",)), "remote read").stdout.splitlines()
        result: dict[str, str] = {}
        for name in names:
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                continue
            url = self._require_success(self._run(("remote", "get-url", name)), "remote read").stdout.strip()
            result[name] = _sanitize_remote_url(url)
        return result

    def staged_files(self) -> tuple[str, ...]:
        result = self._require_success(
            self._run(("diff", "--cached", "--name-only", "-z")),
            "staged-files read",
        )
        if result.truncated:
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "staged path inventory was truncated")
        return tuple(path.replace("\\", "/") for path in result.stdout.split("\0") if path)

    def stage(self, paths: list[str]) -> dict[str, object]:
        normalized = tuple(normalize_relative(path) for path in paths)
        if not normalized or len(set(normalized)) != len(normalized):
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "stage requires unique explicit paths")
        denied = sorted(set(normalized) - self.stageable)
        if denied:
            raise LoomModeError(
                ErrorCategory.TOOL_PERMISSION_ERROR,
                "one or more stage paths are not authorized",
                details={"denied": denied},
            )
        result = self._require_success(self._run(("add", "--", *normalized)), "exact stage")
        return {"paths": list(normalized), "staged_files": list(self.staged_files()), "exit_code": result.exit_code}

    def commit(self, message: str) -> CommitReceipt:
        if message not in self.commit_messages:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "commit message is not authorized")
        staged = self.staged_files()
        if not staged:
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "nothing is staged")
        denied = sorted(set(staged) - self.stageable)
        if denied:
            raise LoomModeError(
                ErrorCategory.TOOL_PERMISSION_ERROR,
                "commit contains unauthorized staged paths",
                details={"denied": denied},
            )
        result = self._run(
            (
                "-c",
                "user.name=LoomMode Runtime",
                "-c",
                "user.email=loommode-runtime@invalid.local",
                "commit",
                "-m",
                message,
            )
        )
        self._require_success(result, "commit")
        head = self._require_success(self._run(("rev-parse", "HEAD")), "HEAD read").stdout.strip()
        return CommitReceipt(
            commit_hash=head,
            message=message,
            staged_files=staged,
            final_status=self.status().stdout,
        )


def require_clean_inventory(value: object, *, workspace: str, scope: list[str]) -> None:
    """Conservative no-change boundary, including hidden index flags."""
    keys = {"workspace", "branch", "head", "index", "tracked", "flags", "status", "index_diff", "worktree_diff"}
    if not isinstance(value, dict) or set(value) != keys:
        raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "unknown Git inventory shape")
    if (value["workspace"] != workspace or not isinstance(value["branch"], str) or not value["branch"]
            or not isinstance(value["head"], str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["head"])):
        raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "Git inventory identity mismatch")
    if any(value[key] != "" for key in ("status", "index_diff", "worktree_diff")):
        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change requires a clean Task-start and current inventory")
    for key in ("index", "tracked", "flags"):
        if not isinstance(value[key], list) or not value[key] or any(not isinstance(p, str) or not p for p in value[key]):
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "unknown tracked/index inventory")
    if (len(value["tracked"]) != len(set(value["tracked"]))
            or len(value["index"]) != len(value["tracked"]) or len(value["flags"]) != len(value["tracked"])):
        raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "ambiguous tracked/index inventory")
    for row, path, flag in zip(value["index"], value["tracked"], value["flags"]):
        if not re.fullmatch(r"(?:100644|100755) (?:[0-9a-f]{40}|[0-9a-f]{64}) 0\t" + re.escape(path), row) or flag != "H " + path:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change excludes sparse, hidden, conflicted and non-file index entries")
    if not scope or any(normalize_relative(p) != p or p not in value["tracked"] for p in scope):
        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change requires explicit tracked-file Task scope")


def _known_test_launch(value, spec, workspace):
    """Pure saved metadata check; owned Host facts establish live provenance.

    Never follow record paths here. Reconstruct the producer's exact plan and
    launch-record bytes so additional metadata cannot silently drift.
    """
    if value is None:
        return True
    fields = {'test_id', 'spec_sha256', 'request_fingerprint', 'policy_sha256', 'argv', 'cwd',
              'environment', 'binary_sha256', 'python_sha256', 'control_directory',
              'host_identity_sha256', 'root_import_index', 'root_import_bootstrap',
              'root_import_bootstrap_sha256', 'plan_sha256', 'isolation', 'record', 'record_sha256'}
    if not isinstance(value, dict) or set(value) != fields:
        return False
    try:
        def digest(item):
            return hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':'),
                                              default=str, allow_nan=False).encode()).hexdigest()
        hashes = ('spec_sha256', 'request_fingerprint', 'policy_sha256', 'binary_sha256',
                  'python_sha256', 'host_identity_sha256', 'root_import_bootstrap_sha256',
                  'plan_sha256', 'record_sha256')
        if (any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k]) for k in hashes)
                or value['test_id'] != spec['test_id'] or value['spec_sha256'] != digest(spec)
                or spec['cwd'] != '.'
                or value['cwd'] != workspace
                or value['isolation'] != 'FIXED_CODEX_MXC_SANDBOX_NO_NETWORK'
                or not isinstance(value['argv'], list) or not value['argv']
                or any(not isinstance(x, str) or not x for x in value['argv'])
                or not isinstance(value['root_import_index'], list) or not value['root_import_index']
                or any(not isinstance(x, str) or not x or x in {'.', '..'}
                       or any(c in x for c in '/\\\x00:') for x in value['root_import_index'])
                or len(set(value['root_import_index'])) != len(value['root_import_index'])
                or not isinstance(value['root_import_bootstrap'], str)
                or hashlib.sha256(value['root_import_bootstrap'].encode()).hexdigest()
                   != value['root_import_bootstrap_sha256']
                or not isinstance(value['environment'], list) or not value['environment']
                or any(not isinstance(pair, list) or len(pair) != 2
                       or any(not isinstance(x, str) for x in pair) or not pair[0]
                       for pair in value['environment'])
                or len({pair[0] for pair in value['environment']}) != len(value['environment'])):
            return False
        if any(not isinstance(value[k], str) or not value[k] or '\x00' in value[k]
               or '..' in Path(value[k]).parts or not Path(value[k]).is_absolute()
               for k in ('control_directory', 'record')):
            return False
        record, directory = Path(value['record']), Path(value['control_directory'])
        if record.parent != directory or not re.fullmatch(r'launch-[0-9a-f]{32}\.json', record.name):
            return False
        plan = {k: v for k, v in value.items() if k not in {'plan_sha256', 'isolation', 'record', 'record_sha256'}}
        if digest(plan) != value['plan_sha256']:
            return False
        embedded_record = {k: v for k, v in value.items() if k not in {'record', 'record_sha256'}}
        raw = (json.dumps(embedded_record, sort_keys=True, default=str, allow_nan=False) + '\n').encode()
        return hashlib.sha256(raw).hexdigest() == value['record_sha256']
    except (KeyError, TypeError, ValueError):
        return False


def require_no_commit_evidence(value: object, *, binding: dict[str, object] | None = None) -> None:
    """Strict saved proof shape. Live provenance is checked separately by Host."""
    keys = {"schema_version", "disposition", "verification_id", "verified_at", "binding", "policy",
            "task_start_inventory", "verified_inventory", "required_tests"}
    if (not isinstance(value, dict) or set(value) != keys or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["disposition"] != "NO_DEV_CHANGE"):
        raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "unknown no-commit evidence contract")
    for key in ("verification_id", "verified_at"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "missing Host no-commit evidence identity")
    actual = value["binding"]
    binding_keys = {"project", "stage_id", "task_id", "host_context_ref", "workspace", "stage_input_ref",
                    "stage_input_sha256", "intent_ref", "final_ref", "report_ref", "acceptance_ref",
                    "report_result_ref", "scope", "required_artifact_refs"}
    if not isinstance(actual, dict) or set(actual) != binding_keys or (binding is not None and actual != binding):
        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-commit formal binding mismatch")
    for key in binding_keys - {"scope", "required_artifact_refs"}:
        if not isinstance(actual[key], str) or not actual[key].strip():
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-commit formal binding missing")
    for key in ("scope", "required_artifact_refs"):
        if (not isinstance(actual[key], list) or not actual[key]
                or any(not isinstance(p, str) or not p for p in actual[key])
                or len(actual[key]) != len(set(actual[key]))):
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-commit scope/artifact inventory is unknown")
    policy = value["policy"]
    if (not isinstance(policy, dict) or set(policy) != {"allow_no_dev_change", "writable_paths", "stageable_paths", "commit_messages", "fixed_tests"}
            or policy["allow_no_dev_change"] is not True or policy["writable_paths"] != actual["scope"]
            or not isinstance(policy["stageable_paths"], list) or not policy["stageable_paths"]
            or not isinstance(policy["commit_messages"], list) or len(policy["commit_messages"]) != 1
            or not isinstance(policy["commit_messages"][0], str)
            or not policy["commit_messages"][0].startswith(f"[{actual['task_id']}]")
            or not isinstance(policy["fixed_tests"], list)
            or any(not isinstance(p, str) or p not in actual["scope"] for p in policy["stageable_paths"])
            or len(policy["stageable_paths"]) != len(set(policy["stageable_paths"]))):
        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-commit does not have an explicit applicable policy")
    for inventory in (value["task_start_inventory"], value["verified_inventory"]):
        require_clean_inventory(inventory, workspace=actual["workspace"], scope=actual["scope"])
    if value["task_start_inventory"] != value["verified_inventory"]:
        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-commit baseline changed")
    test_ids = []
    for spec in policy["fixed_tests"]:
        if (not isinstance(spec, dict) or set(spec) != {"test_id", "argv", "cwd", "timeout_seconds", "output_limit"}
                or not isinstance(spec["test_id"], str) or not spec["test_id"]
                or not isinstance(spec["argv"], list) or not spec["argv"]
                or any(not isinstance(a, str) or not a for a in spec["argv"])
                or not isinstance(spec["cwd"], str) or not spec["cwd"]
                or type(spec["timeout_seconds"]) not in {int, float} or spec["timeout_seconds"] <= 0
                or (type(spec["timeout_seconds"]) is float and not math.isfinite(spec["timeout_seconds"]))
                or type(spec["output_limit"]) is not int or spec["output_limit"] <= 0):
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "unknown required fixed-test inventory")
        test_ids.append(spec["test_id"])
    tests = value["required_tests"]
    if not isinstance(tests, dict) or set(tests) != set(test_ids) or len(test_ids) != len(set(test_ids)):
        raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "required fixed tests were not run by Host")
    specifications = {spec['test_id']: spec for spec in policy['fixed_tests']}
    for test_id, check in tests.items():
        if (not isinstance(check, dict) or set(check) != {"result", "inventory_before", "inventory_after", "inventory_error"}
                or check["inventory_error"] is not None or check["inventory_before"] != value["verified_inventory"]
                or check["inventory_after"] != value["verified_inventory"]):
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "required fixed-test source/inventory is unknown or changed")
        result = check["result"]
        termination = result.get('termination') if isinstance(result, dict) else None
        known_termination = (termination is None or (isinstance(termination, dict)
            and set(termination) == {'pid', 'root_terminated', 'tree_terminated_confirmed', 'job_handle_closed',
                'unknown_side_effect', 'ownership', 'errors', 'output_drained', 'launch_failure',
                'pipes_closed', 'process_handle_closed', 'cleanup_errors'}
            and type(termination.get('pid')) is int and termination['pid'] > 0
            and termination.get('ownership') == 'WINDOWS_JOB_NO_BREAKAWAY' and termination.get('errors') == []
            and termination.get('unknown_side_effect') is False
            and termination.get('cleanup_errors') == [] and termination.get('launch_failure') is None
            and all(termination.get(key) is True for key in ('root_terminated', 'tree_terminated_confirmed',
                'job_handle_closed', 'output_drained', 'pipes_closed', 'process_handle_closed'))))
        result_fields = {"exit_code", "stdout", "stderr", "elapsed_ms", "timed_out", "truncated", "passed", "termination"}
        if (not isinstance(result, dict) or set(result) not in (result_fields, result_fields | {'launch'})
                or not _known_test_launch(result.get('launch'), specifications[test_id], actual['workspace'])
                or type(result["exit_code"]) is not int or result["exit_code"] != 0
                or not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)
                or type(result["elapsed_ms"]) is not int or result["elapsed_ms"] < 0
                or result["timed_out"] is not False or result["truncated"] is not False
                or result["passed"] is not True or not known_termination):
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "required fixed test failed, timed out, truncated or is unknown")
