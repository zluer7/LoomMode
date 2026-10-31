"""Dynamic-tool host with profile checks, fixed targets, and safe audit records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import copy
from uuid import uuid4
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any

from loommode.codex.errors import ErrorCategory, ErrorRecord, LoomModeError, error_record
from .filesystem import BoundedFileSystem, normalize_relative
from .git import GitRuntime, require_clean_inventory, require_no_commit_evidence
from .test_runner import FixedTestRunner, TestSpec, check_execution_control


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ToolProfile(StrEnum):
    READ_ONLY_REVIEW = "READ_ONLY_REVIEW"
    BOUNDED_DEVELOPMENT = "BOUNDED_DEVELOPMENT"


class ToolPhase(StrEnum):
    IMPLEMENTATION = "IMPLEMENTATION"
    COMMIT_AUTHORIZED = "COMMIT_AUTHORIZED"
    SUSPENDED = "SUSPENDED"


@dataclass(frozen=True)
class ToolPolicy:
    workspace: Path
    profile: ToolProfile
    readable_paths: tuple[str, ...]
    writable_paths: tuple[str, ...] = ()
    stageable_paths: tuple[str, ...] = ()
    test_specs: tuple[TestSpec, ...] = ()
    commit_messages: tuple[str, ...] = ()
    allow_no_dev_change: bool = False
    normal_supply_authority_ref: str | None = None

    def __post_init__(self) -> None:
        if type(self.allow_no_dev_change) is not bool:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "no-change permission must be an explicit boolean")
        if self.normal_supply_authority_ref is not None and (not isinstance(self.normal_supply_authority_ref, str)
                or not self.normal_supply_authority_ref.strip() or self.profile != ToolProfile.BOUNDED_DEVELOPMENT):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'normal supply requires explicit bounded development authority reference')
        readable = {normalize_relative(path) for path in self.readable_paths}
        writable = {normalize_relative(path) for path in self.writable_paths}
        stageable = {normalize_relative(path) for path in self.stageable_paths}
        if not writable.issubset(readable):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "writable paths must also be readable")
        if not stageable.issubset(writable):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "stageable paths must also be writable")
        if self.profile == ToolProfile.BOUNDED_DEVELOPMENT and not writable:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "development profile requires a write target")

    def preflight(self, *, bound: ToolPolicy | None = None, check_tests: bool = True) -> None:
        try:
            workspace = self.workspace.resolve(strict=True)
        except OSError as exc:
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, 'tool workspace does not exist') from exc
        if not workspace.is_dir():
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, 'tool workspace is not a directory')
        for field in ('readable_paths', 'writable_paths', 'stageable_paths'):
            for value in getattr(self, field):
                relative = normalize_relative(value)
                target = (workspace / relative).resolve(strict=False)
                if not target.is_relative_to(workspace) or target == workspace:
                    raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, 'policy target escapes workspace')
                if field != 'readable_paths' and Path(relative).parts[0].lower() == '.git':
                    raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'protected Git target is not a development grant')
        if bound:
            if workspace != bound.workspace.resolve(strict=True) or self.profile != bound.profile:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'task policy context mismatch')
            for field in ('readable_paths', 'writable_paths', 'stageable_paths', 'commit_messages', 'test_specs'):
                if not set(getattr(self, field)).issubset(getattr(bound, field)):
                    raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'task grants exceed stage grants')
        if check_tests:
            FixedTestRunner(workspace, self.test_specs).preflight()


@dataclass(frozen=True)
class ToolAudit:
    tool: str
    operation: str
    workspace: str
    target: str | None
    started_at: str
    ended_at: str
    result: str
    exit_status: int | None
    truncated: bool
    error_category: str | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


READ_ONLY_TOOLS = frozenset(
    {
        "loommode_list_files",
        "loommode_read_file",
        "loommode_run_test",
        "loommode_git_status",
        "loommode_git_diff",
        "loommode_git_cached_diff",
        "loommode_git_log_head",
        "loommode_git_remotes",
    }
)

DEVELOPMENT_TOOLS = READ_ONLY_TOOLS | {
    "loommode_replace_file",
    "loommode_git_stage",
    "loommode_git_commit",
}


def _object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }


def _tool(name: str, description: str, schema: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "name": name, "description": description, "inputSchema": schema}


class BoundedToolRuntime:
    def __init__(self, policy: ToolPolicy) -> None:
        policy.preflight(check_tests=False)  # Sticky declarations can include later optional capabilities.
        self.workspace = policy.workspace.resolve(strict=True)
        if not self.workspace.is_dir():
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "tool workspace is not a directory")
        self.profile = policy.profile
        self.policy = policy
        self.stage_policy = policy
        self.phase = ToolPhase.IMPLEMENTATION
        self.poisoned = False
        self._poison_error: ErrorRecord | None = None
        self.timeout_termination: dict[str, Any] | None = None
        self.last_commit_receipt: dict[str, Any] | None = None
        self.last_no_commit_evidence: dict[str, Any] | None = None
        self.task_binding: dict[str, Any] | None = None
        self.task_start_inventory: dict[str, object] | None = None
        self.task_start_inventory_error: str | None = None
        self.test_results: dict[str, dict[str, Any]] = {}
        self._checkpoint_binding: dict[str, Any] | None = None
        self._commit_grant_used = False
        self.files = BoundedFileSystem(
            self.workspace,
            readable=policy.readable_paths,
            writable=policy.writable_paths,
        )
        self.require_test_isolation = False
        self.tests = FixedTestRunner(self.workspace, policy.test_specs)
        self.git = GitRuntime(
            self.workspace,
            stageable=policy.stageable_paths,
            commit_messages=policy.commit_messages,
        )
        self.audit: list[ToolAudit] = []
        self._audit_base = 0
        self.audit_limit = 4096
        self._lock = RLock()

    def configure_task(self, policy: ToolPolicy, *, task_binding: dict[str, Any] | None = None) -> None:
        """Narrow sticky stage tool declarations to current task grants."""
        with self._lock:
            self.assert_usable()
            bound = self.stage_policy
            policy.preflight(bound=replace(bound, profile=self.profile))
            if policy.workspace.resolve(strict=True) != self.workspace or policy.profile != self.profile:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "task policy context mismatch")
            for field in ("readable_paths", "writable_paths", "stageable_paths", "commit_messages", "test_specs"):
                if not set(getattr(policy, field)).issubset(set(getattr(bound, field))):
                    raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "task grants exceed stage grants")
            self.policy = policy
            self.files = BoundedFileSystem(self.workspace, readable=policy.readable_paths, writable=policy.writable_paths)
            self.tests = FixedTestRunner(self.workspace, policy.test_specs,
                                         require_isolation=self.require_test_isolation)
            self.git = GitRuntime(self.workspace, stageable=policy.stageable_paths, commit_messages=policy.commit_messages)
            # A repair on this same input keeps the original Task-start facts.
            # A converted review has no original baseline and cannot prove it.
            if task_binding != self.task_binding or self.task_binding is None:
                self.task_binding = copy.deepcopy(task_binding)
                self.task_start_inventory = None
                self.task_start_inventory_error = None
                if policy.allow_no_dev_change and task_binding:
                    try:
                        self.task_start_inventory = self.git.inventory()
                    except LoomModeError as exc:
                        self.task_start_inventory_error = str(exc)
            self.test_results = {}
            self.phase = ToolPhase.IMPLEMENTATION
            self.last_commit_receipt = None
            self.last_no_commit_evidence = None
            self._checkpoint_binding = None
            self._commit_grant_used = False

    def authorize_commit(self, *, acceptance_ref: str, report_ref: str,
                         checkpoint_binding: dict[str, Any] | None = None) -> None:
        with self._lock:
            self.assert_usable()
            if self.profile != ToolProfile.BOUNDED_DEVELOPMENT or not acceptance_ref or not report_ref:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "commit requires host acceptance and report")
            if self._commit_grant_used:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "commit authorization cannot be replayed")
            self.phase = ToolPhase.COMMIT_AUTHORIZED
            self._commit_grant_used = True
            self._checkpoint_binding = copy.deepcopy(checkpoint_binding)

    def host_no_dev_change(self, binding: dict[str, Any]) -> dict[str, Any]:
        """Host-only proof after Result Gate; never a dynamic model tool."""
        with self._lock:
            self.assert_usable()
            if (self.phase != ToolPhase.COMMIT_AUTHORIZED or not self.policy.allow_no_dev_change
                    or self.last_commit_receipt or self.last_no_commit_evidence):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change is not permitted or checkpoint is already consumed")
            if not binding or binding != self._checkpoint_binding or not self.task_binding:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change lacks accepted Host/Task binding")
            if (not self.policy.stageable_paths or len(self.policy.commit_messages) != 1
                    or not self.policy.commit_messages[0].startswith(f"[{binding.get('task_id')}]")):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change cannot substitute for a missing explicit Task Git grant")
            if any(binding.get(key) != value for key, value in self.task_binding.items()):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change Task-start identity/input changed")
            scope = list(self.policy.writable_paths)
            if binding.get("scope") != scope or set(self.policy.stageable_paths) - set(scope):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change scope is not the explicit Host file scope")
            require_clean_inventory(self.task_start_inventory, workspace=str(self.workspace), scope=scope)
            current = self.git.inventory()
            require_clean_inventory(current, workspace=str(self.workspace), scope=scope)
            if current != self.task_start_inventory:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "Task-start/current Git facts changed")
            tests = []
            for spec in self.policy.test_specs:
                tests.append({**asdict(spec), "argv": list(spec.argv)})
            evidence = {"schema_version": 1, "disposition": "NO_DEV_CHANGE", "verification_id": str(uuid4()),
                        "verified_at": _now(), "binding": copy.deepcopy(binding),
                        "policy": {"allow_no_dev_change": True, "writable_paths": scope,
                                   "stageable_paths": list(self.policy.stageable_paths),
                                   "commit_messages": list(self.policy.commit_messages), "fixed_tests": tests},
                        "task_start_inventory": copy.deepcopy(self.task_start_inventory),
                        "verified_inventory": current, "required_tests": copy.deepcopy(self.test_results)}
            require_no_commit_evidence(evidence, binding=binding)
            self.last_no_commit_evidence = copy.deepcopy(evidence)
            self.phase = ToolPhase.SUSPENDED
            return evidence

    def verify_no_dev_change(self, evidence: dict[str, Any], binding: dict[str, Any]) -> None:
        with self._lock:
            self.assert_usable()
            require_no_commit_evidence(evidence, binding=binding)
            if (self.phase != ToolPhase.SUSPENDED or self.last_commit_receipt
                    or evidence != self.last_no_commit_evidence or binding != self._checkpoint_binding
                    or evidence["required_tests"] != self.test_results
                    or evidence["verified_inventory"] != self.git.inventory()):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "no-change evidence is not this live Host's unchanged checkpoint")

    def suspend_mutations(self) -> None:
        # A stop fence must not wait for a callback holding the runtime lock.
        # It prevents future mutation admission; an already in-flight effect
        # remains UNKNOWN until its owned worker/resources are actually joined.
        self.phase = ToolPhase.SUSPENDED

    def set_profile(self, profile: ToolProfile) -> None:
        with self._lock:
            self.assert_usable()
            if self.profile == ToolProfile.BOUNDED_DEVELOPMENT and profile == ToolProfile.READ_ONLY_REVIEW:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "development profile cannot revert to fresh review")
            self.profile = profile

    def assert_usable(self) -> None:
        if self.poisoned:
            cause = self._poison_error
            raise LoomModeError(cause.category if cause else ErrorCategory.TRANSPORT_ERROR,
                               "invocation permanently stopped: " +
                               (cause.message if cause else "unknown tool runtime poison") + "; no replay",
                               details=cause.details if cause else None)

    def dynamic_tools(self) -> list[dict[str, Any]]:
        # Future implementation targets remain authorized, but an absent file
        # is not yet a readable input. Fresh review after creation advertises it.
        read_enum = self.files.list_allowed()['files']
        write_enum = sorted(self.files.writable)
        test_enum = sorted(self.tests.specs)
        stage_enum = sorted(self.git.stageable)
        commit_enum = sorted(self.git.commit_messages)
        tools = [
            _tool("loommode_list_files", "List only the host-authorized files.", _object_schema({}, [])),
            _tool(
                "loommode_read_file",
                "Read one host-authorized UTF-8 file.",
                _object_schema({"path": {"type": "string", "enum": read_enum}}, ["path"]),
            ),
            _tool("loommode_git_status", "Read Git porcelain status.", _object_schema({}, [])),
            _tool("loommode_git_diff", "Read the unstaged Git diff.", _object_schema({}, [])),
            _tool("loommode_git_cached_diff", "Read the staged Git diff.", _object_schema({}, [])),
            _tool("loommode_git_log_head", "Read the current commit hash and subject.", _object_schema({}, [])),
            _tool("loommode_git_remotes", "Read remote names and sanitized URLs.", _object_schema({}, [])),
        ]
        if test_enum:
            tools.append(
                _tool(
                    "loommode_run_test",
                    "Run one host-defined test command by fixed ID.",
                    _object_schema({"test_id": {"type": "string", "enum": test_enum}}, ["test_id"]),
                )
            )
        # These definitions remain sticky for the app-server thread. The host profile
        # rejects them until the fresh-review context is irreversibly converted.
        if write_enum:
            tools.append(
                _tool(
                    "loommode_replace_file",
                    "Replace one exact occurrence in an authorized file; development profile required.",
                    _object_schema(
                        {
                            "path": {"type": "string", "enum": write_enum},
                            "expected": {"type": "string", "minLength": 1, "maxLength": 128000},
                            "replacement": {"type": "string", "maxLength": 128000},
                        },
                        ["path", "expected", "replacement"],
                    ),
                )
            )
        if stage_enum:
            tools.append(
                _tool(
                    "loommode_git_stage",
                    "Stage only explicit host-authorized paths; development profile required.",
                    _object_schema(
                        {
                            "paths": {
                                "type": "array",
                                "items": {"type": "string", "enum": stage_enum},
                                "minItems": 1,
                                "uniqueItems": True,
                            }
                        },
                        ["paths"],
                    ),
                )
            )
        if commit_enum:
            tools.append(
                _tool(
                    "loommode_git_commit",
                    "Create one local commit using a host-authorized message; development profile required.",
                    _object_schema({"message": {"type": "string", "enum": commit_enum}}, ["message"]),
                )
            )
        return tools

    def audit_index(self) -> int:
        return self._audit_base + len(self.audit)

    def audit_since(self, index: int) -> tuple[ToolAudit, ...]:
        if index < self._audit_base:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "tool audit receipt has already been retired")
        return tuple(self.audit[index - self._audit_base:])

    def has_fatal_failure_since(self, index: int) -> bool:
        return any(item.error_category is not None for item in self.audit_since(index))

    def retire_audit(self, keep: int = 64) -> None:
        with self._lock:
            count = max(0, len(self.audit) - keep)
            del self.audit[:count]
            self._audit_base += count

    def settle_task(self) -> None:
        """Only called after the Host checkpoint and State transition are durable."""
        with self._lock:
            self.suspend_mutations()
            self.task_binding = self.task_start_inventory = self._checkpoint_binding = None
            self.task_start_inventory_error = None
            self.test_results.clear()
            self.last_commit_receipt = self.last_no_commit_evidence = None
            self.retire_audit()

    def handle_call(self, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self._handle_call_locked(params)

    def _handle_call_locked(self, params: dict[str, Any]) -> dict[str, Any]:
        if len(self.audit) >= self.audit_limit:
            failure = LoomModeError(ErrorCategory.TRANSPORT_ERROR, "current tool audit limit exceeded; no further effects")
            if not self.poisoned:
                self._poison_error = failure.record
                self.audit.append(ToolAudit(tool=str(params.get("tool")), operation="AUDIT_OVERFLOW",
                    workspace=str(self.workspace), target="", started_at=_now(), ended_at=_now(),
                    result="error", exit_status=None, truncated=False,
                    error_category=ErrorCategory.TRANSPORT_ERROR.value))
            self.poisoned = True
            self.phase = ToolPhase.SUSPENDED
            raise failure
        tool_name = params.get("tool")
        arguments = params.get("arguments")
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "invalid dynamic tool request")
        started = _now()
        target = self._target(tool_name, arguments)
        exit_status: int | None = None
        truncated = False
        try:
            check_execution_control()
            self.assert_usable()
            allowed = READ_ONLY_TOOLS if self.profile == ToolProfile.READ_ONLY_REVIEW else DEVELOPMENT_TOOLS
            if tool_name not in allowed:
                raise LoomModeError(
                    ErrorCategory.TOOL_PERMISSION_ERROR,
                    f"{tool_name} is denied by {self.profile.value}",
                )
            if tool_name in {"loommode_git_stage", "loommode_git_commit"} and self.phase != ToolPhase.COMMIT_AUTHORIZED:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "Promoter acceptance commit gate is closed")
            if tool_name == "loommode_replace_file" and self.phase != ToolPhase.IMPLEMENTATION:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "implementation write phase is closed")
            output = self._dispatch(tool_name, arguments)
            if isinstance(output, dict):
                raw_exit = output.get("exit_code")
                exit_status = raw_exit if isinstance(raw_exit, int) else None
                truncated = bool(output.get("truncated", False) or output.get("diff_truncated", False))
                if output.get("timed_out"):
                    self.timeout_termination = output.get("termination")
                    raise LoomModeError(ErrorCategory.TOOL_TIMEOUT, "host test command timed out",
                                        details={"termination": self.timeout_termination})
            self.audit.append(
                ToolAudit(
                    tool=tool_name,
                    operation=tool_name.removeprefix("loommode_"),
                    workspace=str(self.workspace),
                    target=target,
                    started_at=started,
                    ended_at=_now(),
                    result="success",
                    exit_status=exit_status,
                    truncated=truncated,
                    error_category=None,
                )
            )
            return {"success": True, "output": output}
        except BaseException as exc:
            record = error_record(exc)
            if record.category == ErrorCategory.TOOL_TIMEOUT:
                if not self.poisoned:
                    self._poison_error = record
                self.poisoned = True
                self.phase = ToolPhase.SUSPENDED
            self.audit.append(
                ToolAudit(
                    tool=str(tool_name),
                    operation=str(tool_name).removeprefix("loommode_"),
                    workspace=str(self.workspace),
                    target=target,
                    started_at=started,
                    ended_at=_now(),
                    result="denied" if record.category == ErrorCategory.TOOL_PERMISSION_ERROR else "error",
                    exit_status=exit_status,
                    truncated=truncated,
                    error_category=record.category.value,
                )
            )
            return {"success": False, "output": {"error": record.as_dict()}}

    @staticmethod
    def _target(tool_name: str, arguments: dict[str, Any]) -> str | None:
        if isinstance(arguments.get("path"), str):
            return arguments["path"]
        if isinstance(arguments.get("paths"), list):
            return ",".join(str(item) for item in arguments["paths"])
        if isinstance(arguments.get("test_id"), str):
            return arguments["test_id"]
        if isinstance(arguments.get("message"), str):
            return "authorized-commit-message"
        return None

    def _dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name in {"loommode_git_stage", "loommode_git_commit"} and self.policy.allow_no_dev_change:
            # Optional Tasks cannot turn an existing/unknown user diff into a
            # Task commit by selecting the changed-worktree checkpoint branch.
            require_clean_inventory(self.task_start_inventory, workspace=str(self.workspace),
                                    scope=list(self.policy.writable_paths))
        if tool_name == "loommode_list_files":
            return self.files.list_allowed()
        if tool_name == "loommode_read_file":
            return self.files.read_text(arguments["path"])
        if tool_name == "loommode_replace_file":
            return asdict(
                self.files.replace_text(arguments["path"], arguments["expected"], arguments["replacement"])
            )
        if tool_name == "loommode_run_test":
            test_id = arguments["test_id"]
            before, after, inventory_error = None, None, None
            if self.policy.allow_no_dev_change:
                try:
                    before = self.git.inventory()
                except LoomModeError as exc:
                    inventory_error = str(exc)
            output = self.tests.run(test_id).as_dict()
            if self.policy.allow_no_dev_change:
                try:
                    after = self.git.inventory()
                except LoomModeError as exc:
                    inventory_error = str(exc)
            self.test_results[test_id] = {"result": copy.deepcopy(output), "inventory_before": before,
                                         "inventory_after": after, "inventory_error": inventory_error}
            return output
        if tool_name == "loommode_git_status":
            return self.git.status().as_dict()
        if tool_name == "loommode_git_diff":
            return self.git.diff(cached=False).as_dict()
        if tool_name == "loommode_git_cached_diff":
            return self.git.diff(cached=True).as_dict()
        if tool_name == "loommode_git_stage":
            return self.git.stage(arguments["paths"])
        if tool_name == "loommode_git_commit":
            receipt = self.git.commit(arguments["message"]).as_dict()
            self.last_commit_receipt = receipt
            self.phase = ToolPhase.SUSPENDED
            return receipt
        if tool_name == "loommode_git_log_head":
            return self.git.log_head().as_dict()
        if tool_name == "loommode_git_remotes":
            return {"remotes": self.git.remotes()}
        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "unknown tool is denied")
