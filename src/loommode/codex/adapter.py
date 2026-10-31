"""Formal thin Adapter contract over Codex app-server and bounded host tools."""

from __future__ import annotations

import time
import json
import os
from collections import deque
from functools import wraps
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from loommode.version import __version__
from loommode.tools.filesystem import WorkspaceGuard
from loommode.tools.runtime import BoundedToolRuntime, READ_ONLY_TOOLS, ToolAudit, ToolPhase, ToolPolicy, ToolProfile
from loommode.tools.task_proof import HostTaskProof

from .app_server import AppServerClient, BinaryPolicy
from .context import ContextPurpose, ContextRecord, ContextRegistry, ResourceState
from .errors import ErrorCategory, ErrorRecord, LoomModeError, error_record
from .schema import TASK_RESULT_SCHEMA, StructuredResult, parse_result


BUILTIN_TOOL_CONFIG: dict[str, Any] = {
    "features": {
        "shell_tool": False,
        "unified_exec": False,
        "shell_snapshot": False,
    }
}


def _serialized(method):
    """Reject concurrent allocation/turn/retirement; callbacks reuse this owner."""
    @wraps(method)
    def call(self, *args, **kwargs):
        if not self._lifecycle_lock.acquire(blocking=False):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Adapter operation is active; retirement/renewal refused")
        try:
            return method(self, *args, **kwargs)
        except LoomModeError as exc:
            if exc.record.category in {ErrorCategory.TRANSPORT_ERROR, ErrorCategory.PROCESS_ERROR,
                                       ErrorCategory.DEADLINE_EXCEEDED}:
                self._degraded = "Adapter operation has uncertain effects: " + str(exc)
            raise
        except Exception as exc:
            self._degraded = "Adapter operation failed; inspect owned effects: " + str(exc)
            raise
        finally:
            self._lifecycle_lock.release()
    return call


@dataclass(frozen=True)
class AdapterConfig:
    default_model: str = "gpt-6.1-sol"
    default_reasoning_effort: str = "low"
    default_turn_deadline_seconds: float = 420.0
    rpc_timeout_seconds: float = 90.0
    builtin_shell_enabled: bool = False
    executor_workspace_development: bool = False
    live_context_limit: int = 12

    def __post_init__(self) -> None:
        if self.builtin_shell_enabled:
            raise LoomModeError(
                ErrorCategory.CONFIG_ERROR,
                "global shell toggle is unsupported; select Executor workspace development explicitly",
            )
        if self.default_turn_deadline_seconds <= 0 or self.rpc_timeout_seconds <= 0:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Adapter timeouts must be positive")
        if type(self.live_context_limit) is not int or not 7 <= self.live_context_limit <= 32:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "live Context limit must be 7..32")


@dataclass(frozen=True)
class ContextHandle:
    thread_id: str
    model: str
    reasoning_effort: str
    purpose: str
    tool_profile: str
    runtime_metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AdapterTurnResult:
    success: bool
    thread_id: str
    turn_id: str | None
    terminal_status: str
    structured_result: StructuredResult | dict[str, Any] | None
    tool_audit: tuple[ToolAudit, ...]
    warnings: tuple[str, ...]
    elapsed_ms: int
    error: ErrorRecord | None
    event_methods: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "terminal_status": self.terminal_status,
            "structured_result": (self.structured_result if isinstance(self.structured_result, dict)
                                  else self.structured_result.as_dict() if self.structured_result else None),
            "tool_audit": [item.as_dict() for item in self.tool_audit],
            "warnings": list(self.warnings),
            "elapsed_ms": self.elapsed_ms,
            "error": self.error.as_dict() if self.error else None,
            "event_methods": list(self.event_methods),
        }


class ThinCodexAdapter:
    def __init__(
        self,
        *,
        client: AppServerClient,
        workspace_guard: WorkspaceGuard,
        registry: ContextRegistry | None = None,
        config: AdapterConfig | None = None,
        normal_supply_authority_materials: dict[str, str] | None = None,
    ) -> None:
        self.client = client
        self.workspace_guard = workspace_guard
        self.registry = registry or ContextRegistry()
        self.config = config or AdapterConfig()
        self.normal_supply_authority = dict(normal_supply_authority_materials or {})
        self._runtimes: dict[str, BoundedToolRuntime] = {}
        self._connected = False
        self._closed = False
        self.owner_id = uuid4().hex
        self._lifecycle_lock = RLock()
        self._metadata_lock = RLock()
        self._retiring: set[str] = set()
        self._active_context: str | None = None
        self._degraded: str | None = None
        self._released_count = self._unloaded_count = self._renewed_count = 0
        self._owned: set[str] = set()
        self._retired_resident: set[str] = set()
        self._created_processes = self._exited_processes = 0
        self._counted_process = None
        self._process_receipts: deque[dict[str, Any]] = deque(maxlen=16)
        self.close_receipt: dict[str, Any] | None = None
        self._initialize_metadata: dict[str, Any] = {}
        self._account_metadata: dict[str, Any] = {}
        self._models: dict[str, set[str]] = {}
        self.last_no_tools_start_observation: dict[str, Any] | None = None
        self.client.dynamic_tool_handler = self._handle_dynamic_tool

    @classmethod
    def from_binary(
        cls,
        *,
        binary_policy: BinaryPolicy,
        process_cwd: Path,
        allowed_workspace_roots: tuple[Path, ...],
        registry: ContextRegistry | None = None,
        config: AdapterConfig | None = None,
        without_app_tools_bridge: bool = False,
    ) -> "ThinCodexAdapter":
        if type(without_app_tools_bridge) is not bool:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'bridge isolation must be an explicit boolean')
        client = AppServerClient.from_binary_policy(binary_policy, process_cwd)
        if without_app_tools_bridge:
            client.environment = {key: value for key, value in os.environ.items()
                                  if key.upper() != 'CODEX_APP_TOOLS_PIPE_PATH'}
        guard = WorkspaceGuard(allowed_workspace_roots)
        return cls(client=client, workspace_guard=guard, registry=registry, config=config)

    @_serialized
    def connect(self) -> dict[str, Any]:
        if self._closed or self._degraded:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "closed/degraded Adapter cannot reconnect")
        if self._connected:
            return self.runtime_metadata()
        try:
            self.client.start()
        finally:
            if self.client.process is not None and self.client.process is not self._counted_process:
                self._created_processes += 1
                self._counted_process = self.client.process
        initialized = self.client.initialize(timeout=self.config.rpc_timeout_seconds)
        self._initialize_metadata = {
            "user_agent": initialized.get("userAgent"),
            "platform_family": initialized.get("platformFamily"),
            "platform_os": initialized.get("platformOs"),
        }
        account = self.client.request(
            "account/read",
            {"refreshToken": False},
            timeout=self.config.rpc_timeout_seconds,
        )
        account_value = account.get("account") or {}
        self._account_metadata = {
            "auth_mode": account_value.get("type") or "stored_login_unknown",
            "plan_type": account_value.get("planType"),
            "requires_openai_auth": account.get("requiresOpenaiAuth"),
        }
        catalog = self.client.request(
            "model/list",
            {"limit": 100, "includeHidden": False, "cursor": None},
            timeout=self.config.rpc_timeout_seconds,
        )
        for item in catalog.get("data") or []:
            name = item.get("model") or item.get("id")
            if not isinstance(name, str):
                continue
            efforts = {
                value.get("reasoningEffort")
                for value in item.get("supportedReasoningEfforts") or []
                if isinstance(value, dict) and isinstance(value.get("reasoningEffort"), str)
            }
            default = item.get("defaultReasoningEffort")
            if isinstance(default, str):
                efforts.add(default)
            self._models[name] = {str(value) for value in efforts}
        self._connected = True
        self._assert_model_profile(self.config.default_model, self.config.default_reasoning_effort)
        return self.runtime_metadata()

    @_serialized
    def close(self) -> None:
        if self._active_context or self.client._active_turn:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "cannot close Adapter with an active turn")
        if any(t.is_alive() for t in self.client._callback_threads) or self.client._callback_resource_unknown:
            raise LoomModeError(ErrorCategory.PROCESS_ERROR, "in-flight host callback prevents runtime retirement/release")
        if self.close_receipt and self.close_receipt.get("released"):
            return
        with self._metadata_lock:
            self._closed = True
            self._connected = False
        try:
            for thread_id in tuple(self._owned):
                record = self.registry.get(thread_id)
                if record.owner_id != self.owner_id:
                    raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Context ownership changed before retirement")
                if record.resource_state != ResourceState.RELEASED:
                    self.registry.resource(thread_id, ResourceState.RETIRED)
                    self.registry.resource(thread_id, ResourceState.RELEASABLE)
            self.client.close()
            receipt = self.client.close_receipt
            if not receipt or not receipt.get("released"):
                raise LoomModeError(ErrorCategory.PROCESS_ERROR, "owned app-server release was not proved")
            receipt = {**receipt, "adapter_owner_id": self.owner_id,
                       "process_epoch": self._created_processes, "context_release_count": len(self._owned)}
            # Process exit is a distinct release proof, not a claim of per-thread
            # unsubscribe, archival, deletion, or global Codex cleanup.
            for thread_id in tuple(self._owned):
                record = self.registry.get(thread_id)
                if record.owner_id != self.owner_id:
                    raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Context ownership changed before close")
                with self._metadata_lock:
                    self.registry.resource(thread_id, ResourceState.RELEASED,
                                           receipt={"proof": "OWNED_PROCESS_EXIT", **receipt})
                    self._released_count += 1
                    self._runtimes.pop(thread_id, None)
                    self._owned.remove(thread_id)
                    self._retired_resident.discard(thread_id)
            self.close_receipt = dict(receipt)
            if receipt.get("pid") is not None:
                self._exited_processes += 1
                self._process_receipts.append(dict(receipt))
        except BaseException as exc:
            self._degraded = "Adapter close is unproved: " + str(exc)
            raise

    def health(self) -> dict[str, Any]:
        # Status takes only a short metadata lock, never the model/RPC operation lock.
        with self._metadata_lock:
            return self._health_snapshot()

    def cancel_active(self, generation: int | None = None) -> bool:
        # Deliberately bypass the lifecycle/RPC locks held by run_turn.
        return self.client.cancel_active(generation)

    def _health_snapshot(self) -> dict[str, Any]:
        reasons = [reason for reason in (self._degraded, self.client._transport_failure) if reason]
        if not self.client._active_turn and any(t.is_alive() for t in self.client._callback_threads):
            reasons.append("host callback stop is unproved; Context and Writer release forbidden")
        if self.client._callback_resource_unknown:
            reasons.append("host callback process/tree/IO release is unproved")
        process = self.client.process
        alive = bool(process and process.poll() is None)
        if self._connected and not self._closed and not alive:
            reasons.append("connected Adapter child exited unexpectedly; no restart/replay")
        for thread_id in self._owned:
            record = self.registry.get(thread_id)
            if record.owner_id != self.owner_id or (
                    thread_id not in self._runtimes and thread_id not in self._retired_resident):
                reasons.append("owned Context/runtime mismatch")
            if (record.resource_state in {ResourceState.RETIRED, ResourceState.RELEASABLE, ResourceState.RELEASED}
                    and thread_id in self._runtimes and thread_id not in self._retiring and not self._closed):
                reasons.append("retired/released Context still has a live runtime")
            if thread_id in self._retired_resident and record.resource_state != ResourceState.RELEASABLE and not self._closed:
                reasons.append("retired resident Context lifecycle mismatch")
            if thread_id in self._runtimes and self._runtimes[thread_id].poisoned:
                reasons.append("owned tool runtime is poisoned")
        if len(self._owned) > self.config.live_context_limit:
            reasons.append("live Context limit exceeded")
        return {"scope": "THIS_ADAPTER_OWNED_PROCESS_AND_CONTEXTS", "owner_id": self.owner_id,
                "status": "DEGRADED" if reasons else "RELEASED" if self._closed and not self._owned else
                          "CLOSING" if self._closed else "RETIRING" if self._retiring else "HEALTHY",
                "connected": self._connected, "closed": self._closed, "active_context": self._active_context,
                "live_contexts": len(self._owned), "context_limit": self.config.live_context_limit,
                "live_tool_runtimes": len(self._runtimes), "retired_resident_contexts": len(self._retired_resident),
                "reusable_contexts": len(self._runtimes), "resident_contexts_upper_bound": len(self._owned),
                "process_epoch": self._created_processes,
                "created_processes": self._created_processes, "exited_processes": self._exited_processes,
                "owned_process_count": self._created_processes - self._exited_processes,
                "alive_process_count": int(alive),
                "process_receipts": list(self._process_receipts),
                "states": {state.value: sum(r.resource_state == state for r in self.registry.all()
                                            if r.owner_id == self.owner_id) for state in ResourceState},
                "released_count": self._released_count, "resident_unload_count": self._unloaded_count,
                "renewed_count": self._renewed_count, "reasons": list(dict.fromkeys(reasons)),
                "transport": self.client.transport_metadata(), "close_receipt": self.close_receipt}

    def assert_healthy(self) -> None:
        health = self.health()
        if health["reasons"] or self._closed:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "resource health blocks new allocation/dispatch",
                                details=health)
        self.client.assert_usable()

    @_serialized
    def protect_context(self, thread_id: str, reason: str | None) -> None:
        self._runtime(thread_id)
        self.registry.resource(thread_id, ResourceState.RETAINED, protection=reason)

    @_serialized
    def release_context(self, thread_id: str, *, reason: str) -> dict[str, Any]:
        if self._active_context or self.client._active_turn:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "pending native turn prevents Context retirement")
        record = self.registry.get(thread_id)
        if record.owner_id != self.owner_id:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "cannot release an unowned Context")
        if record.resource_state == ResourceState.RELEASED:
            return dict(record.release_receipt or {})
        if thread_id in self._retired_resident:
            return dict(record.release_receipt or {})
        self._runtime(thread_id)
        if record.protection:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "protected Context cannot be retired: " + record.protection)
        with self._metadata_lock:
            self._retiring.add(thread_id)
            self.registry.resource(thread_id, ResourceState.RETIRED)
            self.registry.resource(thread_id, ResourceState.RELEASABLE)
        try:
            receipt = {"reason": reason, "process_epoch": self._created_processes,
                       **self.client.release_thread(thread_id,
                        timeout=min(15.0, self.config.rpc_timeout_seconds))}
            with self._metadata_lock:
                self.registry.resource(thread_id, ResourceState.RELEASED if receipt["released"] else
                                       ResourceState.RELEASABLE, receipt=receipt)
                del self._runtimes[thread_id]
                if receipt["released"]:
                    self._owned.remove(thread_id)
                    self._released_count += 1
                else:
                    self._retired_resident.add(thread_id)
                self._unloaded_count += int(receipt["new_unload"])
            return receipt
        except BaseException as exc:
            self._degraded = "Context resident release failed: " + str(exc)
            raise
        finally:
            with self._metadata_lock:
                self._retiring.discard(thread_id)

    @_serialized
    def settle_task(self, thread_id: str) -> None:
        self._runtime(thread_id).settle_task()
        self.protect_context(thread_id, None)

    def record_renewal(self) -> None:
        self._renewed_count += 1

    @property
    def process_renewal_mode(self) -> bool:
        # Installed native schema advertises unsubscribe, but E2 native evidence
        # shows it keeps residency. A fake peer cannot verify native unloading.
        return self.client.binary_info is not None

    @property
    def renewal_due(self) -> bool:
        return bool(self._retired_resident)

    @_serialized
    def renew_process(self) -> dict[str, Any]:
        self._require_connected()
        if self._active_context or any(self.registry.get(key).protection for key in self._owned):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "native renewal would discard protected current evidence")
        previous_client = self.client
        self.close()  # Verified whole-owned-child exit precedes the next process.
        previous = dict(self.close_receipt or {})
        self.client = previous_client.replacement()
        self.client.dynamic_tool_handler = self._handle_dynamic_tool
        self._closed = False
        self.close_receipt = None
        self._models.clear()
        try:
            self.connect()
        except BaseException as exc:
            self._degraded = "renewed app-server startup failed: " + str(exc)
            try:
                self.close()
            finally:
                raise
        return {"proof": "OWNED_PROCESS_RENEWAL", "previous_process": previous,
                "current_pid": self.client.process.pid, "current_process_epoch": self._created_processes,
                "resident_threads_resumed": False,
                "durable_thread_history": "UNCHANGED", "permissions_expanded": False}

    def __enter__(self) -> "ThinCodexAdapter":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def runtime_metadata(self) -> dict[str, Any]:
        binary = self.client.binary_info
        return {
            "adapter_version": __version__,
            "interface": "codex app-server --stdio",
            "binary_path": binary.path if binary else None,
            "codex_version": binary.version if binary else "test-double",
            "binary_tested": binary.tested if binary else False,
            "builtin_shell_enabled": self.native_workspace_development,
            "codex_config_override": BUILTIN_TOOL_CONFIG,
            "cross_process_resume": "NOT_VERIFIED",
            "interrupt": "BOUNDED_PROTOCOL_SUPPORTED" if "turn/interrupt" in self.client.protocol_operations else "UNKNOWN_VERSION",
            "crash_recovery": "NOT_VERIFIED",
            "builtin_shell": "DEVELOPMENT_ONLY" if self.config.executor_workspace_development else "DISABLED",
            "executor_workspace_development": self.config.executor_workspace_development,
            "dynamic_tools": "EXPERIMENTAL_VERIFIED_CURRENT_VERSION",
            **self._initialize_metadata,
            **self._account_metadata,
        }

    @property
    def native_workspace_development(self) -> bool:
        return self.config.executor_workspace_development

    def preflight_task_policy(self, policy: ToolPolicy, task_binding: dict[str, Any] | None = None) -> None:
        policy.preflight()
        ref = policy.normal_supply_authority_ref
        if ref is None:
            return
        if not self.native_workspace_development or policy.profile != ToolProfile.BOUNDED_DEVELOPMENT:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'normal supply requires the native bounded implementation entry')
        if ref not in self.normal_supply_authority or not task_binding:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'normal supply lacks actual Host authority/current Task binding')
        def unique(pairs):
            value = dict(pairs)
            if len(value) != len(pairs):
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'duplicate supply authority fields')
            return value
        try:
            value = json.loads(self.normal_supply_authority[ref], object_pairs_hook=unique)
        except (ValueError, TypeError) as exc:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'normal supply authority must be explicit JSON') from exc
        fields = {'origin', 'project', 'stage_id', 'task_id', 'workspace', 'intent_ref', 'final_ref', 'scope', 'reason'}
        if (not isinstance(value, dict) or set(value) != fields or value['origin'] != 'OWNER_NORMAL_SUPPLY_AUTHORIZATION'
                or any(value[key] != task_binding.get(key) for key in ('project', 'stage_id', 'task_id', 'intent_ref', 'final_ref', 'scope'))
                or not value['intent_ref'] or not value['final_ref']
                or value['workspace'] != str(policy.workspace.resolve(strict=True))
                or not isinstance(value['scope'], list) or not all(isinstance(p, str) for p in value['scope'])
                or not set(policy.writable_paths).issubset(value['scope'])
                or not isinstance(value['reason'], str) or not value['reason'].strip()):
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'normal supply authority differs from actual Intent/Final/scope')

    def preflight_context(self, *, workspace: Path, model: str | None, reasoning_effort: str | None,
                          purpose: ContextPurpose, tool_policy: ToolPolicy, thread_id: str | None = None,
                          task_binding: dict[str, Any] | None = None, required_phase: ToolPhase | None = None) -> None:
        self._require_connected()
        canonical = self.workspace_guard.canonical_workspace(workspace)
        expected = ToolProfile.READ_ONLY_REVIEW if purpose in {ContextPurpose.FRESH_REVIEW, ContextPurpose.READ_ONLY_ROLE} else ToolProfile.BOUNDED_DEVELOPMENT
        if tool_policy.workspace.resolve(strict=True) != canonical or tool_policy.profile != expected:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'context workspace/purpose/tool policy mismatch')
        if required_phase == ToolPhase.COMMIT_AUTHORIZED:
            tool_policy.preflight(check_tests=False)  # Host checkpoint does not invoke a model or rerun fixed tests.
        else:
            self._assert_model_profile(model or self.config.default_model, reasoning_effort or self.config.default_reasoning_effort)
            self.preflight_task_policy(tool_policy, task_binding)
        self._native_setup(canonical, tool_policy.profile)
        if thread_id:
            record, runtime = self.registry.get(thread_id), self._runtime(thread_id)
            runtime.assert_usable()
            if required_phase is not None and runtime.phase != required_phase:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'required current invocation phase is not authorized')
            if record.workspace != str(canonical) or runtime.profile != expected or record.tool_profile != expected.value:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'cached context workspace/profile mismatch')
            tool_policy.preflight(bound=replace(runtime.stage_policy, profile=runtime.profile),
                                  check_tests=required_phase != ToolPhase.COMMIT_AUTHORIZED)
        elif len(self._owned) >= self.config.live_context_limit:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'Context allocation would exceed retained live limit')

    def _native_setup(self, workspace: Path, profile: ToolProfile) -> dict[str, Any]:
        if not self.native_workspace_development:
            return {"sandbox": "read-only", "environments": [], "config": BUILTIN_TOOL_CONFIG,
                    "developerInstructions": "Native execution is disabled. Use the supplied LoomMode tools within their declared workspace and targets. Return the required output schema."}
        if workspace != self.client.cwd:
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR,
                                "native server process cwd must equal the authorized project workspace")
        development = profile == ToolProfile.BOUNDED_DEVELOPMENT
        setup = {"sandbox": "workspace-write" if development else "read-only",
                 "config": {"features": {"shell_tool": development, "unified_exec": development,
                                          "shell_snapshot": False, "multi_agent": False, "multi_agent_v2": False},
                            "sandbox_workspace_write": {"writable_roots": [], "network_access": False,
                                                        "exclude_slash_tmp": True, "exclude_tmpdir_env_var": True}},
                 "developerInstructions": (
                     "Execute the approved Task autonomously within its declared project workspace and scope. Implement and test; do not modify outside the workspace, push, merge or release. Ordinary local dependency/fixture supply requires the current Task's explicit Host authorization. It does not grant credential access, paid services, production, remote modification or Authority change; preserve their explicit authorization/Gates. Do not stage or commit; the Host handles Task commit after acceptance. Return the required output schema."
                     if development else
                     "Read-only role/review. Inspect supplied materials and actual code with authorized read/test tools. Return content; the Host saves artifacts. Findings grant no repair permission. Do not modify, stage, commit, push, merge or release.")}
        if not development:
            setup["environments"] = []
        return setup

    def _no_tools_config(self, workspace: Path, setup: dict[str, Any], effort: str) -> dict[str, Any]:
        """Disable the effective named MCP/plugin servers without reading secrets out.

        New opt-in path requires current config/read + per-thread MCP inventory;
        unsupported older servers fail closed, while ordinary contexts are unchanged.
        """
        try:
            value = self.client.request('config/read', {'cwd': str(workspace), 'includeLayers': False},
                                        timeout=self.config.rpc_timeout_seconds)['config']
            servers, plugins = value.get('mcp_servers', {}), value.get('plugins', {})
            if not isinstance(servers, dict) or not isinstance(plugins, dict):
                raise ValueError('invalid configuration shape')
            config = {**setup.get('config', {}), 'web_search': 'disabled', 'project_doc_max_bytes': 0,
                      'model_reasoning_effort': effort,
                      'features': {**setup.get('config', {}).get('features', {}),
                                   'shell_tool': False, 'unified_exec': False, 'shell_snapshot': False,
                                   'multi_agent': False, 'multi_agent_v2': False, 'apps': False},
                      'mcp_servers': {name: {'enabled': False} for name in servers}}
            plugin_overrides = {}
            for name, settings in plugins.items():
                if not isinstance(settings, dict):
                    raise ValueError('invalid plugin configuration')
                plugin_servers = settings.get('mcp_servers', {})
                if not isinstance(plugin_servers, dict):
                    raise ValueError('invalid plugin server configuration')
                plugin_overrides[name] = {'enabled': False, 'mcp_servers': {
                    server: {'enabled': False} for server in plugin_servers}}
            config['plugins'] = plugin_overrides
            return {**setup, 'sandbox': 'read-only', 'environments': [], 'config': config,
                    'developerInstructions': 'No tools are permitted. Use only the explicit prompt; return its JSON schema.'}
        except Exception:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'cannot verify effective no-tools configuration') from None

    def _assert_complete_no_tools_qualification(self) -> None:
        # No native binary/version/launch combination currently has independently
        # verified complete tool-surface isolation. The observed desktop tool
        # namespaces are not MCP and survive a bridge-free launch. No user profile
        # or environment flag can admit this production path.
        raise LoomModeError(ErrorCategory.CONFIG_ERROR,
                            'native no-tools complete tool-surface qualification is UNVERIFIED')

    def _assert_no_mcp_tools(self, thread_id: str) -> None:
        cursor, seen = None, set()
        try:
            for _ in range(32):
                params = {'threadId': thread_id, 'limit': 100, 'detail': 'toolsAndAuthOnly'}
                if cursor:
                    params['cursor'] = cursor
                value = self.client.request('mcpServerStatus/list', params, timeout=self.config.rpc_timeout_seconds)
                rows = value['data']
                if not isinstance(rows, list) or any(not isinstance(row, dict) or row.get('tools') != {}
                        or row.get('runtimeStatus') != 'disabled' for row in rows):
                    raise ValueError('MCP server remains accessible')
                cursor = value.get('nextCursor')
                if cursor is None:
                    return
                if not isinstance(cursor, str) or not cursor or cursor in seen:
                    raise ValueError('invalid inventory cursor')
                seen.add(cursor)
            raise ValueError('inventory exceeds bound')
        except Exception:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'no-tools thread MCP inventory is not verified empty/disabled') from None

    @_serialized
    def start_context(
        self,
        *,
        workspace: Path,
        model: str | None,
        reasoning_effort: str | None,
        purpose: ContextPurpose,
        tool_policy: ToolPolicy,
        activity_metadata: dict[str, str] | None = None,
        ephemeral: bool = False,
        task_policy: ToolPolicy | None = None,
        task_binding: dict[str, Any] | None = None,
        no_tools: bool = False,
    ) -> ContextHandle:
        if type(no_tools) is not bool or (no_tools and (purpose == ContextPurpose.DEVELOPMENT
                or tool_policy.readable_paths or tool_policy.writable_paths or tool_policy.test_specs
                or tool_policy.stageable_paths or tool_policy.commit_messages)):
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'no-tools context requires an empty read-only policy')
        if no_tools:
            self.last_no_tools_start_observation = None
            self._assert_complete_no_tools_qualification()
            if getattr(self.client, 'launch_app_tools_bridge_present', None) is not False:
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'no-tools requires a verified bridge-free process launch')
        if task_policy:
            tool_policy.preflight(check_tests=False)
            task_policy.preflight(bound=tool_policy)
        self.preflight_context(workspace=workspace, model=model, reasoning_effort=reasoning_effort,
                               purpose=purpose, tool_policy=task_policy or tool_policy, task_binding=task_binding)
        if len(self._owned) >= self.config.live_context_limit:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Context allocation would exceed retained live limit")
        canonical = self.workspace_guard.canonical_workspace(workspace)
        policy_workspace = tool_policy.workspace.resolve(strict=True)
        if policy_workspace != canonical:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "tool policy workspace does not match context")
        expected_profile = (
            ToolProfile.READ_ONLY_REVIEW
            if purpose in {ContextPurpose.FRESH_REVIEW, ContextPurpose.READ_ONLY_ROLE}
            else ToolProfile.BOUNDED_DEVELOPMENT
        )
        if tool_policy.profile != expected_profile:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "context purpose and tool profile do not match")
        chosen_model = model or self.config.default_model
        chosen_effort = reasoning_effort or self.config.default_reasoning_effort
        self._assert_model_profile(chosen_model, chosen_effort)
        runtime = BoundedToolRuntime(tool_policy)
        if task_policy:
            runtime.configure_task(task_policy, task_binding=task_binding)
        setup = self._native_setup(canonical, tool_policy.profile)
        dynamic_tools = runtime.dynamic_tools()
        if self.native_workspace_development:
            dynamic_tools = [tool for tool in dynamic_tools if tool["name"] in READ_ONLY_TOOLS]
        if no_tools:
            dynamic_tools = []
            activity_metadata = {**(activity_metadata or {}), 'no_tools': 'true'}
            setup = self._no_tools_config(canonical, setup, chosen_effort)
        response = self.client.request(
            "thread/start",
            {
                "cwd": str(canonical),
                "runtimeWorkspaceRoots": [str(canonical)],
                "model": chosen_model,
                "allowProviderModelFallback": False,
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "ephemeral": ephemeral,
                "threadSource": "loommode-thin-adapter",
                "dynamicTools": dynamic_tools,
                **setup,
            },
            timeout=self.config.rpc_timeout_seconds,
        )
        thread = response.get("thread") or {}
        thread_id = thread.get("id")
        if not isinstance(thread_id, str) or not thread_id:
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "thread/start did not return an opaque id")
        actual_model = response.get("model") or chosen_model
        actual_effort = response.get("reasoningEffort") or chosen_effort
        with self._metadata_lock:
            self.registry.create(
                thread_id=thread_id, purpose=purpose, workspace=canonical,
                model=str(actual_model), reasoning_effort=str(actual_effort),
                tool_profile=tool_policy.profile.value,
                codex_version=self.runtime_metadata()["codex_version"],
                activity_metadata=activity_metadata, owner_id=self.owner_id)
            self._runtimes[thread_id] = runtime
            self._owned.add(thread_id)
        if no_tools:
            self.last_no_tools_start_observation = {
                'context_ref': thread_id, 'requested_model': chosen_model, 'requested_effort': chosen_effort,
                'effective_model': (response['model'] if isinstance(response.get('model'), str)
                                    and len(response['model']) <= 160 else None),
                'effective_effort': (response['reasoningEffort'] if isinstance(response.get('reasoningEffort'), str)
                                     and len(response['reasoningEffort']) <= 160 else None),
                'launch_bridge_present': False}
            try:
                if response.get('model') != chosen_model or response.get('reasoningEffort') != chosen_effort:
                    raise LoomModeError(ErrorCategory.MODEL_ERROR, 'no-tools effective model/reasoning differs from requested')
                self._assert_no_mcp_tools(thread_id)
            except Exception as original:
                try:
                    self.release_context(thread_id, reason='NO_TOOLS_ALLOCATION_REJECTED')
                    self.last_no_tools_start_observation['cleanup_status'] = 'RELEASED'
                except Exception:
                    self.last_no_tools_start_observation['cleanup_status'] = 'UNVERIFIED'
                raise original from None
        return ContextHandle(
            thread_id=thread_id,
            model=str(actual_model),
            reasoning_effort=str(actual_effort),
            purpose=purpose.value,
            tool_profile=tool_policy.profile.value,
            runtime_metadata=self.runtime_metadata(),
        )

    @_serialized
    def resume_context(
        self,
        *,
        thread_id: str,
        workspace: Path,
        tool_profile: ToolProfile,
    ) -> ContextHandle:
        self._require_connected()
        if (self.registry.get(thread_id).activity_metadata or {}).get('no_tools') == 'true':
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'no-tools contexts are one-shot and cannot resume')
        record = self.registry.get(thread_id)
        canonical = self.workspace_guard.canonical_workspace(workspace)
        if str(canonical) != record.workspace:
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "resume workspace does not match context")
        runtime = self._runtime(thread_id)
        runtime.policy.preflight(check_tests=runtime.phase != ToolPhase.COMMIT_AUTHORIZED)
        if runtime.phase != ToolPhase.COMMIT_AUTHORIZED:
            self.preflight_task_policy(runtime.policy, runtime.task_binding)
        if runtime.profile != tool_profile or record.tool_profile != tool_profile.value:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "resume tool profile does not match context")
        setup = self._native_setup(canonical, runtime.profile)
        # Pinned thread/resume has no environments field; turn/start controls it.
        setup.pop("environments", None)
        response = self.client.request(
            "thread/resume",
            {
                "threadId": thread_id,
                # Only the reviewed 0.160.1 schema proves this optional field.
                **({"excludeTurns": True} if getattr(self.client.binary_info, "version", None) == "0.160.1" else {}),
                "cwd": str(canonical),
                "runtimeWorkspaceRoots": [str(canonical)],
                "model": record.model,
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                **setup,
            },
            timeout=self.config.rpc_timeout_seconds,
        )
        returned_id = (response.get("thread") or {}).get("id")
        if returned_id != thread_id:
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "thread/resume returned a different context id")
        return ContextHandle(
            thread_id=thread_id,
            model=str(response.get("model") or record.model),
            reasoning_effort=str(response.get("reasoningEffort") or record.reasoning_effort),
            purpose=record.purpose.value,
            tool_profile=record.tool_profile,
            runtime_metadata=self.runtime_metadata(),
        )

    @_serialized
    def authorize_development(self, thread_id: str) -> ContextRecord:
        runtime = self._runtime(thread_id)
        record = self.registry.authorize_development(
            thread_id,
            ToolProfile.BOUNDED_DEVELOPMENT.value,
        )
        runtime.set_profile(ToolProfile.BOUNDED_DEVELOPMENT)
        self.registry.resource(thread_id, ResourceState.RETAINED, protection="CURRENT_TASK_BASELINE")
        return record

    @_serialized
    def run_turn(
        self,
        *,
        thread_id: str,
        prompt: str,
        model: str | None = None,
        reasoning_effort: str | None = None,
        tool_profile: ToolProfile,
        deadline_seconds: float | None = None,
        output_schema: dict[str, Any] | None = None,
        result_validator: Callable[[str], dict[str, Any]] | None = None,
    ) -> AdapterTurnResult:
        started = time.monotonic()
        self.last_safe_observation = {'stage':'transport'}
        runtime = self._runtime(thread_id)
        record = self.registry.get(thread_id)
        if runtime.profile != tool_profile or record.tool_profile != tool_profile.value:
            return self._failure_result(
                thread_id=thread_id,
                started=started,
                error=LoomModeError(ErrorCategory.CONFIG_ERROR, "turn tool profile does not match context"),
            )
        chosen_model = model or record.model
        chosen_effort = reasoning_effort or record.reasoning_effort
        audit_index = runtime.audit_index()
        event_methods: tuple[str, ...] = ()
        turn_id = None
        completed_format_failure = False
        self._active_context = thread_id
        self.registry.resource(thread_id, ResourceState.ACTIVE, protection=record.protection)
        try:
            runtime.assert_usable()
            runtime.policy.preflight()
            if (output_schema is None) != (result_validator is None):
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, "custom schema requires local validator")
            self._assert_model_profile(chosen_model, chosen_effort)
            if (record.activity_metadata or {}).get('no_tools') == 'true':
                if runtime.profile != ToolProfile.READ_ONLY_REVIEW:
                    raise LoomModeError(ErrorCategory.CONFIG_ERROR, 'no-tools context lost read-only profile')
                self._assert_no_mcp_tools(thread_id)
            native_development = (self.native_workspace_development
                                  and runtime.profile == ToolProfile.BOUNDED_DEVELOPMENT
                                  and runtime.phase == ToolPhase.IMPLEMENTATION)
            normal_supply = native_development and runtime.policy.normal_supply_authority_ref is not None
            if normal_supply:
                self.preflight_task_policy(runtime.policy, runtime.task_binding)
            sandbox_policy = ({"type": "workspaceWrite", "writableRoots": [str(runtime.workspace)],
                               "networkAccess": normal_supply, "excludeSlashTmp": True, "excludeTmpdirEnvVar": True}
                              if native_development else {"type": "readOnly", "networkAccess": False})
            environments = ([{"environmentId": "local", "cwd": str(runtime.workspace),
                              "runtimeWorkspaceRoots": [str(runtime.workspace)]}]
                            if native_development else [])
            raw = self.client.run_turn(
                thread_id=thread_id,
                prompt=prompt,
                model=chosen_model,
                effort=chosen_effort,
                output_schema=output_schema if output_schema is not None else TASK_RESULT_SCHEMA,
                deadline_seconds=deadline_seconds if deadline_seconds is not None else self.config.default_turn_deadline_seconds,
                sandbox_policy=sandbox_policy,
                environments=environments,
            )
            terminal = raw.terminal
            import hashlib
            final = terminal.final_text
            self.last_safe_observation.update(stage='terminal_publication', terminal_status=terminal.status,
                thread_correlated=getattr(terminal,'thread_id',None)==thread_id,
                turn_correlated=isinstance(terminal.turn_id,str) and bool(terminal.turn_id),
                final_present=isinstance(final,str) and bool(final),final_length=len(final) if isinstance(final,str) else 0,
                final_sha256=hashlib.sha256(final.encode()).hexdigest() if isinstance(final,str) else None)
            if terminal.thread_id!=thread_id or not isinstance(terminal.turn_id,str) or not terminal.turn_id:
                raise LoomModeError(ErrorCategory.TRANSPORT_ERROR,'terminal correlation rejected')
            turn_id = terminal.turn_id
            event_methods = terminal.event_methods
            self.registry.record_turn(thread_id, terminal.turn_id, terminal.status)
            audit = runtime.audit_since(audit_index)
            runtime.assert_usable()
            if terminal.status == "interrupted":
                raise LoomModeError(ErrorCategory.TURN_INTERRUPTED, "Codex turn was interrupted")
            if terminal.status != "completed":
                raise LoomModeError(
                    ErrorCategory.TURN_FAILED,
                    "Codex turn did not complete successfully",
                    details={"status": terminal.status, "turn_error": terminal.error},
                )
            if runtime.has_fatal_failure_since(audit_index):
                category = next(
                    ErrorCategory(item.error_category)
                    for item in audit
                    if item.error_category is not None
                )
                raise LoomModeError(category, "a bounded host tool call failed")
            self.last_safe_observation['stage']='parser_schema'
            try:
                structured = result_validator(terminal.final_text) if result_validator else parse_result(terminal.final_text)
            except (TypeError, ValueError) as exc:
                # A local format problem is correctable only while the actual
                # completed turn and all its owning resources remain trusted.
                self._assert_result_publication(runtime)
                completed_format_failure = True
                self.last_safe_observation['schema_verdict']='FAIL'
                raise LoomModeError(ErrorCategory.STRUCTURED_OUTPUT_ERROR, "local result validation failed",
                                    details={"validation_error": str(exc)}) from exc
            self.last_safe_observation.update(stage='terminal_publication',schema_verdict='PASS')
            # Readers can poison transport while local validation is running.
            # Check known failures at publication, after validation, not only
            # when the native terminal was received. Future events remain async.
            self._assert_result_publication(runtime)
            return AdapterTurnResult(
                success=True,
                thread_id=thread_id,
                turn_id=terminal.turn_id,
                terminal_status=terminal.status,
                structured_result=structured,
                tool_audit=audit,
                warnings=self.client.transport_warnings(),
                elapsed_ms=raw.elapsed_ms,
                error=None,
                event_methods=terminal.event_methods,
            )
        except BaseException as exc:
            self.last_safe_observation['category']=error_record(exc).category.value
            diagnosis = self.client.last_turn_diagnostics
            if diagnosis and diagnosis.get("thread_id") == thread_id:
                turn_id = diagnosis.get("turn_id")
                event_methods = tuple(diagnosis.get("event_methods", ()))
                status = (diagnosis.get("terminal_evidence") or {}).get("status", "unknown")
                self.registry.record_turn(thread_id, turn_id, status)
                self.last_safe_observation['transport_timing'] = diagnosis.get('transport_timing')
            if error_record(exc).category in {ErrorCategory.DEADLINE_EXCEEDED, ErrorCategory.PROCESS_ERROR,
                                              ErrorCategory.TRANSPORT_ERROR, ErrorCategory.TOOL_TIMEOUT}:
                self._degraded = "turn effects/completion are uncertain: " + str(exc)
            return self._failure_result(
                thread_id=thread_id,
                started=started,
                error=exc,
                audit=runtime.audit_since(audit_index),
                event_methods=event_methods,
                turn_id=turn_id,
                completed_format_failure=completed_format_failure,
            )
        finally:
            self._active_context = None
            self.registry.resource(thread_id, ResourceState.RETAINED, protection=record.protection)
            # Return values capture immutable tuples before pruning diagnostics.
            if not any(t.is_alive() for t in self.client._callback_threads):
                runtime.retire_audit()

    @_serialized
    def configure_task(self, thread_id: str, policy: ToolPolicy, *, task_binding: dict[str, Any] | None = None) -> None:
        self.preflight_task_policy(policy, task_binding)
        self._runtime(thread_id).configure_task(policy, task_binding=task_binding)
        self.protect_context(thread_id, "CURRENT_TASK_BASELINE")

    @_serialized
    def authorize_commit(self, thread_id: str, *, acceptance_ref: str, report_ref: str,
                         checkpoint_binding: dict[str, Any] | None = None) -> None:
        self._runtime(thread_id).authorize_commit(acceptance_ref=acceptance_ref, report_ref=report_ref,
                                                  checkpoint_binding=checkpoint_binding)

    @_serialized
    def suspend_mutations(self, thread_id: str) -> None:
        # Fencing is allowed after poison; it cannot allocate or execute a tool.
        record = self.registry.get(thread_id)
        if record.owner_id != self.owner_id or thread_id not in self._runtimes:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "cannot fence an unowned/released runtime")
        self._runtimes[thread_id].suspend_mutations()

    def commit_receipt(self, thread_id: str) -> dict[str, Any] | None:
        return self._runtime(thread_id).last_commit_receipt

    def task_proof(self, thread_id: str) -> HostTaskProof:
        """Facade over this Adapter's actual runtime; no new baseline or thread."""
        return HostTaskProof(self._runtime(thread_id), context_ref=thread_id, backend="codex_app_server")

    @_serialized
    def host_no_dev_change(self, thread_id: str, *, binding: dict[str, Any]) -> dict[str, Any]:
        return self.task_proof(thread_id).no_dev_change(binding)

    @_serialized
    def verify_no_dev_change(self, thread_id: str, *, evidence: dict[str, Any], binding: dict[str, Any]) -> None:
        self.task_proof(thread_id).verify_no_dev_change(evidence, binding)

    @_serialized
    def host_checkpoint(self, thread_id: str, *, paths: list[str], message: str,
                        binding: dict[str, Any] | None) -> dict[str, Any]:
        """Native disposition selection uses the same Host proof as legacy."""
        runtime = self._runtime(thread_id)
        runtime.assert_usable()
        if not self.native_workspace_development or runtime.phase != ToolPhase.COMMIT_AUTHORIZED:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "accepted Host checkpoint phase required")
        return self.task_proof(thread_id).checkpoint(paths=paths, message=message, binding=binding)

    @_serialized
    def host_exact_commit(self, thread_id: str, *, paths: list[str], message: str) -> dict[str, Any]:
        """Host-only phase; never registered as a model tool in native mode."""
        runtime = self._runtime(thread_id)
        runtime.assert_usable()
        if not self.native_workspace_development or runtime.phase != ToolPhase.COMMIT_AUTHORIZED:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "accepted Host commit phase required")
        return self.task_proof(thread_id).exact_commit(paths=paths, message=message)

    def _assert_result_publication(self, runtime):
        runtime.assert_usable()
        self.client.assert_usable()
        process = self.client.process
        if process is None or process.poll() is not None:
            raise LoomModeError(ErrorCategory.PROCESS_ERROR,
                                "app-server exited before result publication",
                                details={"exit_code": process.poll() if process else None})
        self.assert_healthy()

    def _failure_result(
        self,
        *,
        thread_id: str,
        started: float,
        error: BaseException,
        audit: tuple[ToolAudit, ...] = (),
        event_methods: tuple[str, ...] = (),
        turn_id: str | None = None,
        completed_format_failure: bool = False,
    ) -> AdapterTurnResult:
        record = error_record(error)
        terminal_status = {
            ErrorCategory.TURN_INTERRUPTED: "interrupted",
            ErrorCategory.DEADLINE_EXCEEDED: "deadline_exceeded",
        }.get(record.category, "failed")
        if completed_format_failure and record.category == ErrorCategory.STRUCTURED_OUTPUT_ERROR:
            terminal_status = "completed"
        return AdapterTurnResult(
            success=False,
            thread_id=thread_id,
            turn_id=turn_id,
            terminal_status=terminal_status,
            structured_result=None,
            tool_audit=audit,
            warnings=self.client.transport_warnings(),
            elapsed_ms=round((time.monotonic() - started) * 1000),
            error=record,
            event_methods=event_methods,
        )

    def _handle_dynamic_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        thread_id = params.get("threadId")
        if not isinstance(thread_id, str):
            raise LoomModeError(ErrorCategory.TRANSPORT_ERROR, "dynamic tool call omitted threadId")
        runtime = self._runtime(thread_id)
        if (self.registry.get(thread_id).activity_metadata or {}).get('no_tools') == 'true':
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'no-tools Decision context denies tool calls')
        runtime.assert_usable()
        if self.native_workspace_development and params.get("tool") not in READ_ONLY_TOOLS:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "model Host mutation tools are disabled in native mode")
        return runtime.handle_call(params)

    def _runtime(self, thread_id: str) -> BoundedToolRuntime:
        self._require_connected()
        record = self.registry.get(thread_id)
        if record.owner_id != self.owner_id or thread_id not in self._owned or record.resource_state not in {
                ResourceState.ACTIVE, ResourceState.RETAINED}:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Context is retired/released or not owned by this Adapter")
        try:
            return self._runtimes[thread_id]
        except KeyError as exc:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "context has no live tool runtime") from exc

    def _assert_model_profile(self, model: str, effort: str) -> None:
        efforts = self._models.get(model)
        if efforts is None:
            raise LoomModeError(ErrorCategory.MODEL_ERROR, "requested model is not in the live catalog")
        if effort not in efforts:
            raise LoomModeError(
                ErrorCategory.MODEL_ERROR,
                "requested reasoning effort is not supported by the model",
                details={"model": model, "effort": effort, "supported": sorted(efforts)},
            )

    def _require_connected(self) -> None:
        if not self._connected:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "Adapter.connect() must run first")
        self.assert_healthy()
