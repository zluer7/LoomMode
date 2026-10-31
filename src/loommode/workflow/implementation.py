"""Implementation-only selection; configuration is intent, never launch authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from loommode.roles.runtime import Invocation
from loommode.tools.runtime import ToolPolicy
from .errors import WorkflowError
from .transitions import Node

CODEX_APP_SERVER = "codex_app_server"
MANAGED_CODEX_CLI = "managed_codex_cli"


@dataclass(frozen=True)
class ManagedCodexConfig:
    cli_path: str
    cli_version: str
    codex_home: str
    provider: str
    model: str
    endpoint: str
    wire_api: str
    reasoning_effort: str | None
    sandbox_mode: str
    windows_sandbox: str
    approval_policy: str
    unattended: bool
    credential_env: str
    credential_file: str | None = None
    parent_http_route: str = "direct_no_proxy"
    tool_read_dirs: tuple[str, ...] = ()
    tool_write_dirs: tuple[str, ...] = ()
    runtime_read_paths: tuple[str, ...] = ()
    tool_denied_paths: tuple[str, ...] = ()
    test_output_dirs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        from loommode.tools.filesystem import normalize_relative
        for name in ('tool_read_dirs', 'tool_write_dirs', 'runtime_read_paths',
                     'tool_denied_paths', 'test_output_dirs'):
            values = getattr(self, name)
            if not isinstance(values, (tuple, list)) or any(not isinstance(v, str) for v in values):
                raise WorkflowError('managed path declarations must be explicit string lists')
            object.__setattr__(self, name, tuple(values))
            for value in values:
                if name == 'runtime_read_paths':
                    if not Path(value).is_absolute() or Path(value).parent == Path(value):
                        raise WorkflowError('runtime read requires a bounded absolute path')
                elif not (name == 'tool_read_dirs' and value == '.'):
                    if normalize_relative(value) == '.' or (name != 'tool_denied_paths' and
                            any(p.lower() in {'.git', '.env', 'credentials'} for p in Path(value).parts)):
                        raise WorkflowError('managed directory root/Git grant denied')
        for name in ("cli_path", "codex_home"):
            value = getattr(self, name)
            if not isinstance(value, str) or not Path(value).is_absolute() or "\x00" in value:
                raise WorkflowError("managed configuration requires explicit absolute CLI/home paths")
        if Path(self.cli_path) == Path(self.codex_home):
            raise WorkflowError("managed CLI and independent home must differ")
        # This is a candidate preset, not a declaration of native compatibility.
        if (self.cli_version not in {"0.160.1", "0.162.1"} or self.provider != "deepseek" or self.model != "deepseek-flash"
                or self.wire_api != "responses" or self.reasoning_effort not in {None, "high"}):
            raise WorkflowError("unsupported managed candidate CLI/provider/model/protocol/reasoning preset")
        if not isinstance(self.endpoint, str):
            raise WorkflowError("managed endpoint must be an explicit HTTPS URL")
        endpoint = urlsplit(self.endpoint)
        if (endpoint.scheme != "https" or endpoint.netloc != "api.deepseek.com"
                or endpoint.path not in {"", "/", "/v1", "/v1/"} or endpoint.query or endpoint.fragment):
            raise WorkflowError("managed endpoint differs from the explicit DeepSeek Responses route")
        if (self.sandbox_mode != "workspace-write" or
                (self.cli_version, self.windows_sandbox) not in {("0.160.1", "elevated"), ("0.162.1", "mxc")}):
            raise WorkflowError("managed candidate requires bounded Windows sandbox; no bypass")
        if (type(self.unattended) is not bool or self.approval_policy not in {"on-request", "never"}
                or (self.unattended and self.approval_policy != "never")):
            raise WorkflowError("on-request cannot claim unattended execution")
        if not isinstance(self.credential_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", self.credential_env):
            raise WorkflowError("credential reference must be an environment variable name, never a value")
        if self.credential_file is not None and (not isinstance(self.credential_file, str)
                or not Path(self.credential_file).is_absolute() or "\x00" in self.credential_file):
            raise WorkflowError("credential file reference must be an explicit absolute path")
        if self.parent_http_route != 'direct_no_proxy':
            raise WorkflowError('unsupported managed model-parent HTTP route')


@dataclass(frozen=True)
class ImplementationConfig:
    backend: str = CODEX_APP_SERVER
    managed: ManagedCodexConfig | None = None

    def __post_init__(self) -> None:
        if self.backend not in {CODEX_APP_SERVER, MANAGED_CODEX_CLI}:
            raise WorkflowError("unknown implementation backend")
        if ((self.backend == MANAGED_CODEX_CLI and not isinstance(self.managed, ManagedCodexConfig))
                or (self.backend == CODEX_APP_SERVER and self.managed is not None)):
            raise WorkflowError("backend and managed configuration mismatch")

    @classmethod
    def from_mapping(cls, value: dict[str, Any], *, activity: Node = Node.EXECUTOR_IMPLEMENT) -> ImplementationConfig:
        if activity != Node.EXECUTOR_IMPLEMENT:
            raise WorkflowError("backend selection is only valid for EXECUTOR_IMPLEMENT")
        if not isinstance(value, dict) or set(value) - {"backend", "managed"}:
            raise WorkflowError("unknown implementation configuration field")
        try:
            managed = value.get("managed")
            return cls(value.get("backend", CODEX_APP_SERVER),
                       ManagedCodexConfig(**managed) if isinstance(managed, dict) else managed)
        except (TypeError, ValueError) as exc:
            raise WorkflowError("malformed nonsecret implementation configuration") from exc


@dataclass(frozen=True)
class ImplementationRequest:
    config: ImplementationConfig
    policy: ToolPolicy
    binding_json: str
    intent_sha256: str
    final_sha256: str

    @classmethod
    def create(cls, config: ImplementationConfig, policy: ToolPolicy, binding: dict[str, Any],
               intent: str, final: str) -> ImplementationRequest:
        return cls(config, policy, json.dumps(binding, sort_keys=True, separators=(",", ":")),
                   hashlib.sha256(intent.encode()).hexdigest(), hashlib.sha256(final.encode()).hexdigest())

    @property
    def binding(self) -> dict[str, Any]:
        return json.loads(self.binding_json)

    @property
    def fingerprint(self) -> str:
        value = asdict(self)
        value["policy"]["workspace"] = str(self.policy.workspace.resolve(strict=True))
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ImplementationBackend(Protocol):
    """A2 boundary: no adapter, workflow state, artifact saving or acceptance."""
    def preflight(self, request: ImplementationRequest, materials: dict[str, str]) -> None: ...
    def execute(self, request: ImplementationRequest, materials: dict[str, str], cancel_signal: Any) -> Invocation: ...
    def cancel(self) -> None: ...
    def health(self) -> dict[str, Any]: ...
    def close(self) -> dict[str, Any]: ...


class ManagedCodexBackend:
    """One owned lifecycle; session binding alone grants no native capability."""
    def __init__(self, host_preflight: Any = None) -> None:
        self.host_preflight = host_preflight
        self.owner_id = uuid4().hex
        self._session = None
        self._closed = False

    def preflight(self, request: ImplementationRequest, materials: dict[str, str] | None = None) -> None:
        if self._closed:
            raise WorkflowError("managed backend closed")
        if request.config.backend != MANAGED_CODEX_CLI:
            raise WorkflowError("managed backend request mismatch")
        if self.host_preflight is None:
            raise WorkflowError("managed execution lacks trusted Host preflight authority")
        if self._session is None:
            self.host_preflight.check(request)
            raise WorkflowError("managed native execution unavailable: Host session not bound; credential/isolation unverified")
        if materials is None:
            raise WorkflowError("managed native execution unavailable: original materials required")
        self._session.preflight(request, materials)

    def execute(self, request: ImplementationRequest, materials: dict[str, str] | None = None,
                cancel_signal: Any = None) -> Invocation:
        self.preflight(request, materials)
        return self._session.execute_native(request, materials, cancel_signal)

    def cancel(self) -> None:
        if self._session is not None:
            self._session.cancel()

    @property
    def owns_session(self) -> bool:
        return self._session is not None

    def bind_session(self, working_root: Path, reserve_dispatch: Any, *, limits: Any = None, native_host: Any = None):
        """Trusted Host binds resource ownership, not credential/isolation authority."""
        if self._closed or self._session is not None:
            raise WorkflowError("managed backend already owns a session or is closed")
        from .managed_cli import ManagedCliSession, CliLimits
        self._session = ManagedCliSession(working_root, self.host_preflight, reserve_dispatch,
                                          limits=limits if limits is not None else CliLimits(), native_host=native_host)
        return self._session

    def fixture_session(self, working_root: Path, reserve_dispatch: Any, *, limits: Any = None):
        """Compatibility entry; each execute_fixture still checks its typed fixture."""
        return self.bind_session(working_root, reserve_dispatch, limits=limits)

    def execute_fixture(self, request: ImplementationRequest, materials: dict[str, str], fixture: Any,
                        cancel_signal: Any = None) -> Invocation:
        if self._closed or self._session is None:
            raise WorkflowError("explicit owned fixture session required")
        return self._session.execute_fixture(request, materials, fixture, cancel_signal)

    def health(self) -> dict[str, Any]:
        if self._session is not None:
            health = self._session.health()
            return {**health, "owned_resources": int(health['running'] or not health['healthy'])}
        return {"healthy": True, "native_execute_available": False, "owned_resources": 0}

    def close(self) -> dict[str, Any]:
        self._closed = True
        if self._session is not None:
            return self._session.close()
        return {"closed": True, "owned_resources": 0, "proof": "A1_NO_LAUNCH_IMPLEMENTED"}
