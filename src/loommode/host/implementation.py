"""Read-only Host authority contract for the managed implementation candidate.

The trusted Host supplies the lookup and live Writer check from its actual
authority/lease machinery. Neither configuration nor normal supply is a grant.
Synthetic lookups prove this contract only; A1 never enables native dispatch.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Callable

from loommode.workflow.errors import WorkflowError
from loommode.workflow.implementation import ImplementationRequest, MANAGED_CODEX_CLI

REQUIRED_AUTHORITIES = ("task_policy_workspace", "writer", "paid_provider", "endpoint", "independent_home",
                        "os_permissions", "sandbox_isolation", "credential_reference")


@dataclass(frozen=True)
class HostAuthorityProof:
    capability: str
    request_fingerprint: str
    evidence_ref: str
    expires_at: datetime
    # A trusted usage ledger must supply remaining limits, not config booleans.
    dispatches_remaining: int | None = None
    cost_units_remaining: int | None = None
    currency: str | None = None
    max_runtime_seconds: int | None = None


class ManagedHostPreflight:
    def __init__(self, authority_lookup: Callable[[ImplementationRequest, str], HostAuthorityProof | None],
                 writer_check: Callable[[ImplementationRequest], None], *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._lookup, self._writer_check, self._clock = authority_lookup, writer_check, clock

    def check(self, request: ImplementationRequest) -> None:
        if request.config.backend != MANAGED_CODEX_CLI:
            raise WorkflowError("managed Host preflight only applies to implementation candidate")
        request.policy.preflight()
        binding = request.binding
        if (set(binding) != {"project", "stage_id", "task_id", "intent_ref", "final_ref", "scope"}
                or any(not isinstance(binding[key], str) or not binding[key].strip()
                       for key in ("project", "stage_id", "task_id", "intent_ref", "final_ref"))
                or not isinstance(binding["scope"], list) or not binding["scope"]
                or any(not isinstance(path, str) for path in binding["scope"])
                or not set(request.policy.writable_paths).issubset(binding["scope"])
                or any(not message.startswith(f"[{binding['task_id']}]") for message in request.policy.commit_messages)
                or any(not re.fullmatch(r"[0-9a-f]{64}", digest)
                       for digest in (request.intent_sha256, request.final_sha256))):
            raise WorkflowError("managed preflight requires exact original Task/input/policy binding")
        config = request.config.managed
        from loommode.workflow.managed_cli import managed_tool_paths
        managed_tool_paths(request)
        workspace = request.policy.workspace.resolve(strict=True)
        home = Path(config.codex_home).resolve(strict=False)
        if home == workspace or home.is_relative_to(workspace) or workspace.is_relative_to(home):
            raise WorkflowError("managed home must be independent of the development workspace")
        # Must raise on loss/conflict. This callback may inspect, never acquire a lease.
        self._writer_check(request)
        now = self._clock()
        for capability in REQUIRED_AUTHORITIES:
            proof = self._lookup(request, capability)
            if (not isinstance(proof, HostAuthorityProof) or proof.capability != capability
                    or proof.request_fingerprint != request.fingerprint
                    or not isinstance(proof.evidence_ref, str) or not proof.evidence_ref.strip()
                    or not isinstance(proof.expires_at, datetime) or proof.expires_at.tzinfo is None
                    or proof.expires_at <= now):
                raise WorkflowError("missing, unmatched or expired trusted Host authority: " + capability)
            if capability == "paid_provider" and (
                    any(type(value) is not int or value <= 0 for value in
                        (proof.dispatches_remaining, proof.cost_units_remaining, proof.max_runtime_seconds))
                    or not isinstance(proof.currency, str) or not proof.currency.strip()):
                raise WorkflowError("paid-provider remaining usage/limits are unproved")


def implementation_options(value):
    """Parse optional canonical Host configuration; no authority or secret reads."""
    from loommode.workflow.implementation import ImplementationConfig, CODEX_APP_SERVER
    from loommode.workflow.managed_cli import CliLimits
    if not isinstance(value, dict) or set(value) - {"config", "working_root", "limits"} or "config" not in value:
        raise WorkflowError("explicit canonical implementation configuration required")
    config = ImplementationConfig.from_mapping(value["config"])
    if config.backend == CODEX_APP_SERVER:
        if set(value) != {"config"}:
            raise WorkflowError("Codex default has no managed working root or limits")
        return config, None, None
    if "working_root" not in value or not isinstance(value["working_root"], str):
        raise WorkflowError("managed Host requires its existing absolute working root")
    working = Path(value["working_root"])
    if not working.is_absolute() or not working.is_dir():
        raise WorkflowError("managed Host working root must be an existing absolute directory")
    raw_limits = value.get("limits", {})
    if not isinstance(raw_limits, dict):
        raise WorkflowError("explicit bounded managed CLI limits required")
    try:
        limits = CliLimits(**raw_limits)
    except TypeError as exc:
        raise WorkflowError("unknown managed CLI limit") from exc
    return config, working.resolve(strict=True), limits


def configure_implementation(host, writer_lease, value, *, native_locations=None):
    """Connect an unstarted canonical Host to the existing production Factory.

    The optional binding carries nonsecret configuration, never Native acceptance,
    a run Grant or a fixture switch. The original retained Writer owns all work.
    """
    from loommode.workflow.executor import ExecutorRuntime
    from loommode.workflow.implementation import CODEX_APP_SERVER
    from loommode.host.managed_native import ManagedNativeHost, _RESERVATIONS
    config, working, limits = implementation_options(value)
    engine, executor = host.engine, host.engine.executor
    if (not isinstance(executor, ExecutorRuntime) or engine._busy or engine.state.in_flight_activity
            or executor.task_requests or executor.main_context or executor._managed_session is not None
            or executor.implementation_config_provider is not None
            or getattr(host, "_managed_native", None) is not None):
        raise WorkflowError("canonical implementation configuration requires an unstarted Executor")
    if config.backend == CODEX_APP_SERVER:
        if executor.implementation_config.backend != CODEX_APP_SERVER:
            raise WorkflowError("managed programming cannot silently fall back to Codex")
        return
    from loommode.host.ownership import WorkspaceLease, _LEASES, workspace_identity
    workspace = workspace_identity(host.entry.projection.workspace)
    if (type(writer_lease) is not WorkspaceLease or not writer_lease.held
            or writer_lease.workspace != workspace or writer_lease.owner is not engine
            or _LEASES.get(workspace) is not writer_lease
            or getattr(engine, "_workspace_writer_lease", None) is not writer_lease):
        raise WorkflowError("managed configuration requires the original canonical Writer")
    native = (ManagedNativeHost.from_trusted_config(writer_lease) if native_locations is None else
              ManagedNativeHost.from_trusted_config(writer_lease, locations=native_locations))

    def lookup(request, capability):
        admission = native.check(request, working, limits)
        grant = admission.grant
        with _RESERVATIONS:
            _, _, ledger, _ = native._paths()
            bindings = (native._task_bindings(grant, admission.grant_sha256, ledger)
                        if grant.get("request_binding_mode") else None)
            _, entries = native._budget(grant, admission.grant_sha256, ledger, bindings)
        return HostAuthorityProof(capability, request.fingerprint,
            "NATIVE_PRODUCTION_RUN#sha256=" + admission.grant_sha256,
            datetime.fromisoformat(grant["expires_at"].replace("Z", "+00:00")),
            grant["dispatch_limit"] - len(entries),
            grant["cost_units_limit"] - len(entries) * grant["cost_units_per_dispatch"],
            grant["currency"], grant["timeout_seconds"])

    def reserve(request, attempt):
        for reference in reversed(engine.state.artifact_refs.get("HOST_ALLOWANCE_CONSUMPTION", [])):
            row = engine.artifacts.read_json(reference)
            if row.get("kind") == "implementation" and row.get("task_id") == request.binding["task_id"]:
                if row.get("source") != {"intent_ref": request.binding["intent_ref"],
                                         "final_ref": request.binding["final_ref"]}:
                    raise WorkflowError("durable Engine allowance original Task mismatch")
                return reference
        raise WorkflowError("durable Engine implementation allowance missing")

    executor.implementation_config = config
    executor.managed_backend.host_preflight = ManagedHostPreflight(lookup, native._writer)
    executor.bind_managed_cli(working, reserve, limits=limits, native_host=native)
    host._managed_native = native
