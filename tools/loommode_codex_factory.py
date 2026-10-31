"""Copy to the approved management directory; replace and review both values.

Pin this complete factory in the canonical Binding after pinning bootstrap.json.
Configuration changes require a newly reviewed factory/configuration identity.
Public assembly returns the registered SupervisorHost. Configure its underlying
DecisionHost through .host, then return that same registered SupervisorHost.
"""
from loommode.host.bootstrap import create_host as assemble

CANONICAL_FACTORY_API = 1
CONFIG_PATH = 'REPLACE_WITH_ABSOLUTE_APPROVED_BOOTSTRAP_JSON'
CONFIG_SHA256 = 'REPLACE_WITH_EXACT_RAW_CONFIG_SHA256'


def create_host(*, canonical_context):
    supervisor = assemble(CONFIG_PATH, expected_sha256=CONFIG_SHA256, canonical_context=canonical_context)
    # Optional, explicitly approved caller relay wiring belongs here:
    # supervisor.host.require_caller_relay(task_id=approved_task_id,
    #     caller_id=actual_caller_id, source_provider=selected_capture_pin)
    # Optional native admission follows the configured Caller/Relay checks:
    # supervisor.host.require_native_executor_admission(
    #     task_id=approved_task_id, caller_id=actual_caller_id,
    #     reserve=trusted_caller.reserve_native, seal=trusted_caller.seal_native)
    # Callbacks must perform actual durable caller accounting; never model text.
    # Do not call require_caller_relay on SupervisorHost or return its .host.
    return supervisor
