"""Small allowlisted, non-secret Host failure evidence contract.

Raw exception text, tool output and nested error details never enter new saved
failure evidence. Historical five-field receipts remain readable separately.
"""
from typing import Any

from loommode.codex.errors import ErrorCategory, LoomModeError
from .errors import WorkflowError


FAILED_TOOLS = frozenset({"loommode_git_stage", "loommode_git_commit"})
REASON_TEXT = {
    "DIRTY_TASK_START": "Host checkpoint rejected: Task-start inventory is not clean.",
    "POLICY_REJECTED": "Tool operation rejected by policy.",
    "TOOL_TIMEOUT": "Tool operation timed out; effects require inspection.",
    "GIT_OPERATION_FAILED": "Host Git checkpoint failed; effects require inspection.",
    "TOOL_EXECUTION_FAILED": "Tool operation failed; effects require inspection.",
    "EVIDENCE_SAVE_FAILED": "Formal evidence publication failed; workflow stopped.",
    "RESULT_GATE_REJECTED": "failed/incomplete Executor report cannot pass commit gate",
    "WORKFLOW_FAILURE": "Workflow activity failed; inspect trusted evidence and effects.",
}
MAX_ERROR_LENGTH = 160
assert all(len(message) <= MAX_ERROR_LENGTH for message in REASON_TEXT.values())
TOOL_REASON_CATEGORIES = {
    "DIRTY_TASK_START": {ErrorCategory.TOOL_PERMISSION_ERROR.value},
    "POLICY_REJECTED": {ErrorCategory.TOOL_PERMISSION_ERROR.value},
    "TOOL_TIMEOUT": {ErrorCategory.TOOL_TIMEOUT.value},
    "GIT_OPERATION_FAILED": {ErrorCategory.TOOL_EXECUTION_ERROR.value,
                             ErrorCategory.PROCESS_ERROR.value, ErrorCategory.WORKSPACE_ERROR.value},
    "TOOL_EXECUTION_FAILED": {member.value for member in ErrorCategory} -
                             {ErrorCategory.TOOL_PERMISSION_ERROR.value, ErrorCategory.TOOL_TIMEOUT.value},
}
SAFE_WORKFLOW_MESSAGES = frozenset({
    "Stage plan lacks actual Stage authority",
    "Task policy differs from actual original Intent scope",
    "managed execution lacks trusted Host preflight authority",
    "managed CLI lacks trusted Host preflight",
}) | frozenset(f"{kind} allowance exhausted for actual causal family" for kind in
              ("implementation", "repair", "treatment", "decision_flow"))
NEW_RECEIPT_KEYS = frozenset({"origin", "task_id", "activity", "error", "may_have_dev_effects",
                              "category", "failed_tool", "reason_code"})
OLD_RECEIPT_KEYS = NEW_RECEIPT_KEYS - {"category", "failed_tool", "reason_code"}


def failure_evidence(exc: Exception) -> dict[str, Any]:
    """Return only fixed vocabulary and allowlisted identity, never exception data."""
    category, tool, reason = "WORKFLOW_ERROR", None, "WORKFLOW_FAILURE"
    if isinstance(exc, LoomModeError):
        category = exc.record.category.value
        details = exc.record.details or {}
        if (isinstance(details, dict) and isinstance(details.get("failed_tool"), str)
                and details["failed_tool"] in FAILED_TOOLS):
            tool = details["failed_tool"]
            candidate = details.get("reason_code")
            if (isinstance(candidate, str) and candidate in TOOL_REASON_CATEGORIES
                    and category in TOOL_REASON_CATEGORIES[candidate]):
                reason = candidate
            else:
                tool = None
        if tool is None:
            if exc.record.category == ErrorCategory.TOOL_PERMISSION_ERROR:
                reason = "POLICY_REJECTED"
            elif exc.record.category == ErrorCategory.TOOL_TIMEOUT:
                reason = "TOOL_TIMEOUT"
            elif exc.record.category == ErrorCategory.TOOL_EXECUTION_ERROR:
                reason = "TOOL_EXECUTION_FAILED"
    elif isinstance(exc, WorkflowError):
        if str(exc) == "artifact write failed; workflow must stop":
            category, reason = "EVIDENCE_ERROR", "EVIDENCE_SAVE_FAILED"
        elif str(exc) == "failed/incomplete Executor report cannot pass commit gate":
            category, reason = "RESULT_GATE_ERROR", "RESULT_GATE_REJECTED"
    return {"category": category, "failed_tool": tool, "reason_code": reason, "error": REASON_TEXT[reason]}


def safe_outward_error(exc: Exception, diagnostic: dict[str, Any]) -> str:
    """Preserve only known constant messages in Host status; never echo raw input."""
    if isinstance(exc, WorkflowError) and str(exc) in SAFE_WORKFLOW_MESSAGES:
        return str(exc)
    if (isinstance(exc, LoomModeError) and exc.record.category == ErrorCategory.CONFIG_ERROR
            and str(exc).startswith("declared executable unavailable:")):
        return "declared executable unavailable"
    return diagnostic["error"]


def valid_failure_receipt(value: Any, *, task: str, activities: set[str]) -> bool:
    if not isinstance(value, dict) or frozenset(value) not in {OLD_RECEIPT_KEYS, NEW_RECEIPT_KEYS}:
        return False
    if (value.get("origin") != "HOST_TASK_FAILURE" or value.get("task_id") != task
            or not isinstance(value.get("activity"), str) or value["activity"] not in activities
            or not isinstance(value.get("error"), str)
            or not value["error"] or type(value.get("may_have_dev_effects")) is not bool):
        return False
    if set(value) == OLD_RECEIPT_KEYS:
        return True  # Frozen historical format, including its original error text.
    category = value.get("category")
    tool = value.get("failed_tool")
    reason = value.get("reason_code")
    if (not isinstance(category, str) or not isinstance(reason, str) or reason not in REASON_TEXT
            or (tool is not None and (not isinstance(tool, str) or tool not in FAILED_TOOLS))):
        return False
    if reason in TOOL_REASON_CATEGORIES:
        if category not in TOOL_REASON_CATEGORIES[reason]:
            return False
        if reason in {"DIRTY_TASK_START", "GIT_OPERATION_FAILED"} and tool is None:
            return False
    elif tool is not None:
        return False
    elif reason == "EVIDENCE_SAVE_FAILED" and category != "EVIDENCE_ERROR":
        return False
    elif reason == "RESULT_GATE_REJECTED" and category != "RESULT_GATE_ERROR":
        return False
    elif reason == "WORKFLOW_FAILURE" and category not in (
            {member.value for member in ErrorCategory} | {"WORKFLOW_ERROR"}):
        return False
    return (isinstance(value.get("category"), str)
            and value["category"] in {member.value for member in ErrorCategory} |
            {"WORKFLOW_ERROR", "EVIDENCE_ERROR", "RESULT_GATE_ERROR"}
            and value["error"] == REASON_TEXT[value["reason_code"]])


FAILURE_STAGES=frozenset({'transport','terminal_publication','parser_schema','handoff','route','artifact','state'})
def safe_observation(value, stage='transport'):
    import re
    value=value if isinstance(value,dict) else {}
    stage=value.get('stage') if isinstance(value.get('stage'),str) and value.get('stage') in FAILURE_STAGES else stage
    status=value.get('terminal_status')
    category=value.get('category')
    sha=value.get('final_sha256')
    length=value.get('final_length')
    result = {'stage':stage if stage in FAILURE_STAGES else 'transport',
        'category':category if isinstance(category,str) and category in {m.value for m in ErrorCategory} else 'UNKNOWN',
        'terminal_status':status if isinstance(status,str) and status in {'completed','failed','interrupted'} else 'unknown',
        'thread_correlated':value.get('thread_correlated') is True,
        'turn_correlated':value.get('turn_correlated') is True,
        'final_present':value.get('final_present') is True,
        'final_length':length if type(length) is int and 0<=length<=100000000 else 0,
        'final_sha256':sha if isinstance(sha,str) and re.fullmatch('[0-9a-f]{64}',sha) else None,
        'schema_verdict':value.get('schema_verdict') if isinstance(value.get('schema_verdict'),str) and value.get('schema_verdict') in {'PASS','FAIL'} else 'NOT_RUN'}
    # Optional additive evidence; absent/invalid input preserves the old shape.
    # Never forward arbitrary exception messages, stderr, endpoints or secrets.
    import math
    timing=value.get('transport_timing')
    keys={'wait_phase','deadline_seconds','elapsed_before_diagnosis_ms',
          'turn_start_sent_or_uncertain','turn_start_acknowledged'}
    if (isinstance(timing,dict) and set(timing)==keys
            and isinstance(timing['wait_phase'],str)
            and timing['wait_phase'] in {'ADMISSION','TURN_START_RESPONSE','MATCHING_TERMINAL','PUBLICATION'}
            and type(timing['deadline_seconds']) in {int,float} and math.isfinite(timing['deadline_seconds'])
            and 0 < timing['deadline_seconds'] <= 86400
            and type(timing['elapsed_before_diagnosis_ms']) is int
            and 0 <= timing['elapsed_before_diagnosis_ms'] <= 604800000
            and type(timing['turn_start_sent_or_uncertain']) is bool
            and type(timing['turn_start_acknowledged']) is bool):
        result['transport_timing']=dict(timing)
    return result
