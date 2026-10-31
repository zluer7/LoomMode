"""Strict local JSON validation in addition to the transport output schema."""
import json
from typing import Any
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node, Role, allowed_actions, ESCALATION_CATEGORIES, MEDIATION_OUTCOMES


def obj(properties: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def text() -> dict[str, Any]:
    return {"type": "string", "minLength": 1}


def nullable(schema: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [schema, {"type": "null"}]}


def array(schema: dict[str, Any], *, min_items: int = 0) -> dict[str, Any]:
    result = {"type": "array", "items": schema}
    if min_items:
        result["minItems"] = min_items
    return result


def enum(values: list[str]) -> dict[str, Any]:
    return {"type": "string", "enum": values}


ARTIFACT_KINDS = ["TASK_INTENT", "CONSTRAINT_DRAFT", "DISCUSSANT_REVIEW", "FINAL_TASK_CONSTRAINT",
                  "EXECUTION_REPORT", "INDEPENDENT_REVIEW", "PLAN_REFERENCE", "STAGE_ISSUE_LEDGER",
                  "STAGE_RECORD", "ROLE_EXPERIENCE", "DECISION", "IMPLEMENTATION_PLAN", "ACCEPTANCE"]
ARTIFACT_KINDS += ["STAGE_KNOWLEDGE"]
SYNC_TARGETS = ["HIGHEST_CONTRACT", "PROGRAM_NOTE", "CURRENT", "DEVELOPMENT_PRINCIPLES", "ISSUE_LEDGER", "ROLE_MEMORY"]
OVERRIDE_SCHEMA = obj({"activity": enum([n.value for n in Node]), "model": nullable(text()),
                       "reasoning_effort": nullable(text()), "reason": text()})
INTENT_SCHEMA = obj({
    "task_id": text(), "goal": text(), "why_now": text(), "scope": array(text()),
    "authority_refs": array(text()), "expected_result": text(), "acceptance_intent": text(),
    "workflow_path": enum(["NORMAL", "FAST"]), "fast_authorization_ref": nullable(text()),
    "execution_input": nullable(text()), "model_override": nullable(OVERRIDE_SCHEMA),
    "independent_review_suggested": {"type": "boolean"}, "decision_suggested": {"type": "boolean"},
    "relationship": nullable(obj({'parent_task_id': text(), 'parent_ref': text(),
                                  'kind': enum(['REPAIR', 'FOLLOWUP']), 'reason': text()})),
})
ISSUE_UPDATE_SCHEMA = obj({'issue_id': text(), 'expected_revision': {'type': 'integer', 'minimum': 0},
    'origin_ref': text(), 'evidence_refs': array(text()), 'status': enum(['OPEN', 'RESOLVED']),
    'relationship': nullable(text()), 'summary': text()})
TRIAGE_SCHEMA = obj({'issue_id': text(), 'revision': {'type': 'integer', 'minimum': 1},
    'disposition': enum(['MUST_FIX_BEFORE_STAGE_CLOSE', 'RESIDUAL_ACCEPTED', 'PROMOTE_TO_MAJOR_PHASE', 'OWNER_OR_FUTURE_CYCLE_DECISION']),
    'reason': text()})
KNOWLEDGE_SCHEMA = obj({'stage_id': text(), 'goal': text(), 'plan_ref': text(), 'approved_plan_summary': text(),
    'chain': array(obj({'task_id': text(), 'series_id': text(), 'reason': text(), 'outcome': text(),
                       'repairs_followups': text(), 'checkpoint_ref': nullable(text()),
                       'disposition': enum(['ACCEPTED', 'NOT_ACCEPTED']), 'evidence_refs': array(text())})),
    'outcomes': text(), 'residuals': array(text()), 'acceptance_ref': text(), 'acceptance_distinctions': text(),
    'evidence_refs': array(text())})
COMPLETION_SCHEMA = obj({'scope': enum(['TASK', 'SERIES', 'STAGE', 'MAJOR_PHASE', 'EXPLICIT_BOUNDED_SCOPE']),
    'scope_id': text(), 'accepted_task_ids': array(text()), 'checkpoint_refs': array(text()),
    'residuals': array(text()), 'remaining_stage_work': array(text()), 'reason': text()})
STAGE_PLAN_SCHEMA = obj({'stage_id': text(), 'goal': text(), 'functional_outcomes': array(text(), min_items=1),
    'series': array(text(), min_items=1), 'initial_tasks': array(text(), min_items=1),
    'risks': array(text(), min_items=1), 'authority_refs': array(text(), min_items=1),
    'acceptance_focus': array(text(), min_items=1)})
ESCALATION_SCHEMA = obj({'origin_role': enum([role.value for role in Role]), 'origin_activity': enum([node.value for node in Node]),
    'stage_id': text(), 'task_id': nullable(text()), 'category': enum(sorted(ESCALATION_CATEGORIES)),
    'reason': text(), 'evidence_refs': array(text()),
    'requested_treatment': enum(sorted(MEDIATION_OUTCOMES | {'REPORT_CORRECTION'}))})
MEDIATION_SCHEMA = obj({'handoff_ref': text(), 'outcome': enum(sorted(MEDIATION_OUTCOMES)),
    'reason': text(), 'notice': nullable(text())})

# One definition for transport choices, saving guards and required outputs.
REQUIRED_ARTIFACT = {
    Node.STAGE_REVIEW: "PLAN_REFERENCE", Node.STAGE_PLANNING: "IMPLEMENTATION_PLAN",
    Node.STAGE_PLAN_DECISION: "DECISION", Node.STAGE_ISSUE_TRIAGE: "DECISION",
    Node.DECISION_MEDIATION: "DECISION",
    Node.CONSTRAINT_DRAFT: "CONSTRAINT_DRAFT", Node.DISCUSS_NORMAL: "DISCUSSANT_REVIEW",
    Node.CONSTRAINT_FINALIZE: "FINAL_TASK_CONSTRAINT", Node.EXECUTOR_IMPLEMENT: "EXECUTION_REPORT",
    Node.INDEPENDENT_REVIEW: "INDEPENDENT_REVIEW", Node.DISCUSSANT_DECISION_ANALYSIS: "DISCUSSANT_REVIEW",
    Node.DECISION_REVIEW: "DECISION", Node.DECISION_RE_REVIEW: "DECISION",
    Node.PROMOTER_IMPLEMENTATION_PLAN: "IMPLEMENTATION_PLAN",
    Node.DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW: "DISCUSSANT_REVIEW",
    Node.STAGE_ACCEPTANCE: "INDEPENDENT_REVIEW", Node.STAGE_SETTLEMENT: "STAGE_ISSUE_LEDGER",
}


def allowed_artifact_kinds(node: Node) -> list[str]:
    return sorted({"ROLE_EXPERIENCE", "STAGE_ISSUE_LEDGER"} | ({REQUIRED_ARTIFACT[node]} if node in REQUIRED_ARTIFACT else set()))


def review_repair_available(state: dict[str, Any]) -> bool:
    if state.get('host_review_context_conversion_available') is False:
        return False
    task = state.get("task_id")
    return bool(task and state.get("active_review_context_ref") and state.get("independent_review_used") and
                any(f"{task}_INDEPENDENT_REVIEW_" in ref for ref in state.get("artifact_refs", {}).get("INDEPENDENT_REVIEW", [])))


REPORT_CORRECTION_NODES = frozenset({Node.PROMOTER_RESULT_REVIEW, Node.INDEPENDENT_REVIEW})


def escalation_schema(node):
    from copy import deepcopy
    schema = deepcopy(ESCALATION_SCHEMA)
    if node not in REPORT_CORRECTION_NODES:
        values = schema['properties']['requested_treatment']['enum']
        schema['properties']['requested_treatment']['enum'] = [v for v in values if v != 'REPORT_CORRECTION']
    return schema


def result_schema(node: Node, state: dict[str, Any] | None = None) -> dict[str, Any]:
    artifacts = array(obj({"kind": enum(allowed_artifact_kinds(node)), "content": text()}))
    if node == Node.ROLE_MEMORY_CONSOLIDATION:
        artifacts["maxItems"] = 0
    return obj({
        "action": enum(list(allowed_actions(node))), "explanation": text(), "handoff": nullable(text()),
        "intent": (nullable(INTENT_SCHEMA) if node in {Node.TASK_SELECTION, Node.STAGE_SETTLEMENT,
                                                       Node.PROMOTER_IMPLEMENTATION_PLAN} else {"type": "null"}),
        "artifacts": artifacts,
        "evidence": nullable(obj({k: {"type": "boolean"} for k in
                                  ["goals_met", "tests_passed", "self_review_done", "nonblocking_handled", "report_complete"]})),
        "blocker_id": nullable(text()),
        "new_basis": nullable(obj({"basis_id": text(), "change_kind": enum(["NEW_CONTRACT", "TASK_BOUNDARY", "IMPLEMENTATION_BASIS", "CONFIG_ADJUSTMENT"]),
                                    "description": text(), "authority_refs": array(text()), "changed_premise": {"type": "boolean"}})),
        "model_override": nullable(OVERRIDE_SCHEMA),
        "repair_from_review": ({"type": "boolean"} if node == Node.PROMOTER_RESULT_REVIEW and
                               (state is None or review_repair_available(state)) else
                               {"type": "boolean", "enum": [False]}),
        "sync": array(obj({"target": enum(SYNC_TARGETS), "outcome": enum(["UPDATED", "NO_CHANGE", "NEEDS_HUMAN"]),
                           "content": nullable(text()), "authority_ref": nullable(text())})),
        "experiences": array(obj({"role": enum(["Promoter", "Constraint", "Discussant", "Decision"]),
                                  "lesson": text(), "conditions": text(), "source_refs": array(text())})),
        "owner_summary": nullable(text()),
        "issues": array(ISSUE_UPDATE_SCHEMA),
        "triage": array(TRIAGE_SCHEMA) if node == Node.STAGE_ISSUE_TRIAGE else {"type": "array", "items": TRIAGE_SCHEMA, "maxItems": 0},
        "knowledge": nullable(KNOWLEDGE_SCHEMA) if node == Node.STAGE_KNOWLEDGE else {"type": "null"},
        "completion": nullable(COMPLETION_SCHEMA) if node == Node.TASK_SELECTION else {"type": "null"},
        'stage_plan': nullable(STAGE_PLAN_SCHEMA) if node == Node.STAGE_PLANNING else {'type': 'null'},
        'escalation': nullable(escalation_schema(node)),
        'mediation': nullable(MEDIATION_SCHEMA) if node == Node.DECISION_MEDIATION else {'type': 'null'},
    })


def validate(value: Any, schema: dict[str, Any], path: str = "result") -> None:
    if "anyOf" in schema:
        for branch in schema["anyOf"]:
            try:
                validate(value, branch, path)
                return
            except WorkflowError:
                pass
        raise WorkflowError(f"{path}: invalid nullable/union value")
    kind = schema["type"]
    valid = {"null": value is None, "string": isinstance(value, str), "boolean": type(value) is bool,
             "object": isinstance(value, dict), "array": isinstance(value, list), "integer": type(value) is int}[kind]
    if not valid:
        raise WorkflowError(f"{path}: expected {kind}")
    if kind == "object":
        if set(value) != set(schema["properties"]):
            raise WorkflowError(f"{path}: missing or unknown fields")
        for key, item in value.items():
            validate(item, schema["properties"][key], f"{path}.{key}")
    elif kind == "array":
        if len(value) < schema.get("minItems", 0):
            raise WorkflowError(f"{path}: too few items")
        if len(value) > schema.get("maxItems", len(value)):
            raise WorkflowError(f"{path}: too many items")
        for i, item in enumerate(value):
            validate(item, schema["items"], f"{path}[{i}]")
    elif kind == "string":
        if len(value.strip()) < schema.get("minLength", 0):
            raise WorkflowError(f"{path}: empty string")
    if "enum" in schema and value not in schema["enum"]:
        raise WorkflowError(f"{path}: unknown enum")
    if kind == 'integer' and value < schema.get('minimum', value):
        raise WorkflowError(f"{path}: below minimum")


def parse_result(raw: str, node: Node, state: dict[str, Any] | None = None) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise WorkflowError("duplicate JSON key")
            result[key] = value
        return result
    # The control object may sit inside prose/Markdown. Never choose between
    # multiple control objects or repair JSON syntax/authority values here.
    decoder = json.JSONDecoder(object_pairs_hook=unique)
    candidates = []
    def contains_control(value):
        if isinstance(value, dict):
            return 'action' in value or any(contains_control(item) for item in value.values())
        return isinstance(value, list) and any(contains_control(item) for item in value)
    offset = 0
    if not isinstance(raw, str):
        raise WorkflowError("structured result is not JSON")
    while offset < len(raw):
        start = raw.find('{', offset)
        if start < 0:
            break
        try:
            value, end = decoder.raw_decode(raw, start)
        except json.JSONDecodeError as exc:
            raise WorkflowError('malformed workflow control object') from exc
        if isinstance(value, dict) and 'action' in value:
            if raw[:start].rstrip().endswith('['):
                raise WorkflowError('array-wrapped workflow control object is ambiguous')
            candidates.append(value)
        elif contains_control(value):
            raise WorkflowError('nested workflow control object is ambiguous')
        offset = end
    if len(candidates) != 1:
        raise WorkflowError("expected one unambiguous workflow control object")
    result = candidates[0]
    # Only inactive bookkeeping has defaults. Evidence, actions, artifacts and
    # all authority-bearing values remain explicitly validated.
    defaults = empty_result(result['action'])
    for key in ('handoff', 'intent', 'blocker_id', 'new_basis', 'model_override',
                'repair_from_review', 'sync', 'experiences', 'owner_summary',
                'issues', 'triage', 'knowledge', 'completion', 'stage_plan',
                'escalation', 'mediation'):
        result.setdefault(key, defaults[key])
    validate(result, result_schema(node, state))
    return result


def empty_result(action: str, explanation: str = "Explicit fixture decision") -> dict[str, Any]:
    """Construct envelopes for deterministic fixtures, never a production decision."""
    return {"action": action, "explanation": explanation, "handoff": None, "intent": None, "artifacts": [],
            "evidence": None, "blocker_id": None, "new_basis": None, "model_override": None,
            "repair_from_review": False, "sync": [], "experiences": [], "owner_summary": None,
            "issues": [], "triage": [], "knowledge": None, "completion": None, 'stage_plan': None,
            'escalation': None, 'mediation': None}


def handoff_schema(node: Node, state: dict[str, Any] | None = None) -> dict[str, Any]:
    """Original Engine validation also covers its own format-failure findings.

    This is not the model output schema. Model text still passes parse_result's
    node-specific schema before the unchanged Engine node/provenance guard.
    """
    schema = result_schema(node, state)
    schema['properties']['escalation'] = nullable(ESCALATION_SCHEMA)
    return schema
