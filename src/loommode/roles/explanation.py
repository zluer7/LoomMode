"""A presentation purpose, deliberately outside the Engine's Node/Action table."""
import json
from typing import Any

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object
from .contracts import array, obj, text, validate

OWNER_STATUS_EXPLANATION = "OWNER_STATUS_EXPLANATION"


def explanation_schema() -> dict[str, Any]:
    return obj({"summary": text(), "evidence_refs": array(text()), "limitations": array(text())})


def validate_explanation(value: dict[str, Any], material_refs: set[str]) -> dict[str, Any]:
    validate(value, explanation_schema())
    if any(ref not in material_refs for ref in value["evidence_refs"]):
        raise WorkflowError("explanation cites evidence outside this snapshot")
    return value


def parse_explanation(raw: str, material_refs: set[str]) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=unique_json_object)
    except (TypeError, ValueError) as exc:
        raise WorkflowError("explanation is not strict JSON") from exc
    return validate_explanation(value, material_refs)


def explanation_prompt(*, role_text: str, question: str, projection: dict[str, Any],
                       materials: dict[str, str], profile: tuple[str, str]) -> str:
    return (
        "LoomMode read-only Owner status explanation. This is presentation, not a workflow activity. "
        "Use the freshly supplied facts and verified evidence; conversation history is not current authority. "
        "Explain progress, the latest accepted Task, stops and existing human needs briefly. "
        "Do not accept results, approve a Gate, route work, start checks, write files, change permissions, "
        "or claim to have performed an Owner command. For requests to act, explain this read-only scope. "
        "Distinguish turn completion, Task acceptance, checkpoint, machine readiness and Owner acceptance. "
        "Keep missing, conflicting or unknown evidence explicit. Cite only supplied material references. "
        "Return exactly the supplied explanation schema, with no action or workflow envelope.\n"
        + role_text + "\n\nPURPOSE: " + OWNER_STATUS_EXPLANATION
        + "\nMODEL/REASONING: " + json.dumps(profile)
        + "\nOWNER QUESTION: " + json.dumps(question, ensure_ascii=False)
        + "\nFACT SNAPSHOT: " + json.dumps(projection, ensure_ascii=False, allow_nan=False)
        + "\nVERIFIED MATERIALS: " + json.dumps(materials, ensure_ascii=False)
        + "\nEXPLANATION SCHEMA: " + json.dumps(explanation_schema())
    )
