"""Verification of the saved no-commit proof and its original Result Gate."""
import hashlib
import json
from pathlib import Path
from typing import Any

from loommode.roles.contracts import INTENT_SCHEMA, result_schema, validate
from loommode.tools.git import require_no_commit_evidence
from .errors import WorkflowError
from .transitions import Node
from .state import unique_json_object
from .failure_evidence import valid_failure_receipt


def task_closure_history(artifacts, used_task_ids, artifact_refs, checkpoint_refs, relationships):
    """Derive closure obligations from saved facts; never erase or replace history."""
    if len(set(used_task_ids)) != len(used_task_ids) or not set(checkpoint_refs) <= set(used_task_ids):
        raise WorkflowError('attempt/checkpoint identities disagree')
    entries = []
    for kind in ('TASK_INTENT', 'FINAL_TASK_CONSTRAINT', 'EXECUTION_REPORT', 'ACCEPTANCE',
                 'REPORT_RESULT', 'DECISION', 'IMPLEMENTATION_PLAN', 'HOST_TASK_FAILURE'):
        for ref in artifact_refs.get(kind, []):
            owners = []
            for owner in used_task_ids:
                try:
                    artifacts.assert_task_reference(ref, 'DECISION' if kind in {'REPORT_RESULT', 'HOST_TASK_FAILURE'} else kind, owner)
                    owners.append(owner)
                except WorkflowError:
                    pass
            if not owners:
                continue  # Stage-owned evidence is not a Task disposition.
            if len(owners) != 1:
                raise WorkflowError('ambiguous Task history owner')
            content = artifacts.read(ref)
            value = None
            if kind not in {'FINAL_TASK_CONSTRAINT', 'EXECUTION_REPORT'}:
                try:
                    def reject_constant(value):
                        raise WorkflowError('non-finite Task history JSON')
                    value = json.loads(content, object_pairs_hook=unique_json_object, parse_constant=reject_constant)
                except json.JSONDecodeError as exc:
                    if kind in {'TASK_INTENT', 'ACCEPTANCE', 'REPORT_RESULT', 'HOST_TASK_FAILURE'}:
                        raise WorkflowError('mandatory Task history JSON is invalid') from exc
            entries.append((kind, ref, owners[0], content, value))
    rows = {}
    supersessions = {}
    actions = {'IMPLEMENTATION_PLAN_READY': Node.PROMOTER_IMPLEMENTATION_PLAN,
               'MEDIATION_READY': Node.DECISION_MEDIATION, 'DECISION_READY': Node.DECISION_REVIEW,
               'NEW_BASIS_APPROVED': Node.DECISION_REVIEW}
    for kind, ref, owner, content, value in entries:
        if not isinstance(value, dict) or value.get('origin') != 'TASK_SUPERSESSION':
            continue
        if (kind not in {'DECISION', 'IMPLEMENTATION_PLAN'} or set(value) !=
                {'origin', 'task_id', 'successor_task_id', 'evidence_refs', 'covered_dev_paths', 'reason'}
                or value['task_id'] not in used_task_ids or not isinstance(value['reason'], str)
                or not value['reason'].strip() or not isinstance(value['evidence_refs'], list)
                or not isinstance(value['covered_dev_paths'], list)
                or not value['evidence_refs']
                or any(not isinstance(item, str) or not item for item in value['evidence_refs'])
                or any(not isinstance(path, str) or not path for path in value['covered_dev_paths'])
                or len(set(value['evidence_refs'])) != len(value['evidence_refs'])
                or len(set(value['covered_dev_paths'])) != len(value['covered_dev_paths'])):
            raise WorkflowError('invalid explicit Task supersession')
        producers = []
        for receipt_kind, receipt_ref, receipt_owner, _, reply in entries:
            if (receipt_kind != 'DECISION' or receipt_ref in artifact_refs.get('DECISION_PLAN', [])
                    or receipt_owner != owner or not isinstance(reply, dict) or reply.get('action') not in actions):
                continue
            validate(reply, result_schema(actions[reply['action']]))
            if any(a['kind'] == kind and a['content'] == content for a in reply['artifacts']):
                producers.append(receipt_ref)
        if len(producers) != 1 or value['task_id'] in supersessions:
            raise WorkflowError('supersession lacks one saved Planner/Decision producer')
        supersessions[value['task_id']] = (ref, producers[0], value)
    for task in used_task_ids:
        own = [entry for entry in entries if entry[2] == task]
        intents = [entry for entry in own if entry[0] == 'TASK_INTENT']
        acceptances, failures = [], []
        for kind, ref, _, _, value in own:
            if kind == 'ACCEPTANCE':
                validate(value, result_schema(Node.PROMOTER_RESULT_REVIEW))
                if value['action'] != 'TASK_ACCEPTED' or not value['evidence'] or not all(value['evidence'].values()):
                    raise WorkflowError('invalid saved Task acceptance')
                acceptances.append(ref)
            elif kind == 'REPORT_RESULT':
                validate(value, result_schema(Node.EXECUTOR_IMPLEMENT))
                if value['action'] in {'HUMAN_REQUIRED', 'OWNER_REQUIRED'} or (value['evidence'] and not all(value['evidence'].values())):
                    failures.append(ref)
            elif kind == 'HOST_TASK_FAILURE':
                if not valid_failure_receipt(value, task=task, activities={node.value for node in Node}):
                    raise WorkflowError('invalid saved Host Task failure')
                failures.append(ref)
        if len(intents) > 1 or (not intents and not failures):
            raise WorkflowError('Task attempt lacks original Intent or explicit preparation failure')
        intent = intents[0][4] if intents else None
        if intent:
            validate(intent, INTENT_SCHEMA)
            if intent['task_id'] != task or intent['relationship'] != relationships.get(task):
                raise WorkflowError('Task history Intent/relationship mismatch')
        checkpoint = checkpoint_refs.get(task)
        if checkpoint and (not acceptances or not any(entry[0] == 'FINAL_TASK_CONSTRAINT' for entry in own)
                           or not any(entry[0] == 'EXECUTION_REPORT' for entry in own)):
            raise WorkflowError('checkpoint lacks original accepted Task facts')
        rows[task] = {'intent_ref': intents[0][1] if intents else None, 'acceptance_refs': acceptances,
                      'failure_refs': failures, 'checkpoint_ref': checkpoint,
                      'relationship': relationships.get(task), 'supersession_ref': None,
                      'successor_task_id': None, 'closure_required': bool(acceptances) or not failures,
                      'disposition': 'CHECKPOINTED' if checkpoint else 'ACCEPTED_UNCHECKPOINTED' if acceptances else
                                     'FAILED_OR_REJECTED' if failures else 'UNRESOLVED_ATTEMPT',
                      'evidence_refs': list(dict.fromkeys(entry[1] for entry in own if entry[0] in
                          {'TASK_INTENT', 'FINAL_TASK_CONSTRAINT', 'EXECUTION_REPORT', 'ACCEPTANCE', 'REPORT_RESULT'} or entry[1] in failures))}
        if checkpoint:
            rows[task]['closure_required'] = True
    for task, row in rows.items():
        if row['checkpoint_ref']:
            continue
        successors = [child for child, child_row in rows.items() if child_row['checkpoint_ref']
                      and child_row['relationship'] and child_row['relationship']['parent_task_id'] == task
                      and child_row['relationship']['parent_ref'] in row['evidence_refs']]
        if task in supersessions:
            ref, producer_ref, value = supersessions[task]
            child = value['successor_task_id']
            if child not in successors:
                raise WorkflowError('supersession successor is not actually closed with a typed parent')
            required = set(row['evidence_refs']) | {ref}
            child_intent = next(entry[4] for entry in entries if entry[0] == 'TASK_INTENT' and entry[2] == child)
            if not required <= set(child_intent['authority_refs']) or not set(row['evidence_refs']) <= set(value['evidence_refs']):
                raise WorkflowError('supersession omits predecessor facts or successor input coverage')
            proof = artifacts.read_json(rows[child]['checkpoint_ref'])
            paths = value['covered_dev_paths']
            if paths and (proof.get('origin') != 'HOST_COMMIT_RECEIPT' or
                          not set(paths) <= set(proof['receipt']['staged_files'])):
                raise WorkflowError('superseded Dev paths are not covered by successor commit')
            row.update(closure_required=False, disposition='SUPERSEDED', supersession_ref=ref, successor_task_id=child)
            row['evidence_refs'] += [ref, producer_ref, rows[child]['checkpoint_ref']]
        elif not row['acceptance_refs'] and row['failure_refs'] and successors:
            # A failed execution with unknown Dev effects needs explicit coverage,
            # not merely the existence of a later successful Task.
            unknown = any(entry[0] == 'REPORT_RESULT' or (entry[0] == 'HOST_TASK_FAILURE'
                          and entry[4]['may_have_dev_effects']) for entry in entries if entry[1] in row['failure_refs'])
            child_intent = next(entry[4] for entry in entries if entry[0] == 'TASK_INTENT' and entry[2] == successors[0])
            covered_inputs = set(row['evidence_refs']) <= set(child_intent['authority_refs'])
            row.update(closure_required=unknown or not covered_inputs, successor_task_id=successors[0])
        else:
            row['closure_required'] = True
    return rows


def verify_saved_no_commit(artifacts: Any, evidence: dict[str, Any], *, project: str, stage_id: str,
                           task_id: str, workspace: Path, authority: dict[str, str]) -> None:
    """Read-only historical verification; this cannot authorize/replay a Task."""
    require_no_commit_evidence(evidence)
    binding = evidence["binding"]
    if ((binding["project"], binding["stage_id"], binding["task_id"]) != (project, stage_id, task_id)
            or binding["workspace"] != str(workspace.resolve())):
        raise WorkflowError("saved no-commit identity/workspace mismatch")
    stage_ref = binding["stage_input_ref"]
    if (stage_ref not in authority or hashlib.sha256(authority[stage_ref].encode("utf-8")).hexdigest()
            != binding["stage_input_sha256"]):
        raise WorkflowError("saved no-commit Stage authority changed or is unavailable")
    fields = {"intent_ref": "TASK_INTENT", "final_ref": "FINAL_TASK_CONSTRAINT", "report_ref": "EXECUTION_REPORT",
              "acceptance_ref": "ACCEPTANCE", "report_result_ref": "DECISION"}
    refs = binding["required_artifact_refs"]
    required = {binding[key] for key in fields}
    for key, kind in fields.items():
        ref = binding[key]
        if ref not in refs:
            raise WorkflowError("saved no-commit omitted a required formal reference")
        artifacts.assert_task_reference(ref, kind, task_id)
        artifacts.read(ref)
    intent = artifacts.read_json(binding["intent_ref"])
    validate(intent, INTENT_SCHEMA)
    if intent["task_id"] != task_id or intent["scope"] != binding["scope"]:
        raise WorkflowError("saved no-commit Intent/scope mismatch")
    acceptance = artifacts.read_json(binding["acceptance_ref"])
    report = artifacts.read_json(binding["report_result_ref"])
    for value, node, action in ((acceptance, Node.PROMOTER_RESULT_REVIEW, "TASK_ACCEPTED"),
                                (report, Node.EXECUTOR_IMPLEMENT, "REPORT_READY")):
        validate(value, result_schema(node))
        if value["action"] != action or not value["evidence"] or not all(value["evidence"].values()):
            raise WorkflowError("saved no-commit Result Gate is incomplete")
    if sum(a["kind"] == "EXECUTION_REPORT" for a in report["artifacts"]) != 1:
        raise WorkflowError("saved no-commit requires one Execution Report")
    for artifact in report["artifacts"]:
        candidates = []
        for ref in refs:
            try:
                artifacts.assert_task_reference(ref, artifact["kind"], task_id)
            except WorkflowError:
                continue
            if artifacts.read(ref) == artifact["content"]:
                candidates.append(ref)
        if len(candidates) != 1 or (artifact["kind"] == "EXECUTION_REPORT" and candidates[0] != binding["report_ref"]):
            raise WorkflowError("saved no-commit required artifact cannot be verified")
        required.add(candidates[0])
    if required != set(refs):
        raise WorkflowError("saved no-commit has unknown required artifact references")
