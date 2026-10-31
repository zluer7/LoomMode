"""Typed Owner grants and current issue/knowledge guards; no prose authorization."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import WorkflowError
from .state import identity, unique_json_object

SCOPES = {"TASK", "SERIES", "STAGE", "MAJOR_PHASE", "EXPLICIT_BOUNDED_SCOPE"}
ALIASES = {"current_task": "TASK", "current_series": "SERIES", "current_stage": "STAGE",
           "major_phase": "MAJOR_PHASE", "explicit_bounded_scope": "EXPLICIT_BOUNDED_SCOPE"}
DISPOSITIONS = {"MUST_FIX_BEFORE_STAGE_CLOSE", "RESIDUAL_ACCEPTED", "PROMOTE_TO_MAJOR_PHASE",
                "OWNER_OR_FUTURE_CYCLE_DECISION"}


def scope_name(value):
    value = ALIASES.get(value, value)
    if value not in SCOPES:
        raise WorkflowError("unknown delegation scope")
    return value


def stage_tuple(stage_id):
    match = re.fullmatch(r"(.+)-([A-Za-z]+)([0-9]+)", identity(stage_id))
    if not match:
        raise WorkflowError("fixed cycle/Major Phase/Stage identity required")
    cycle, phase, number = match.groups()
    return cycle, phase, phase + number


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def original_task_id(task):
    """Validate derived numbering only; this supplies no permission."""
    return re.sub(r'-[RF][0-9]+$', '', identity(task))


@dataclass(frozen=True)
class ScopeGrant:
    scope: str
    scope_id: str
    authority_ref: str
    authority_sha256: str
    project: str
    workspace: str
    major_phase: str
    stage_ids: tuple[str, ...]
    series_ids: tuple[str, ...] = ()
    task_ids: tuple[str, ...] = ()
    relationships: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_authority(cls, reference, content):
        """Trusted Host registers actual structured Owner evidence, never an enum."""
        try:
            value = json.loads(content, object_pairs_hook=unique_json_object)
        except (ValueError, TypeError) as exc:
            raise WorkflowError("broader scope requires explicit structured Owner grant") from exc
        keys = {"origin", "scope", "scope_id", "project", "workspace", "major_phase",
                "stage_ids", "series_ids", "task_ids", "relationships"}
        if not isinstance(value, dict) or set(value) != keys or value["origin"] != "OWNER_SCOPE_GRANT":
            raise WorkflowError("explicit Owner grant representation required")
        for key in ("stage_ids", "series_ids", "task_ids"):
            if not isinstance(value[key], list) or any(not isinstance(v, str) for v in value[key]) or len(value[key]) != len(set(value[key])):
                raise WorkflowError("finite declared grant membership required")
        if not isinstance(value["relationships"], dict):
            raise WorkflowError("explicit derived Task relationships required")
        if not isinstance(value['workspace'], str) or not Path(value['workspace']).is_absolute():
            raise WorkflowError('Owner grant workspace must be an explicitly absolute path')
        grant = cls(value["scope"], value["scope_id"], reference, digest(content), value["project"],
                    str(Path(value["workspace"]).resolve()), value["major_phase"], tuple(value["stage_ids"]),
                    tuple(value["series_ids"]), tuple(value["task_ids"]), tuple(value["relationships"].items()))
        grant.validate()
        return grant

    def validate(self):
        if self.scope not in SCOPES:
            raise WorkflowError("grant requires canonical scope")
        for value in (self.scope_id, self.project, self.major_phase, *self.stage_ids, *self.series_ids, *self.task_ids):
            identity(value)
        if not self.stage_ids or not Path(self.workspace).is_absolute():
            raise WorkflowError("grant requires workspace and finite Stage membership")
        for stage in self.stage_ids:
            cycle, phase, _ = stage_tuple(stage)
            if self.major_phase != f"{cycle}-{phase}":
                raise WorkflowError("grant crosses Major Phase")
        if any(not any(re.fullmatch(re.escape(stage) + r'-[A-Za-z]+', series) for stage in self.stage_ids) for series in self.series_ids):
            raise WorkflowError("Series outside declared Stage membership")
        if self.scope in {"TASK", "STAGE", "SERIES"} and len(self.stage_ids) != 1:
            raise WorkflowError("single-Stage scope cannot broaden Stage membership")
        if self.scope == "STAGE" and self.scope_id != self.stage_ids[0]:
            raise WorkflowError("Stage grant identity mismatch")
        if self.scope == "MAJOR_PHASE" and self.scope_id != self.major_phase:
            raise WorkflowError("Major Phase grant identity mismatch")
        if self.scope == "SERIES" and self.series_ids != (self.scope_id,):
            raise WorkflowError("Series grant requires its declared parent")
        if self.scope == "TASK" and self.task_ids != (self.scope_id,):
            raise WorkflowError("Task grant requires exact Task membership")
        if self.scope == "EXPLICIT_BOUNDED_SCOPE" and (not self.task_ids or self.series_ids):
            raise WorkflowError("explicit bounded scope requires finite exact Task membership")
        relationships = dict(self.relationships)
        for child, parent in relationships.items():
            identity(child); identity(parent)
            parent_valid = any(re.fullmatch(re.escape(stage) + r'-[A-Za-z]+[0-9]+(?:-[RF][0-9]+)?', parent) for stage in self.stage_ids)
            if child == parent or not self.contains(child, relationship_check=False) or not parent_valid:
                raise WorkflowError("derived Task relationship outside actual grant")
            if not re.search(r'-[RF][0-9]+$', child) or original_task_id(child) != original_task_id(parent):
                raise WorkflowError('derived Task relationship must retain the original Task stem')

    def contains(self, task, *, stage=None, relationship_check=True):
        identity(task)
        stages = (stage,) if stage else self.stage_ids
        if any(s not in self.stage_ids for s in stages):
            return False
        if not any(re.fullmatch(re.escape(s) + r'-[A-Za-z]+[0-9]+(?:-[RF][0-9]+)?', task) for s in stages):
            return False
        if self.scope in {"TASK", "EXPLICIT_BOUNDED_SCOPE"}:
            permitted = task in self.task_ids
        elif self.series_ids:
            # Parent membership permits adaptive decomposition, not a fixed queue.
            permitted = any(re.fullmatch(re.escape(series) + r"[0-9]+(?:-[RF][0-9]+)?", task) for series in self.series_ids)
        else:
            permitted = self.scope in {"STAGE", "MAJOR_PHASE"}
        if relationship_check and re.search(r"-[RF][0-9]+$", task):
            permitted = permitted and task in dict(self.relationships)
        return bool(permitted)

    def as_dict(self):
        value = asdict(self)
        for key in ("stage_ids", "series_ids", "task_ids"):
            value[key] = list(value[key])
        value["relationships"] = dict(value["relationships"])
        return value


def validate_issue_update(update, current, known_refs):
    keys = {"issue_id", "expected_revision", "origin_ref", "evidence_refs", "status", "relationship", "summary"}
    if not isinstance(update, dict) or set(update) != keys:
        raise WorkflowError("typed issue update required")
    identity(update["issue_id"])
    old = current.get(update["issue_id"])
    if type(update["expected_revision"]) is not int or update["expected_revision"] != (old["revision"] if old else 0):
        raise WorkflowError("stale current issue revision")
    if update["status"] not in {"OPEN", "RESOLVED"} or not update["summary"].strip():
        raise WorkflowError("meaningful current issue status/summary required")
    if update["origin_ref"] not in known_refs or not update["evidence_refs"] or any(ref not in known_refs for ref in update["evidence_refs"]):
        raise WorkflowError("issue lacks verified origin/evidence")
    if old and (old["origin_ref"] != update["origin_ref"] or old["relationship"] != update["relationship"]):
        raise WorkflowError("issue origin/relationship identity changed")
    return {**update, "revision": update["expected_revision"] + 1}


def validate_triage(triage, issues):
    if len(triage) != len(issues) or len({row['issue_id'] for row in triage}) != len(triage):
        raise WorkflowError("Decision triage duplicates or omits current issues")
    for row in triage:
        issue = issues.get(row['issue_id'])
        if not issue or row['revision'] != issue['revision'] or row['disposition'] not in DISPOSITIONS or not row['reason'].strip():
            raise WorkflowError("Decision triage is stale/unclassified/incomplete")
    return [row for row in triage if row['disposition'] == 'MUST_FIX_BEFORE_STAGE_CLOSE' and issues[row['issue_id']]['status'] != 'RESOLVED']


def render_knowledge(knowledge, state, read):
    if not isinstance(knowledge['goal'], str) or not knowledge['goal'].strip():
        raise WorkflowError("nonempty Stage Knowledge goal required")
    for key in ('approved_plan_summary', 'outcomes', 'acceptance_distinctions'):
        if not isinstance(knowledge[key], str) or len(knowledge[key].strip()) < 12:
            raise WorkflowError("substantive readable Stage Knowledge required")
    if knowledge['stage_id'] != state.stage_id or knowledge['plan_ref'] != state.stage_plan_ref or knowledge['acceptance_ref'] != state.stage_acceptance_ref:
        raise WorkflowError("Knowledge goal/plan/acceptance provenance mismatch")
    approved = json.loads(read(knowledge['plan_ref']), object_pairs_hook=unique_json_object)
    if knowledge['goal'] != approved['goal']:
        raise WorkflowError('Knowledge goal differs from the actual Decision-reviewed plan')
    chain = knowledge['chain']
    if len(chain) != len(state.used_task_ids) or {r['task_id'] for r in chain} != set(state.used_task_ids):
        raise WorkflowError("Knowledge omits actual Task chain")
    known = {ref for refs in state.artifact_refs.values() for ref in refs} | {state.stage_input_ref}
    refs = [knowledge['plan_ref'], knowledge['acceptance_ref'], *knowledge['evidence_refs']]
    if not knowledge['evidence_refs'] or not knowledge['residuals']:
        raise WorkflowError("Knowledge requires explicit residual assessment and evidence")
    lines = [f'# {state.stage_id} — Stage Knowledge', '', 'Machine accepted; Owner acceptance is false unless separately recorded.', '',
             '## Goal and approved plan', '', knowledge['goal'], '', knowledge['approved_plan_summary'], '',
             f"Plan: {knowledge['plan_ref']}", '', '## Actual Task / Series / checkpoint chain', '']
    for item in chain:
        if not re.fullmatch(re.escape(state.stage_id) + r'-[A-Za-z]+', item['series_id']):
            raise WorkflowError('Knowledge Series is not an actual parent within this fixed Stage')
        if item['checkpoint_ref'] != state.task_checkpoint_refs.get(item['task_id']) or not re.fullmatch(re.escape(item['series_id']) + r'[0-9]+(?:-[RF][0-9]+)?', item['task_id']) or any(len(item[k].strip()) < 8 for k in ('reason', 'outcome', 'repairs_followups')):
            raise WorkflowError("Knowledge lacks reasons/outcomes/Repairs/checkpoints")
        if item['disposition'] != ('ACCEPTED' if item['checkpoint_ref'] else 'NOT_ACCEPTED') or not item['evidence_refs']:
            raise WorkflowError('Knowledge Task acceptance distinction contradicts actual checkpoint evidence')
        if not item['checkpoint_ref'] and not any(Path(ref.split('#sha256=')[0]).name.startswith(item['task_id'] + '_') for ref in item['evidence_refs']):
            raise WorkflowError('unaccepted Task lacks its actual named input/report evidence')
        refs.extend(([item['checkpoint_ref']] if item['checkpoint_ref'] else []) + item['evidence_refs'])
        lines += [f"- {item['task_id']} / {item['series_id']} — {item['disposition']}: {item['reason']} {item['outcome']} Repairs/Follow-ups: {item['repairs_followups']}",
                  f"  Checkpoint: {item['checkpoint_ref'] or 'NO_ACCEPTED_CHECKPOINT'}"]
    if any(ref not in known for ref in refs):
        raise WorkflowError("Knowledge references unregistered evidence")
    for ref in set(refs) - {state.stage_input_ref}:
        read(ref)
    if validate_triage(state.issue_triage, state.stage_issues):
        raise WorkflowError('Knowledge cannot conceal an unresolved must-fix')
    lines += ['', '## Current Decision issue dispositions', '']
    if not state.stage_issues:
        lines.append('No current typed Stage issues were registered; this does not claim all history is defect-free.')
    for row in state.issue_triage:
        issue = state.stage_issues[row['issue_id']]
        lines += [f"- {row['issue_id']} — {issue['status']}, revision {issue['revision']}: {row['disposition']}. {row['reason']}",
                  f"  Summary: {issue['summary']} Origin: {issue['origin_ref']}",
                  f"  Evidence: {', '.join(issue['evidence_refs'])}; relationship: {issue['relationship'] or 'none declared'}"]
    lines += ['', '## Outcomes and acceptance', '', knowledge['outcomes'], '', knowledge['acceptance_distinctions'], '',
              f"Acceptance: {knowledge['acceptance_ref']}", '', '## Residuals', '', *[f'- {v}' for v in knowledge['residuals']], '',
              '## Verified Layer 1 evidence', '', *[f'- {ref}' for ref in dict.fromkeys(refs)], '']
    return '\n'.join(lines)
