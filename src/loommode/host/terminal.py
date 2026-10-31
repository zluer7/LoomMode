"""Factual delegated-run boundaries and the existing final-text Hook contract."""
from __future__ import annotations

import hashlib

from loommode.workflow.errors import WorkflowError
from .state_view import _json

_MARKER = "CODEX_TASK_STATUS"


def _clean_reason(reason: str) -> str:
    return "\n".join(line for line in reason.splitlines() if _MARKER.casefold() not in line.casefold()).strip()


def render_final_reply(status: str, reason: str) -> str:
    """Format caller-verified completion; formatting never grants authority."""
    if status not in {"COMPLETED", "BLOCKED"} or not isinstance(reason, str):
        raise WorkflowError("final reply requires one allowed terminal status and explicit reason text")
    # splitlines handles CR/LF and Unicode line separators. Remove the whole
    # untrusted line, including quoted/fenced/inline attempts at the reserved Hook.
    clean = _clean_reason(reason)
    if not clean:
        clean = ("The selected delegated run reached its verified boundary." if status == "COMPLETED"
                 else "The selected delegated run stopped; inspect its bound factual evidence.")
    return f"{clean}\n\n{_MARKER}: {status}"


def _result(state, reason, *, terminal=False, attention="NONE", boundary=None, refs=()):
    return {"state": state, "reason": _clean_reason(reason) or "Inspect the selected run's bound factual evidence.", "terminal": terminal,
            "notification_status": state if terminal else None, "attention": attention,
            "boundary": boundary, "evidence_refs": list(dict.fromkeys(refs)),
            "series_completion": "NOT_ESTABLISHED_BY_SERIES_METADATA"}


def _stage_boundary(view, materials):
    managed = view["managed_run"]
    reached = managed["reached_boundary"] if managed["known_owner_event"] else None
    gate = reached["gate"] if reached else view["gate"]
    node = reached["node"] if reached else view["node"]
    last_completed = reached["last_completed"] if reached else view["activity"]["last_completed"]
    last_result = reached["last_result"] if reached else view["activity"]["last_result"]
    if (node != "HUMAN_GATE" or not gate["machine_close_ready"] or gate["owner_accepted"]
            or last_completed != "OWNER_SUMMARY" or not gate["stage_record_refs"]):
        raise WorkflowError("selected Stage has not reached its original unapproved Human Gate")
    ref = gate["stage_record_refs"][-1]
    record = _json(materials[ref])
    checkpoints = view["checkpoints"]
    if (record["stage"] != view["stage_id"] or record["stage_authorization_ref"] != view["stage_input"]["reference"]
            or record["stage_goal_input"] != view["stage_input"]["content"] or record["owner_accepted"] is not False
            or record["machine_close_ready"] is not True or record["human_gate"]["automatic_next_stage"] is not False
            or record["checkpoints"] != {task: value["reference"] for task, value in checkpoints.items()}
            or any(value["verification"] != "VERIFIED" for value in checkpoints.values())
            or set(record["memory_completed_roles"]) != {"Promoter", "Constraint", "Discussant", "Decision"}):
        raise WorkflowError("saved Stage Record/checkpoint/closure binding is incomplete or mismatched")
    history_refs = _task_closure_boundary(view, materials, record)
    refs = [ref, record["stage_acceptance_ref"], *history_refs]
    for key in ("issue_ledger_refs", "sync_refs", "sync_application_refs", "memory_refs", "decision_refs"):
        if not record[key]:
            raise WorkflowError(f"saved Stage Record lacks {key}")
        refs.extend(record[key])
    refs.extend(record["checkpoints"].values())
    result_ref = (last_result or {}).get("result_ref")
    summary = _json(materials[result_ref])
    if summary["action"] != "SUMMARY_READY" or not summary["owner_summary"].strip():
        raise WorkflowError("saved final Owner Summary is unavailable or not ready")
    refs.append(result_ref)
    if any(reference not in materials for reference in refs):
        raise WorkflowError("a required saved Stage close reference is unverified")
    return refs, summary["owner_summary"]


def _task_closure_boundary(view, materials, record=None, members=None):
    history = view['task_history']
    if history is None:
        raise WorkflowError('Task history facts are unavailable')
    selected = set(history) if members is None else set(members)
    required = {task for task, row in history.items() if task in selected and row['closure_required']}
    checkpoints = {task for task in view['checkpoints'] if task in selected}
    if required != checkpoints:
        raise WorkflowError('accepted or unresolved Task is still required without a checkpoint')
    if record is not None:
        if record['tasks'] != list(history) or ('task_history' in record and record['task_history'] != history):
            raise WorkflowError('saved attempt history/dispositions differ from current formal facts')
        registered = {ref for refs in record['artifacts'].values() for ref in refs}
        if any(ref not in registered or ref not in materials for row in history.values() for ref in row['evidence_refs']):
            raise WorkflowError('saved Stage Record does not bind required Task history evidence')
    return [ref for task, row in history.items() if task in selected for ref in row['evidence_refs']]


def classify_managed(view: dict, materials: dict[str, str]) -> dict:
    """Pure presentation of existing facts; no dispatch or delivery consumption."""
    managed = view["managed_run"]
    binding = managed["binding"]
    if not binding:
        return _result("NEEDS_ATTENTION" if managed["failure"] else "READY_FOR_EXECUTION",
            managed["failure"] or "An explicit authorized live delegation must be started.", attention="HOST_READINESS")
    if managed["pending_event"] or managed["in_flight"] or managed["phase"] in {"RUNNING", "DRAINING", "STOPPING"}:
        draining = managed["phase"] in {"DRAINING", "STOPPING"}
        return _result("NEEDS_ATTENTION" if managed["failure"] or draining else "RUNNING",
            managed["failure"] or ("Close is draining actual work; no cancellation or known outcome is claimed."
                                   if draining else "Queued/current work retains the single operation slot."
                                   + (" Automatic continuation needs no Owner continue request." if managed["automatic"] else "")),
            attention="SAFE_INSPECTION" if managed["failure"] else "HOST_DRAINING" if draining else "NONE")
    delegation = view.get("delegation") or {}
    error = managed["failure"]
    if not error:
        try:
            if (view["availability"] != "AVAILABLE" or view["issues"]
                    or (view["project"], view["stage_id"], view["workspace"]) !=
                       (binding["project"], binding["stage_id"], binding["workspace"])
                    or view["stage_input"]["reference"] != binding["stage_authorization_ref"]
                    or hashlib.sha256(view["stage_input"]["content"].encode("utf-8")).hexdigest() != binding["stage_authorization_sha256"]
                    or delegation.get("request_id") != binding["delegation_request_id"]
                    or delegation.get("persistence", {}).get("verification") != "VERIFIED"
                    or managed["current_grants"] != binding["grants"]
                    or (binding["series"] and binding["series"].get("verification") != "VERIFIED")
                    or view["source"]["state_sha256"] != managed["expected_state_sha256"]):
                raise WorkflowError("live binding, grants, current state or saved evidence is unverified; inspect before continuing")
        except (KeyError, TypeError, ValueError, WorkflowError) as exc:
            error = str(exc)
    if error:
        return _result("BLOCKED", error, terminal=True, attention="SAFE_INSPECTION")
    status = delegation["status"]
    if status in {'STAGE_COMPLETED', 'SCOPE_COMPLETED'}:
        try:
            governance = view['governance']
            if view['node'] != 'COMPLETED':
                raise WorkflowError('completion node is not actual COMPLETED')
            refs = []
            if status == 'STAGE_COMPLETED':
                refs += _task_closure_boundary(view, materials, _json(materials[view['gate']['stage_record_refs'][-1]]))
                if any(row['verification'] != 'VERIFIED' for row in view['checkpoints'].values()):
                    raise WorkflowError('completed Stage checkpoints unavailable')
                refs += [row['reference'] for row in view['checkpoints'].values()]
                if not governance['stage_closed'] or not view['gate']['machine_close_ready']:
                    raise WorkflowError('actual Stage close not established')
                refs += [governance['closeout_ref'], governance['knowledge_ref']]
                if not view['gate']['owner_accepted'] and not any(row['node'] == 'SOFT_ACCEPTANCE_WAIT' for row in governance['soft_window_events']):
                    raise WorkflowError('Stage soft acceptance expiry not evidenced')
                reason = ('Stage machine close, readable Knowledge and final Decision report completed. '
                          f"Owner acceptance is {str(view['gate']['owner_accepted']).lower()}. "
                          'Silence records no objection; further work needs an actual grant.')
            else:
                completion = governance['scope_completion']
                broader = completion and completion.get('origin') == 'HOST_BOUND_SCOPE_COMPLETION'
                if broader:
                    rows = completion['stage_results']
                    if set(row['stage_id'] for row in rows) != set(governance['grant']['stage_ids']):
                        raise WorkflowError('broader scope lacks all declared actual Stage close results')
                    chain = {task: ref for row in rows for task, ref in row['checkpoints'].items()}
                    if set(completion['accepted_task_ids']) != set(chain) or completion['checkpoint_refs'] != list(chain.values()):
                        raise WorkflowError('broader accepted checkpoint chain mismatch')
                    refs += [completion['result_ref'], *chain.values(),
                             *[ref for row in rows for ref in row.get('promotion_refs', [])],
                             *[ref for row in rows for ref in (row['closeout_ref'], row['knowledge_ref'])]]
                else:
                    from loommode.workflow.governance import ScopeGrant
                    value = dict(governance['grant'])
                    for key in ('stage_ids', 'series_ids', 'task_ids'):
                        value[key] = tuple(value[key])
                    value['relationships'] = tuple(value['relationships'].items())
                    grant = ScopeGrant(**value)
                    members = [task for task in view['checkpoints'] if grant.contains(task, stage=view['stage_id'], relationship_check=False)]
                    selected_attempts = [task for task in view['task_history'] if grant.contains(task, stage=view['stage_id'], relationship_check=False)]
                    refs += _task_closure_boundary(view, materials, members=selected_attempts)
                    if not completion or set(completion['accepted_task_ids']) != set(members):
                        raise WorkflowError('actual selected scope completion evidence absent')
                    if any(view['checkpoints'][task]['verification'] != 'VERIFIED' for task in members):
                        raise WorkflowError('completed selected scope checkpoints unavailable')
                    selected_refs = [view['checkpoints'][task]['reference'] for task in members]
                    if set(completion['checkpoint_refs']) != set(selected_refs):
                        raise WorkflowError('selected scope completion checkpoint references differ')
                    refs += selected_refs
                if not broader:
                    refs += [view['activity']['last_result']['result_ref']]
                reason = ('All declared Stages in the delegated scope completed with verified predecessor and current closeout, Knowledge and checkpoint evidence. Owner acceptance remains separately recorded.' if broader else
                    'Delegated scope completed with accepted checkpoint chain, residuals and remaining Stage work. The Stage is not accepted by this scope result.')
            if any(ref not in materials for ref in refs):
                raise WorkflowError('completed boundary formal evidence unverified')
            return _result('COMPLETED', reason, terminal=True, attention='DELEGATED_BOUNDARY', boundary=status, refs=refs)
        except (KeyError, TypeError, WorkflowError) as exc:
            return _result('BLOCKED', str(exc), terminal=True, attention='SAFE_INSPECTION')
    if status in {"TASK_COMPLETED", "HUMAN_GATE"}:
        try:
            if status == "TASK_COMPLETED":
                task = binding["target_task_id"]
                checkpoint = view["checkpoints"][task]
                if (binding["scope"] != "current_task" or delegation["stop_boundary"] != "TASK_COMPLETE"
                        or view["node"] != "TASK_SELECTION" or view["task"]["task_id"] != task
                        or view["activity"]["last_completed"] != "TASK_COMPLETE"
                        or view["task"]["acceptance_status"] != "ACCEPTED" or checkpoint["verification"] != "VERIFIED"
                        or managed["cleanup"]["active_blocker_id"] is not None
                        or managed["cleanup"]["pending_override_task_id"] == task):
                    raise WorkflowError("selected Task acceptance/checkpoint/cleanup boundary is unverified")
                refs = [checkpoint["reference"], view["task"]["acceptance_ref"], view["task"]["intent_ref"],
                        view["task"]["final_ref"], view["task"]["report_ref"]]
                if any(ref not in materials for ref in refs):
                    raise WorkflowError("selected Task formal boundary evidence is unavailable")
                reason = f"Selected current Task {task} accepted, checkpoint verified and cleanup complete. Next Task selection was not called."
            else:
                if binding["scope"] != "current_stage" or delegation["stop_boundary"] != "HUMAN_GATE":
                    raise WorkflowError("Human Gate does not prove this selected scope")
                refs, summary = _stage_boundary(view, materials)
                reason = f"Selected approved Stage {binding['stage_id']} reached its verified Human Gate with Owner acceptance false at that boundary. No next Stage is authorized.\n{summary}"
                owner_event = managed["known_owner_event"]
                if owner_event:
                    reason += (f"\nThe subsequent legal Owner event {owner_event['event']} was applied; current node is {view['node']}, "
                               f"Owner acceptance is {str(view['gate']['owner_accepted']).lower()}. The original delegation stays stopped; no next Stage starts.")
            if binding["series"]:
                reason += f"\nSeries {binding['series']['series_id']} remains an explicit Plan binding; this proves the selected {binding['scope']} boundary."
            return _result("COMPLETED", reason, terminal=True,
                           attention="OWNER_GATE" if status == "HUMAN_GATE" else "DELEGATED_BOUNDARY",
                           boundary=delegation["stop_boundary"], refs=refs)
        except (KeyError, TypeError, ValueError, WorkflowError) as exc:
            return _result("BLOCKED", f"Completion boundary evidence is unverified: {exc}", terminal=True, attention="SAFE_INSPECTION")
    if status != "PENDING":
        if status == "HUMAN_BLOCK" and view["node"] != "HUMAN_BLOCK" and managed["known_owner_event"]:
            return _result("NEEDS_ATTENTION", "The legal Owner event resolved the prior block. The original delegation stays stopped; further work requires a new explicit legal scope selection.",
                           attention="HOST_READINESS", boundary=delegation["stop_boundary"])
        attention = ("OWNER_DECISION" if status == "HUMAN_BLOCK" else "AUTHORIZATION" if status in
                     {"NO_PROGRESS_GRANT", "STALE_AUTHORITY", "TARGET_CHANGED"} else "SAFE_INSPECTION")
        reason, refs = delegation.get("reason") or status, []
        notice = view.get('owner_notice')
        if (status == 'HUMAN_BLOCK' and notice and notice.get('verification') == 'VERIFIED'
                and notice.get('kind') in {'HARD_GATE', 'SAFE_STOP', 'FACTUAL_OWNER_STOP'}):
            reason += f"\nDecision notice: {notice['body']}"
            refs.append(notice['reference'])
        return _result("BLOCKED", reason, terminal=True, attention=attention, refs=refs)
    if view["activity"]["in_flight"] or view["activity"]["host_busy"]:
        return _result("BLOCKED", "An unowned in-flight marker has unknown effects; inspect without replay.",
                       terminal=True, attention="SAFE_INSPECTION")
    if managed["phase"] == "CLOSED":
        return _result("CLOSED_INCOMPLETE", "Explicit close ended the live runtime before the selected scope completed.", attention="HOST_READINESS")
    if managed["runtime_alive"] and managed["waiting_for_event"]:
        if view['node'] in {'SOFT_REVIEW_WAIT', 'SOFT_ACCEPTANCE_WAIT'}:
            return _result('WAITING', 'Host-owned soft review/acceptance timer is active. Silence records no objection and grants no Owner approval; Owner pause takes priority. No model polling.')
        return _result("WAITING", "Live event wait; manual pending work is ready for an explicit event. No model polling.")
    return _result("NEEDS_ATTENTION", "The selected live run cannot currently dispatch; inspect Host readiness.", attention="HOST_READINESS")
