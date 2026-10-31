"""Derive Owner facts from explicit sources without restarting or writing workflow."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Callable

from loommode.codex.context import ContextRegistry, utc_now
from loommode.codex.errors import LoomModeError
from loommode.roles.contracts import ARTIFACT_KINDS, INTENT_SCHEMA, result_schema, validate
from loommode.workflow.artifacts import ArtifactStore
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import WorkflowState, identity, unique_json_object
from loommode.workflow.transitions import Node
from loommode.workflow.checkpoints import verify_saved_no_commit, task_closure_history
from .activity import ActivityView

ALIASES = {"DECISION_PLAN": "DECISION", "REPORT_RESULT": "DECISION", "SYNC_APPLICATION": "DECISION",
           "OWNER_REQUEST": "DECISION", 'MAJOR_PHASE_PROMOTION': 'DECISION',
           'DECISION_HANDOFF': 'DECISION', 'DECISION_MEDIATION_RESULT': 'DECISION', 'DECISION_NOTICE': 'DECISION',
           'SYNC_RESULT': 'DECISION', 'PROGRAM_INPUT': 'DECISION', 'ISSUE_REPAIR_REQUEST': 'DECISION',
           'HOST_TASK_FAILURE': 'DECISION', 'HOST_STAGE_FAILURE': 'DECISION', 'HOST_ALLOWANCE_FAMILY': 'DECISION',
           'HOST_ALLOWANCE_CONSUMPTION': 'DECISION', 'HOST_ALLOWANCE_GRANT': 'DECISION',
           'HOST_ALLOWANCE_HISTORY': 'DECISION',
           'HOST_CALLER_RELAY_VERIFICATION': 'DECISION',
           'HOST_NATIVE_EXECUTOR_ADMISSION': 'DECISION',
           'HOST_REPORT_OUTPUT_BINDING': 'DECISION',
           'ROLE_OUTPUT': 'DECISION', 'DECISION_RESOLVED_OUTPUT': 'DECISION'}
READ_ERRORS = (WorkflowError, LoomModeError, OSError, ValueError, TypeError)


def _json(text: str) -> Any:
    def reject_constant(value: str):
        raise WorkflowError(f"non-finite JSON value: {value}")
    return json.loads(text, object_pairs_hook=unique_json_object, parse_constant=reject_constant)


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def saved_state_provider(store: Any) -> Callable[[], WorkflowState]:
    """Read an explicitly supplied StateStore path; never call load_for_restart/save."""
    path, project, stage = Path(store.path), store.project, store.stage_id

    def read() -> WorkflowState:
        value = _json(path.read_text(encoding="utf-8"))
        additive = {'active_grant', 'stage_plan_ref', 'stage_plan_decision_ref', 'stage_acceptance_ref',
            'stage_notice_ref', 'stage_knowledge_ref', 'stage_closeout_ref', 'stage_closed', 'scope_completion',
            'stage_issues', 'issue_triage', 'soft_window_events', 'task_relationships'}
        required = {field.name for field in fields(WorkflowState)}
        if not isinstance(value, dict) or set(value) - required or required - set(value) - additive:
            raise WorkflowError("checkpoint fields missing or unknown")
        state = WorkflowState(**value)
        state.validate()
        if (state.project, state.stage_id) != (project, stage):
            raise WorkflowError("checkpoint identity mismatch")
        return state

    return read


@dataclass(frozen=True)
class StatusSnapshot:
    view: dict[str, Any]
    materials: dict[str, str]
    revision: str

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.view)

    def summary(self) -> str:
        view = self.view
        if view["availability"] != "AVAILABLE":
            return f"当前现场不可核验：{view['issues'][0]['problem']}。"
        task = view["task"]
        lines = [f"{view['project']} / {view['stage_id']} / {task['task_id'] or '暂无当前 Task'}；"
                 f"{view['node']}（{view['activity']['status']}）。"]
        activities = view["activities"]
        if activities["active"]:
            current = activities["active"][0]
            lines.append(f"当前在途活动：{current['role'] or 'Host'} / {current['activity']}；原生 turn 是否运行仍需实际证据。")
        if activities["recent"]:
            lines.append(f"最近完成活动：{activities['recent'][0]['activity']}，已从 active view 退场；已观察历史 {len(activities['recent'])} 项。")
        accepted = view["latest_accepted"]
        if accepted["status"] == "VERIFIED":
            checkpoint = accepted["checkpoint"]
            disposition = ("Host 已核验，无需 Dev commit" if checkpoint and checkpoint["verification"] == "VERIFIED"
                           and checkpoint["disposition"] == "NO_DEV_CHANGE" else
                           "已创建 Dev commit" if checkpoint and checkpoint["verification"] == "VERIFIED" else "checkpoint 未核验/尚未形成")
            lines.append(f"最近已接受：{accepted['task_id']}（{disposition}）。Report：{accepted['report_ref']}")
        elif accepted["status"] == "NONE":
            lines.append("暂无已接受结果。")
        else:
            lines.append("最新接受状态无法核验；不以旧结果替代。")
        gate = view["gate"]
        notice = view.get('owner_notice')
        if notice and notice['verification'] == 'VERIFIED':
            lines.append(f"Decision / {notice['kind']}：{notice['body']}")
        if view['node'] in {'SOFT_REVIEW_WAIT', 'SOFT_ACCEPTANCE_WAIT'}:
            duration = 1800 if view['node'] == 'SOFT_REVIEW_WAIT' else 3600
            lines.append(f"当前为 {duration}s soft window；无反对不表示 Owner approval，明确反对立即停止。")
        if gate["reason"]:
            lines.append(f"停点/人工事项：{gate['reason']}")
        elif view["activity"]["status"] == "FAILED_UNKNOWN_EFFECTS":
            lines.append("失败后保留活动标记，副作用可能已发生；需定向核对。")
        elif gate["owner_accepted"]:
            lines.append("Owner 已接受本 Stage。")
        elif view.get('governance', {}).get('stage_closed'):
            lines.append("本 Stage 已按无反对窗口完成关闭；未记录 Owner approval。")
        elif view['node'] == 'SOFT_ACCEPTANCE_WAIT':
            lines.append("最终 Decision 收尾已完成，正在等待 soft acceptance 窗口；本 Stage 尚未关闭。")
        elif view['node'] == 'SOFT_REVIEW_WAIT':
            lines.append("已保存 Stage 开始通知，正在等待 soft review 窗口。")
        elif gate["machine_close_ready"] and gate["kind"] != "HUMAN_GATE":
            lines.append("早期收尾资格已核验；可读 Knowledge、同步、角色记忆和最终 Decision 仍按实际进度完成。")
        else:
            lines.append("当前没有明确的 Owner Gate；普通任务不新增 Decision 审批。")
        delegation = view.get("delegation")
        if delegation:
            managed = view.get("managed_run") or {}
            reason = ("自动链仍在运行，无需 Owner 继续请求。" if managed.get("automatic")
                      and (managed.get("presentation") or {}).get("state") == "RUNNING" else delegation["reason"])
            lines.append(f"托管：{delegation['scope']} / {delegation['target']['task_id'] or delegation['target']['stage_id']}；"
                         f"{delegation['status']}，{'仍在委托内继续' if delegation['continuing'] else '已停止派发'}。"
                         f"{reason}")
        if view["issues"]:
            lines.append(f"另有 {len(view['issues'])} 项证据缺口，见 issues。")
        presentation = view.get("managed_run", {}).get("presentation")
        if presentation:
            lines.append(f"托管现场：{presentation['state']}；{presentation['reason']}")
        return "\n".join(lines)


class StateProjection:
    def __init__(self, *, project: str, stage_id: str, workspace: Path, artifacts: ArtifactStore,
                 registry: ContextRegistry, state_provider: Callable[[], WorkflowState] | None,
                 source_ref: str, authority_materials: dict[str, str] | None = None,
                 is_busy: Callable[[], bool] | None = None, history_limit: int = 25) -> None:
        self.project, self.stage_id = identity(project), identity(stage_id)
        if (artifacts.project, artifacts.stage) != (project, stage_id):
            raise WorkflowError("projection ArtifactStore identity mismatch")
        if not isinstance(source_ref, str) or not source_ref.strip():
            raise WorkflowError("explicit projection source reference required")
        self.workspace, self.artifacts, self.registry = workspace.resolve(), artifacts, registry
        self.provider, self.source_ref, self.is_busy = state_provider, source_ref, is_busy
        self.activities = ActivityView(history_limit)
        self.authority = dict(authority_materials or {})
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.authority.items()):
            raise WorkflowError("Host authority materials must be explicit text references")

    def capture(self) -> StatusSnapshot:
        observed = utc_now()
        if self.provider is None:
            return self._unavailable("UNBOUND", "未绑定 runtime 状态来源", observed)
        try:
            state = copy.deepcopy(self.provider())
            if not isinstance(state, WorkflowState):
                raise WorkflowError("state provider did not supply WorkflowState")
            state.validate()
            if (state.project, state.stage_id) != (self.project, self.stage_id):
                raise WorkflowError("projection state identity mismatch")
            state_digest = _digest(state.as_dict())
            host_busy = bool(self.is_busy()) if self.is_busy else False
        except READ_ERRORS as exc:
            return self._unavailable("UNAVAILABLE", str(exc), observed)

        issues: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        materials: dict[str, str] = {}
        owners = list(dict.fromkeys(state.used_task_ids + ([state.task_id] if state.task_id else []) + [state.stage_id]))

        def record(kind: str, ref: str) -> dict[str, Any]:
            real_kind = ALIASES.get(kind, kind)
            known = next((item for item in evidence if item["kind"] == kind and item["reference"] == ref), None)
            if known is not None:
                return known
            path = ref.rsplit("#sha256=", 1)[0]
            item = {"kind": kind, "record_kind": real_kind, "reference": ref, "path": path,
                    "owner_id": None, "verification": "UNVERIFIED", "error": None}
            try:
                if real_kind not in ARTIFACT_KINDS:
                    raise WorkflowError("unknown formal artifact kind")
                name = Path(path).name
                suffix = r"\.md" if real_kind == "FINAL_TASK_CONSTRAINT" else r"_v[0-9]{3,}\.md"
                matches = [owner for owner in owners if re.fullmatch(re.escape(f"{owner}_{real_kind}") + suffix, name)]
                explicit_suffix = {"FINAL_TASK_CONSTRAINT": "_Task_Constraint.md",
                                   "EXECUTION_REPORT": "_Execution_Report.md"}.get(real_kind)
                if not matches and explicit_suffix:
                    matches = [owner for owner in owners if name == owner + explicit_suffix]
                # A project Store can explicitly support Owner-named frozen files.
                # Delegate that contract instead of requiring base Store filenames.
                if not matches:
                    for owner in owners:
                        try:
                            self.artifacts.assert_task_reference(ref, real_kind, owner)
                            matches.append(owner)
                        except READ_ERRORS:
                            pass
                if len(matches) != 1:
                    raise WorkflowError("artifact has no explicit Task/Stage owner in this snapshot")
                item["owner_id"] = matches[0]
                self.artifacts.assert_task_reference(ref, real_kind, matches[0])
                text = self.artifacts.read(ref)
                if not text.strip():
                    raise WorkflowError("empty formal artifact")
                materials[ref] = text
                item["verification"] = "VERIFIED"
            except READ_ERRORS as exc:
                item["error"] = str(exc)
                issues.append({"source": kind, "reference": ref, "problem": str(exc)})
            evidence.append(item)
            return item

        for kind, refs in state.artifact_refs.items():
            for ref in refs:
                record(kind, ref)
        for kind, ref in (("TASK_INTENT", state.formal_task_intent_ref),
                          ("FINAL_TASK_CONSTRAINT", state.formal_constraint_ref),
                          ("EXECUTION_REPORT", state.latest_execution_report_ref),
                          ("ACCEPTANCE", state.acceptance_ref)):
            if ref:
                item = record(kind, ref)
                if item["owner_id"] != state.task_id:
                    issues.append({"source": kind, "reference": ref, "problem": "current Task pointer ownership mismatch"})

        def body(ref: str) -> Any:
            if ref not in materials:
                raise WorkflowError("formal evidence is unavailable")
            return _json(materials[ref])

        def associated(kind: str, owner: str) -> dict[str, Any] | None:
            current_ref = {"EXECUTION_REPORT": state.latest_execution_report_ref,
                           "FINAL_TASK_CONSTRAINT": state.formal_constraint_ref}.get(kind)
            if owner == state.task_id and current_ref:
                return record(kind, current_ref)
            items = [item for item in evidence if item["kind"] == kind and item["owner_id"] == owner]
            return items[-1] if items else None

        checkpoints = {}
        for task_id, ref in state.task_checkpoint_refs.items():
            item = record("DECISION", ref)
            checkpoint = {"reference": ref, "verification": "UNVERIFIED", "disposition": None,
                          "receipt": None, "no_commit_evidence": None, "error": item["error"]}
            try:
                value = body(ref)
                if not isinstance(value, dict):
                    raise WorkflowError("checkpoint receipt is not an object")
                if value.get("origin") == "HOST_NO_DEV_CHANGE":
                    if (set(value) != {"origin", "task_id", "evidence"} or item["owner_id"] != task_id
                            or value["task_id"] != task_id or (task_id == state.task_id and state.commit_receipt is not None)):
                        raise WorkflowError("checkpoint is not this Task's separate no-commit proof")
                    verify_saved_no_commit(self.artifacts, value["evidence"], project=self.project, stage_id=self.stage_id,
                                           task_id=task_id, workspace=self.workspace, authority=self.authority)
                    binding = value["evidence"]["binding"]
                    if task_id == state.task_id and any(binding[key] != expected for key, expected in
                            (("intent_ref", state.formal_task_intent_ref), ("final_ref", state.formal_constraint_ref),
                             ("report_ref", state.latest_execution_report_ref), ("acceptance_ref", state.acceptance_ref))):
                        raise WorkflowError("current no-commit formal pointers disagree")
                    checkpoint.update(verification="VERIFIED", disposition="NO_DEV_CHANGE",
                                      no_commit_evidence=copy.deepcopy(value["evidence"]))
                    checkpoints[task_id] = checkpoint
                    continue
                receipt = value.get("receipt")
                if (item["owner_id"] != task_id or value.get("origin") != "HOST_COMMIT_RECEIPT"
                        or value.get("task_id") != task_id or not isinstance(receipt, dict)
                        or not isinstance(receipt.get("commit_hash"), str) or not receipt["commit_hash"]
                        or not isinstance(receipt.get("staged_files"), list) or not receipt["staged_files"]
                        or any(not isinstance(path, str) or not path for path in receipt["staged_files"])):
                    raise WorkflowError("checkpoint is not this Task's Host commit receipt")
                checkpoint.update(verification="VERIFIED", disposition="COMMIT_COMPLETE", receipt=copy.deepcopy(receipt))
            except READ_ERRORS as exc:
                checkpoint["error"] = str(exc)
                issues.append({"source": "checkpoint", "reference": ref, "problem": str(exc)})
            checkpoints[task_id] = checkpoint

        history = state.artifact_refs.get("ACCEPTANCE", [])
        candidate = history[-1] if history else state.acceptance_ref
        latest = {"status": "NONE" if not candidate else "UNVERIFIED", "task_id": None,
                  "acceptance_ref": candidate, "report_ref": None, "final_ref": None, "checkpoint": None}
        if candidate:
            item = record("ACCEPTANCE", candidate)
            latest["task_id"] = item["owner_id"]
            try:
                if state.acceptance_ref and (not history or state.acceptance_ref != candidate):
                    raise WorkflowError("current acceptance pointer disagrees with ordered acceptance history")
                value = body(candidate)
                value = {**{'issues': [], 'triage': [], 'knowledge': None, 'completion': None, 'stage_plan': None}, **value}
                validate(value, result_schema(Node.PROMOTER_RESULT_REVIEW))
                if value["action"] != "TASK_ACCEPTED" or not value["evidence"] or not all(value["evidence"].values()):
                    raise WorkflowError("candidate is not explicit Promoter acceptance with required evidence")
                task_id = item["owner_id"]
                if task_id not in state.used_task_ids:
                    raise WorkflowError("acceptance is not for an explicitly used Task")
                report, final = associated("EXECUTION_REPORT", task_id), associated("FINAL_TASK_CONSTRAINT", task_id)
                latest.update(report_ref=report["reference"] if report else None,
                              final_ref=final["reference"] if final else None, checkpoint=checkpoints.get(task_id))
                if not report or not final or any(x["verification"] != "VERIFIED" for x in (report, final)):
                    raise WorkflowError("accepted Task Report/Final cannot be verified")
                latest["status"] = "VERIFIED"
            except READ_ERRORS as exc:
                issues.append({"source": "latest_accepted", "reference": candidate, "problem": str(exc)})

        goal = None
        if state.formal_task_intent_ref:
            try:
                if record("TASK_INTENT", state.formal_task_intent_ref)["owner_id"] != state.task_id:
                    raise WorkflowError("current Task Intent reference ownership mismatch")
                value = body(state.formal_task_intent_ref)
                value = {'relationship': None, **value}
                validate(value, INTENT_SCHEMA)
                if value["task_id"] != state.task_id:
                    raise WorkflowError("Task Intent body identity mismatch")
                goal = value["goal"]
            except READ_ERRORS as exc:
                issues.append({"source": "task_goal", "reference": state.formal_task_intent_ref, "problem": str(exc)})

        stage_input = {"reference": state.stage_input_ref, "verification": "UNVERIFIED", "content": None}
        if state.stage_input_ref:
            if "#sha256=" in state.stage_input_ref:
                try:
                    text = self.artifacts.read(state.stage_input_ref)
                    materials[state.stage_input_ref] = text
                    stage_input.update(verification="VERIFIED", content=text)
                except READ_ERRORS as exc:
                    issues.append({"source": "stage_input", "reference": state.stage_input_ref, "problem": str(exc)})
            elif state.stage_input_ref in self.authority:
                text = self.authority[state.stage_input_ref]
                materials[state.stage_input_ref] = text
                stage_input.update(verification="HOST_SUPPLIED", content=text)
            else:
                issues.append({"source": "stage_input", "reference": state.stage_input_ref,
                               "problem": "Stage input content is not supplied by the bound Host"})

        contexts = {}
        refs = {**state.role_context_refs, "Executor": state.executor_context_ref, "Review": state.active_review_context_ref}
        for role, ref in refs.items():
            if not ref:
                continue
            try:
                value = copy.deepcopy(self.registry.get(ref).as_dict())
                if Path(value["workspace"]).resolve() != self.workspace:
                    raise WorkflowError("Context workspace mismatch")
                metadata = value.get("activity_metadata") or {}
                if not isinstance(metadata, dict):
                    raise WorkflowError("Context metadata is not an object")
                if metadata.get("stage", self.stage_id) != self.stage_id:
                    raise WorkflowError("Context Stage mismatch")
                contexts[role] = {"verification": "VERIFIED", "record": value}
            except READ_ERRORS as exc:
                contexts[role] = {"verification": "UNVERIFIED", "reference": ref, "error": str(exc)}
                issues.append({"source": "context", "reference": ref, "problem": str(exc)})

        activity_status = ("FAILED_UNKNOWN_EFFECTS" if state.status == "FAILED" and state.in_flight_activity else
                           state.status if state.status != "RUNNING" else
                           "IN_FLIGHT" if state.in_flight_activity or host_busy else "IDLE_PENDING_DISPATCH")
        gate_kind = state.current_node if state.current_node in {"HUMAN_GATE", "HUMAN_BLOCK", "RECOVERY_REQUIRED"} else None
        events = {"HUMAN_GATE": ["APPROVE_STAGE", "REJECT_STAGE", "REQUEST_MORE_WORK"],
                  'SOFT_REVIEW_WAIT': ['COMPLETE_STAGE_REVIEW'],
                  'SOFT_ACCEPTANCE_WAIT': ['APPROVE_STAGE', 'REJECT_STAGE', 'REQUEST_MORE_WORK'],
                  "HUMAN_BLOCK": ["RESOLVE_HUMAN_BLOCK"], "RECOVERY_REQUIRED": ["RESOLVE_HUMAN_BLOCK"]}
        if (state.current_node in {'HUMAN_BLOCK', 'RECOVERY_REQUIRED'} and state.task_id and not state.in_flight_activity
                and state.latest_execution_report_ref and state.decision_handoff_ref and state.mediation_result_ref
                and not state.acceptance_ref and not state.commit_receipt
                and state.task_id not in state.task_checkpoint_refs):
            events[state.current_node].append('REQUEST_SAME_TASK_REPAIR')
            # Publish only the explicitly bound trusted admission inputs. The
            # Engine revalidates their full source chain before any transition.
            for ref, raw in self.authority.items():
                try:
                    value = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if (not isinstance(value, dict) or value.get('origin') not in {
                        'OWNER_SAME_TASK_REPAIR_AUTHORIZATION', 'OWNER_KNOWN_INTERNAL_FINDING_REPAIR_AUTHORIZATION'}
                        or (value.get('project'), value.get('stage_id'), value.get('task_id'), value.get('final_ref')) !=
                           (state.project, state.stage_id, state.task_id, state.formal_constraint_ref)):
                    continue
                for candidate in (ref, value.get('owner_source_ref'), value.get('admission_ref')):
                    if not isinstance(candidate, str):
                        continue
                    text = self.authority.get(candidate)
                    if isinstance(candidate, str) and isinstance(text, str):
                        _, marker, expected = candidate.rpartition('#sha256=')
                        if marker and hashlib.sha256(text.encode('utf-8')).hexdigest() == expected:
                            materials[candidate] = text
        reason = state.human_gate_reason
        if state.status == "FAILED":
            reason = (state.last_result or {}).get("error") or "Failure reason unavailable; inspect actual effects."
        current_acceptance = "NO_CURRENT_TASK" if not state.task_id else "PENDING"
        if state.acceptance_ref:
            current_acceptance = "ACCEPTED" if (latest["status"] == "VERIFIED" and latest["task_id"] == state.task_id) else "UNVERIFIED"
        elif state.task_id and latest["task_id"] == state.task_id:
            current_acceptance = "UNVERIFIED"
            issues.append({"source": "acceptance_ref", "reference": latest["acceptance_ref"],
                           "problem": "current Task has acceptance history but no current acceptance pointer"})
        if state.commit_receipt and (state.task_id not in checkpoints or
                checkpoints[state.task_id]["receipt"] != state.commit_receipt):
            issues.append({"source": "commit_receipt", "reference": None,
                           "problem": "current commit receipt disagrees with saved Task checkpoint"})
            if state.task_id in checkpoints:
                checkpoints[state.task_id]["verification"] = "UNVERIFIED"
                checkpoints[state.task_id]["error"] = "current commit receipt conflicts with saved checkpoint"

        view = {"schema_version": 1, "availability": "AVAILABLE", "observed_at": observed,
                "project": state.project, "stage_id": state.stage_id, "workspace": str(self.workspace),
                "source": {"reference": self.source_ref, "state_sha256": state_digest},
                "node": state.current_node, "status": state.status, "stage_input": stage_input,
                "task": {"task_id": state.task_id, "goal": goal, "intent_ref": state.formal_task_intent_ref,
                         "final_ref": state.formal_constraint_ref, "report_ref": state.latest_execution_report_ref,
                         "acceptance_ref": state.acceptance_ref, "acceptance_status": current_acceptance,
                         "formal_refs": {kind: {"reference": ref, "verification":
                             "VERIFIED" if record(kind, ref)["verification"] == "VERIFIED" and
                             record(kind, ref)["owner_id"] == state.task_id else "UNVERIFIED"}
                             for kind, ref in (("TASK_INTENT", state.formal_task_intent_ref),
                                               ("FINAL_TASK_CONSTRAINT", state.formal_constraint_ref),
                                               ("EXECUTION_REPORT", state.latest_execution_report_ref)) if ref}},
                "activity": {"status": activity_status, "in_flight": state.in_flight_activity,
                             "last_completed": state.last_completed_activity, "host_busy": host_busy,
                             "last_result": copy.deepcopy(state.last_result)},
                "latest_accepted": latest, "checkpoints": checkpoints, "contexts": contexts,
                "gate": {"kind": gate_kind, "reason": reason, "machine_close_ready": state.machine_close_ready,
                         "owner_accepted": state.owner_accepted, "available_events": events.get(gate_kind, []),
                         "events": copy.deepcopy(state.human_events),
                         "stage_record_refs": list(state.artifact_refs.get("STAGE_RECORD", []))},
                "evidence": evidence, "issues": issues}
        view['governance'] = {'grant': copy.deepcopy(state.active_grant), 'scope_completion': copy.deepcopy(state.scope_completion),
            'stage_closed': state.stage_closed, 'plan_ref': state.stage_plan_ref,
            'notice_ref': state.stage_notice_ref, 'knowledge_ref': state.stage_knowledge_ref,
            'closeout_ref': state.stage_closeout_ref, 'issue_triage': copy.deepcopy(state.issue_triage),
            'stage_issues': copy.deepcopy(state.stage_issues), 'soft_window_events': copy.deepcopy(state.soft_window_events),
            'decision_handoff_ref': state.decision_handoff_ref, 'mediation_result_ref': state.mediation_result_ref,
            'latest_decision_notice_ref': state.latest_decision_notice_ref, 'owner_window_refs': list(state.owner_window_refs)}
        view['gate']['available_events'] = events.get(state.current_node, [])
        view['owner_notice'] = None
        if state.latest_decision_notice_ref:
            ref = state.latest_decision_notice_ref
            try:
                if record('DECISION', ref)['verification'] != 'VERIFIED':
                    raise WorkflowError('current Decision notice reference is unverified')
                value = body(ref)
                origin = value.get('origin')
                if origin == 'STAGE_PLAN_OWNER_NOTICE':
                    kind, notice = 'STAGE_START', value['summary']
                elif value.get('action') == 'SUMMARY_READY':
                    kind, notice = 'STAGE_CLOSEOUT', value['owner_summary']
                elif origin == 'DECISION_OWNER_NOTICE':
                    kind, notice = value['outcome'], value['body']
                elif origin == 'HOST_URGENT_OWNER_STOP':
                    kind, notice = 'FACTUAL_OWNER_STOP', value['request']['direction']
                else:
                    raise WorkflowError('unknown current Decision notice contract')
                if not isinstance(notice, str) or not notice.strip():
                    raise WorkflowError('current Decision notice body unavailable')
                view['owner_notice'] = {'reference': ref, 'kind': kind, 'body': notice[:2400],
                    'body_truncated': len(notice) > 2400, 'verification': 'VERIFIED', 'owner_accepted': False}
            except READ_ERRORS as exc:
                view['owner_notice'] = {'reference': ref, 'verification': 'UNVERIFIED', 'error': str(exc)}
                issues.append({'source': 'owner_notice', 'reference': ref, 'problem': str(exc)})
        view["activities"] = self.activities.observe(view, materials)
        try:
            view['task_history'] = task_closure_history(self.artifacts, state.used_task_ids, state.artifact_refs,
                                                       state.task_checkpoint_refs, state.task_relationships)
        except READ_ERRORS as exc:
            view['task_history'] = None
            issues.append({'source': 'task_history', 'reference': None, 'problem': str(exc)})
        # Turn bookkeeping is excluded; changed Context identity/freshness/policy is material.
        context_identity = {role: {"verification": item["verification"],
            "identity": {key: item["record"].get(key) for key in
                         ("thread_id", "purpose", "freshness", "workspace", "tool_profile", "activity_metadata")}
                        if item["verification"] == "VERIFIED" else item.get("error")}
            for role, item in contexts.items()}
        revision = _digest({"state": state_digest, "materials": materials, "evidence": evidence,
                            "contexts": context_identity})
        return StatusSnapshot(view, materials, revision)

    def _unavailable(self, availability: str, problem: str, observed: str) -> StatusSnapshot:
        view = {"schema_version": 1, "availability": availability, "observed_at": observed,
                "project": self.project, "stage_id": self.stage_id, "workspace": str(self.workspace),
                "source": {"reference": self.source_ref}, "issues": [{"source": "state", "problem": problem}]}
        view["activities"] = self.activities.observe(view, {})
        return StatusSnapshot(view, {}, _digest(view["issues"]))
