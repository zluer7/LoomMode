"""Deterministic roles/executor for route tests, no semantic model substitute."""
import copy
import json
import re
from pathlib import Path
from loommode.roles.contracts import empty_result
from loommode.roles.runtime import Invocation
from loommode.workflow.artifacts import ArtifactStore
from loommode.workflow.engine import WorkflowEngine, REQUIRED_ARTIFACT
from loommode.workflow.state import StateStore, WorkflowState
from loommode.workflow.transitions import Node


def response(node: Node, action: str, **fields):
    result = empty_result(action)
    if node in REQUIRED_ARTIFACT:
        result["artifacts"] = [{"kind": REQUIRED_ARTIFACT[node], "content": f"Formal {node.value} fixture artifact"}]
        if REQUIRED_ARTIFACT[node] == 'DECISION':
            result['artifacts'][0]['content'] = json.dumps({'scripted_artifact': result['artifacts'][0]['content']})
    result.update(fields)
    return result


def intent(task_id="FX-A1-A0", path="NORMAL"):
    return {"task_id": task_id, "goal": "Correct fixture arithmetic", "why_now": "Fixture validation",
            "scope": ["calc.py"], "authority_refs": ["owner"], "expected_result": "Addition passes",
            "acceptance_intent": "Passing tests and self-review", "workflow_path": path,
            "fast_authorization_ref": "owner" if path == "FAST" else None,
            "execution_input": "Only repair calc.py, run unit test, report; stop if outside scope." if path == "FAST" else None,
            "model_override": None, "independent_review_suggested": False, "decision_suggested": False, 'relationship': None}


def mediation(outcome='HARD_GATE', **fields):
    return response(Node.DECISION_MEDIATION, 'MEDIATION_READY', mediation={
        'handoff_ref': 'FIXTURE_ACTUAL_HANDOFF', 'outcome': outcome,
        'reason': 'Explicit scripted Decision treatment under actual recorded limits.',
        'notice': 'Scripted Decision notice: inspect the bound finding; no permission or retry expansion.'}, **fields)


PASS_EVIDENCE = {k: True for k in ["goals_met", "tests_passed", "self_review_done", "nonblocking_handled", "report_complete"]}


def governed_script(script):
    """Explicit scripted new judgments, leaving old Task-index fixture construction intact."""
    result = []
    nodes = {node for node, _ in script}
    for node, reply in copy.deepcopy(script):
        if node == Node.STAGE_CLOSE_SYNC and Node.STAGE_KNOWLEDGE not in nodes:
            result.append((Node.STAGE_KNOWLEDGE, response(Node.STAGE_KNOWLEDGE, 'KNOWLEDGE_READY', evidence=PASS_EVIDENCE)))
        if node == Node.OWNER_SUMMARY:
            reply['evidence'] = reply['evidence'] or dict(PASS_EVIDENCE)
        result.append((node, reply))
        if node == Node.STAGE_PLANNING and Node.STAGE_PLAN_DECISION not in nodes:
            result.append((Node.STAGE_PLAN_DECISION, response(Node.STAGE_PLAN_DECISION, 'PLAN_ACCEPTED',
                owner_summary='Scripted Decision reviewed actual fixture Stage goal, plan, risks and bounded authorization; Owner may pause.')))
        if node == Node.STAGE_SETTLEMENT and reply['action'] == 'STAGE_ACCEPTED' and Node.STAGE_ISSUE_TRIAGE not in nodes:
            result.append((Node.STAGE_ISSUE_TRIAGE, response(Node.STAGE_ISSUE_TRIAGE, 'TRIAGE_READY')))
    return result


def fill_governance_result(node, reply, state, role=None):
    """Scripted semantic choices based on actual fields; never a native-model claim."""
    if reply['action'] in {'HUMAN_REQUIRED', 'OWNER_REQUIRED'} and reply['escalation'] is None:
        from loommode.workflow.transitions import TABLE
        reply['escalation'] = {'origin_role': role or TABLE[node][0].value, 'origin_activity': node.value,
            'stage_id': state['stage_id'], 'task_id': state['task_id'], 'category': 'TRUE_UNRESOLVED_BLOCKER',
            'reason': 'Explicit scripted protected finding; no native semantic judgment.',
            'evidence_refs': [state['stage_input_ref']], 'requested_treatment': 'HARD_GATE'}
    if node == Node.DECISION_MEDIATION and reply['mediation'] is not None and reply['mediation']['handoff_ref'] == 'FIXTURE_ACTUAL_HANDOFF':
        reply['mediation']['handoff_ref'] = state['decision_handoff_ref']
    relation = (reply.get('intent') or {}).get('relationship')
    if relation and relation['parent_ref'] == 'FIXTURE_ACTUAL_PARENT_INTENT':
        if state['task_id'] != relation['parent_task_id']:
            raise AssertionError('scripted relationship does not name actual preceding parent')
        relation['parent_ref'] = state['formal_task_intent_ref']
    if node == Node.STAGE_PLANNING and reply['action'] == 'PLAN_READY' and reply['stage_plan'] is None:
        reply['stage_plan'] = {'stage_id': state['stage_id'], 'goal': 'Verify bounded fixture arithmetic and workflow governance',
            'functional_outcomes': ['Actual fixed checks and truthful checkpoint completion'],
            'series': [state['stage_id'] + '-A'], 'initial_tasks': [state['stage_id'] + '-A0'],
            'risks': ['Scripted envelopes prove mechanics only; no native semantic acceptance'],
            'authority_refs': [state['stage_input_ref']], 'acceptance_focus': ['Actual inputs, checks, closure and Owner approval false']}
    if node == Node.STAGE_KNOWLEDGE and reply['knowledge'] is None:
        reply['knowledge'] = {'stage_id': state['stage_id'], 'goal': 'Verify bounded fixture arithmetic and workflow governance',
            'plan_ref': state['stage_plan_ref'], 'approved_plan_summary': 'Fresh fixture review and Decision-reviewed bounded plan with explicit risks and fixed checks.',
            'chain': [{'task_id': task, 'series_id': re.sub(r'[0-9]+(?:-[RF][0-9]+)?$', '', task),
                'reason': 'Verify the actual bounded fixture milestone under its original input.',
                'outcome': ('Accepted actual checkpoint is retained with its exact evidence.' if task in state['task_checkpoint_refs'] else
                            'This prior Task has no accepted checkpoint; preserve its actual input/report and unaccepted outcome.'),
                'repairs_followups': 'Same-Final repairs and Follow-ups remain recorded in original reports/receipts.',
                'checkpoint_ref': state['task_checkpoint_refs'].get(task),
                'disposition': 'ACCEPTED' if task in state['task_checkpoint_refs'] else 'NOT_ACCEPTED',
                'evidence_refs': ([state['task_checkpoint_refs'][task]] if task in state['task_checkpoint_refs'] else
                    [ref for refs in state['artifact_refs'].values() for ref in refs if Path(ref.split('#sha256=')[0]).name.startswith(task + '_')])} for task in state['used_task_ids']],
            'outcomes': 'Actual accepted Task chain, fresh Stage judgment, sync and truthful Owner boundary.',
            'residuals': ['Scripted mechanical fixture only; native semantic acceptance not established.'],
            'acceptance_ref': state['stage_acceptance_ref'], 'acceptance_distinctions': 'Task checkpoints and Stage machine acceptance are separate; Owner acceptance remains false.',
            'evidence_refs': [state['stage_plan_ref'], state['stage_acceptance_ref']]}
    return reply


def install_test_windows(engine):
    """Inject explicit zero-duration Host timers into old mechanical fixtures."""
    from types import SimpleNamespace
    from loommode.host.windows import SoftWindows
    engine._test_window_configuration = {'clock': lambda: 0.0,
        'scheduler': lambda delay, callback: (callback() or SimpleNamespace(cancel=lambda: None)),
        'test_durations': (0.0, 0.0)}
    owner = SimpleNamespace(engine=engine, stop_requested=False)
    windows = SoftWindows(owner, **engine._test_window_configuration)
    engine._test_windows = windows
    original = engine.step
    engine._unwrapped_step = original

    def step(**kwargs):
        original(**kwargs)
        active = getattr(engine, '_test_bound_host', None)
        controller = active.windows if active is not None else windows
        controller.arm()
        controller.consume()
        return engine.state

    engine.step = step


def normal_script(path="NORMAL"):
    script = [
        (Node.STAGE_REVIEW, response(Node.STAGE_REVIEW, "REVIEW_READY")),
        (Node.STAGE_PLANNING, response(Node.STAGE_PLANNING, "PLAN_READY")),
        (Node.TASK_SELECTION, response(Node.TASK_SELECTION, "TASK_INTENT_READY", intent=intent(path=path))),
    ]
    if path == "NORMAL":
        script += [(Node.CONSTRAINT_DRAFT, response(Node.CONSTRAINT_DRAFT, "DRAFT_READY")),
                   (Node.DISCUSS_NORMAL, response(Node.DISCUSS_NORMAL, "NO_CHANGE")),
                   (Node.CONSTRAINT_FINALIZE, response(Node.CONSTRAINT_FINALIZE, "FINAL_READY"))]
    return script + [
        (Node.EXECUTOR_IMPLEMENT, response(Node.EXECUTOR_IMPLEMENT, "REPORT_READY", evidence=PASS_EVIDENCE)),
        (Node.PROMOTER_RESULT_REVIEW, response(Node.PROMOTER_RESULT_REVIEW, "TASK_ACCEPTED", evidence=PASS_EVIDENCE)),
        (Node.EXECUTOR_LOCAL_COMMIT, response(Node.EXECUTOR_LOCAL_COMMIT, "COMMIT_COMPLETE")),
        (Node.TASK_SELECTION, response(Node.TASK_SELECTION, "STAGE_READY")),
        (Node.STAGE_ACCEPTANCE, response(Node.STAGE_ACCEPTANCE, "REVIEW_READY")),
        (Node.STAGE_SETTLEMENT, response(Node.STAGE_SETTLEMENT, "STAGE_ACCEPTED")),
        (Node.STAGE_MACHINE_CLOSE, response(Node.STAGE_MACHINE_CLOSE, "MACHINE_CLOSE_READY")),
        (Node.STAGE_CLOSE_SYNC, response(Node.STAGE_CLOSE_SYNC, "SYNC_READY", sync=[
            {"target": target, "outcome": "NO_CHANGE", "content": None, "authority_ref": None}
            for target in ["HIGHEST_CONTRACT", "PROGRAM_NOTE", "CURRENT", "DEVELOPMENT_PRINCIPLES", "ISSUE_LEDGER", "ROLE_MEMORY"]])),
        *[(Node.ROLE_MEMORY_CONSOLIDATION, response(Node.ROLE_MEMORY_CONSOLIDATION, "MEMORY_READY")) for _ in range(4)],
        (Node.OWNER_SUMMARY, response(Node.OWNER_SUMMARY, "SUMMARY_READY", owner_summary="Fixture Stage machine closed; Owner decision pending.")),
    ]


class ScriptedParticipants:
    @property
    def script(self):
        return self._script

    @script.setter
    def script(self, value):
        self._script = governed_script(value)

    def __init__(self, script):
        self.script = governed_script(script)
        self.calls = []
        self.granted = False
        self.transfers = []
        self.suspensions = 0

    def invoke(self, *args):
        if isinstance(args[0], Node):
            node, state, materials = args[:3]
            role = "Executor"
        else:
            role, node, state, materials = args[:4]
            role = role.value
        if node == Node.DECISION_MEDIATION and (not self.script or self.script[0][0] != node):
            expected, result = node, mediation()
        else:
            expected, result = self.script.pop(0)
        if expected != node:
            raise AssertionError(f"expected {expected}, got {node}")
        fill_governance_result(node, result, state, role)
        context = f"fresh-{len(self.calls)}" if node in {Node.STAGE_REVIEW, Node.STAGE_ACCEPTANCE, Node.INDEPENDENT_REVIEW} else f"stage-{role}"
        self.calls.append({"role": role, "node": node, "state": copy.deepcopy(state), "materials": dict(materials), "context": context})
        receipt = None
        if node == Node.EXECUTOR_LOCAL_COMMIT and result["action"] == "COMMIT_COMPLETE":
            assert self.granted
            receipt = {"commit_hash": "a" * 40, "staged_files": ["calc.py"], "message": "[FX-A1-A0] exact commit", "final_status": ""}
            self.granted = False
        return Invocation(result, context, receipt)

    def authorize_commit(self, state):
        assert state["current_node"] == Node.COMMIT_AUTHORIZATION.value
        assert state["acceptance_ref"] and state["latest_execution_report_ref"]
        self.granted = True

    def transfer_review_for_repair(self, task_id, review_ref):
        self.transfers.append((task_id, review_ref))

    def suspend(self):
        self.suspensions += 1


def make_engine(root: Path, script, *, grant=True, artifact_store=None, workspace=None):
    participants = ScriptedParticipants(script)
    artifacts = artifact_store or ArtifactStore(root / "Records", "FX", "FX-A1")
    from types import SimpleNamespace
    participants.stage_policy = SimpleNamespace(workspace=(workspace or artifacts.root.parent / 'Dev').resolve())
    engine = WorkflowEngine(WorkflowState("FX", "FX-A1"), StateStore(root / "DevEnv", "FX", "FX-A1"),
                            artifacts, participants, participants, {"owner": "Explicit fixture authorization"},
                            stage_authorization_ref="owner", local_commit_authorized=grant)
    install_test_windows(engine)
    return engine, participants
