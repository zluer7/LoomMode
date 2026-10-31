import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from loommode.codex.adapter import AdapterConfig, ThinCodexAdapter
from loommode.codex.app_server import AppServerClient
from loommode.codex.context import ContextPurpose, ContextRegistry, FreshnessState
from loommode.codex.errors import LoomModeError
from loommode.roles.contracts import empty_result, parse_result, result_schema
from loommode.roles.runtime import RoleRuntime, current_verified_profiles
from loommode.tools.filesystem import WorkspaceGuard
from loommode.tools.runtime import BoundedToolRuntime, ToolPhase, ToolPolicy, ToolProfile
from loommode.tools.test_runner import TestSpec
from loommode.workflow.errors import WorkflowError
from loommode.workflow.executor import ExecutorRuntime
from loommode.workflow.state import WorkflowState
from loommode.workflow.transitions import Node, Role
from tests.fake_workflow_adapter import FakeWorkflowAdapter
from tests.support import make_repo, run
from tests.workflow_support import response, PASS_EVIDENCE, intent, make_engine, normal_script


def policy(repo, profile=ToolProfile.BOUNDED_DEVELOPMENT):
    return ToolPolicy(repo, profile, ("calc.py", "test_calc.py"), ("calc.py",), ("calc.py",),
                      (TestSpec("unit", (sys.executable, "-m", "unittest", "-v")),), ("[FX-A1-A0] exact commit",))


class CommitRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.temp.name) / "repo")
        self.runtime = BoundedToolRuntime(policy(self.repo))

    def tearDown(self):
        self.temp.cleanup()

    def call(self, tool, **arguments):
        return self.runtime.handle_call({"tool": tool, "arguments": arguments})

    def test_implementation_denies_stage_commit_then_commit_phase_denies_write(self):
        self.assertFalse(self.call("loommode_git_stage", paths=["calc.py"])["success"])
        self.assertFalse(self.call("loommode_git_commit", message="[FX-A1-A0] exact commit")["success"])
        self.assertTrue(self.call("loommode_replace_file", path="calc.py", expected="left - right", replacement="left + right")["success"])
        self.runtime.suspend_mutations()
        self.assertFalse(self.call("loommode_replace_file", path="calc.py", expected="left + right", replacement="left - right")["success"])
        self.runtime.authorize_commit(acceptance_ref="promoter-accepted", report_ref="frozen-report")
        self.assertFalse(self.call("loommode_replace_file", path="calc.py", expected="left + right", replacement="left - right")["success"])
        self.assertTrue(self.call("loommode_git_stage", paths=["calc.py"])["success"])
        result = self.call("loommode_git_commit", message="[FX-A1-A0] exact commit")
        self.assertTrue(result["success"])
        self.assertEqual(self.runtime.phase, ToolPhase.SUSPENDED)
        self.assertFalse(self.call("loommode_git_commit", message="[FX-A1-A0] exact commit")["success"])
        with self.assertRaises(LoomModeError):
            self.runtime.authorize_commit(acceptance_ref="again", report_ref="again")
        self.assertEqual(run(["git", "rev-list", "--count", "HEAD"], self.repo).stdout.strip(), "2")

    def test_task_grants_narrow_and_next_task_revokes_commit(self):
        narrow = replace(policy(self.repo), stageable_paths=(), commit_messages=())
        self.runtime.configure_task(narrow)
        self.runtime.authorize_commit(acceptance_ref="accepted", report_ref="report")
        self.assertFalse(self.call("loommode_git_stage", paths=["calc.py"])["success"])
        self.runtime.configure_task(policy(self.repo))
        self.assertEqual(self.runtime.phase, ToolPhase.IMPLEMENTATION)
        self.assertFalse(self.call("loommode_git_stage", paths=["calc.py"])["success"])
        with self.assertRaises(LoomModeError):
            self.runtime.configure_task(replace(policy(self.repo), readable_paths=("calc.py", "test_calc.py", "unknown.py")))

    def test_read_only_cannot_get_commit_permission_or_write(self):
        runtime = BoundedToolRuntime(policy(self.repo, ToolProfile.READ_ONLY_REVIEW))
        with self.assertRaises(LoomModeError):
            runtime.authorize_commit(acceptance_ref="accepted", report_ref="report")
        self.assertFalse(runtime.handle_call({"tool": "loommode_git_stage", "arguments": {"paths": ["calc.py"]}})["success"])

    def test_unknown_staged_deletion_is_not_hidden_from_commit_gate(self):
        run(["git", "rm", "--", "test_calc.py"], self.repo)
        self.runtime.authorize_commit(acceptance_ref="accepted", report_ref="report")
        self.assertFalse(self.call("loommode_git_commit", message="[FX-A1-A0] exact commit")["success"])
        self.assertIsNone(self.runtime.last_commit_receipt)

    def test_invalid_commit_refs_and_reauthorization_fail_closed(self):
        with self.assertRaises(LoomModeError):
            self.runtime.authorize_commit(acceptance_ref="", report_ref="report")
        self.runtime.authorize_commit(acceptance_ref="accepted", report_ref="report")
        self.runtime.suspend_mutations()
        with self.assertRaises(LoomModeError):
            self.runtime.authorize_commit(acceptance_ref="accepted", report_ref="report")


class RuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = make_repo(self.root / "repo")
        self.role_files = {}
        for role in Role:
            if role != Role.EXECUTOR:
                path = self.root / f"{role.value}.md"
                path.write_text(f"# {role.value}\n## Part I — Fixed Role Definition\nFixed duties\n## Part II — Long-term Role Experience\nExperience grants no permission", encoding="utf-8")
                self.role_files[role] = path

    def tearDown(self):
        self.temp.cleanup()

    def test_role_context_resume_reinjects_raw_intent_actual_definition_and_schema(self):
        adapter = FakeWorkflowAdapter([(Node.CONSTRAINT_DRAFT, response(Node.CONSTRAINT_DRAFT, "DRAFT_READY"))] * 2)
        roles = RoleRuntime(adapter, self.role_files, ToolPolicy(self.repo, ToolProfile.READ_ONLY_REVIEW, ("calc.py",)), current_verified_profiles(), "FX-A1")
        state = WorkflowState("FX", "FX-A1").as_dict()
        first = roles.invoke(Role.CONSTRAINT, Node.CONSTRAINT_DRAFT, state, {"RAW_INTENT": "original input 1", "AUTHORITY": "formal scope"})
        second = roles.invoke(Role.CONSTRAINT, Node.CONSTRAINT_DRAFT, state, {"RAW_INTENT": "original input 2", "AUTHORITY": "formal scope"})
        self.assertEqual(first.context_ref, second.context_ref)
        self.assertEqual(roles.last_metadata['turn_id'], second.metadata['turn_id'])
        self.assertTrue(roles.last_metadata['success'])
        self.assertIn(first.context_ref, adapter.resumed)
        self.assertIn("original input 2", adapter.prompts[-1]["prompt"])
        self.assertIn("Part I", adapter.prompts[-1]["prompt"])
        self.assertIn("Part II", adapter.prompts[-1]["prompt"])
        self.assertEqual(adapter.registry.get(first.context_ref).freshness, FreshnessState.READ_ONLY_ROLE)
        with self.assertRaises(WorkflowError):
            roles.invoke(Role.DECISION, Node.CONSTRAINT_DRAFT, state, {"RAW_INTENT": "input"})
        with self.assertRaises(WorkflowError):
            roles.invoke(Role.CONSTRAINT, Node.CONSTRAINT_DRAFT, {**state, "stage_id": "other"}, {})

    def test_role_runtime_rejects_write_policy(self):
        with self.assertRaises(WorkflowError):
            RoleRuntime(FakeWorkflowAdapter([]), self.role_files, policy(self.repo, ToolProfile.READ_ONLY_REVIEW), current_verified_profiles(), "FX-A1")

    def test_host_task_policy_provider_continues_one_stage_executor(self):
        adapter = FakeWorkflowAdapter([(Node.EXECUTOR_IMPLEMENT, response(Node.EXECUTOR_IMPLEMENT, "REPORT_READY", evidence=PASS_EVIDENCE))] * 2)
        first = policy(self.repo)
        second = replace(first, commit_messages=("[FX-A1-A1] exact commit",))
        stage = replace(first, commit_messages=first.commit_messages + second.commit_messages)
        looked_up = []
        def host_policy(task_id):
            looked_up.append(task_id)
            return {"FX-A1-A0": first, "FX-A1-A1": second}[task_id]
        executor = ExecutorRuntime(adapter, stage, {}, current_verified_profiles(), task_policy_provider=host_policy)
        refs = []
        for task_id in ("FX-A1-A0", "FX-A1-A1"):
            state = WorkflowState("FX", "FX-A1", task_id=task_id, formal_task_intent_ref='intent-ref', formal_constraint_ref="final-ref").as_dict()
            refs.append(executor.invoke(Node.EXECUTOR_IMPLEMENT, state, {"intent-ref": json.dumps(intent(task_id)), "final-ref": "Explicit frozen input"}).context_ref)
        self.assertEqual(refs[0], refs[1])
        self.assertEqual(looked_up, ["FX-A1-A0", "FX-A1-A1"])
        self.assertIn(refs[0], adapter.resumed)

    def test_task_commit_policy_requires_full_task_identity(self):
        executor = ExecutorRuntime(FakeWorkflowAdapter([]), policy(self.repo), {"FX-A1-A1": policy(self.repo)}, current_verified_profiles())
        with self.assertRaises(WorkflowError):
            executor._task_policy("FX-A1-A1")

    def test_executor_commit_human_required_needs_no_fake_receipt(self):
        adapter = FakeWorkflowAdapter([(Node.EXECUTOR_LOCAL_COMMIT, response(Node.EXECUTOR_LOCAL_COMMIT, "HUMAN_REQUIRED",
            escalation={'origin_role':'Executor','origin_activity':Node.EXECUTOR_LOCAL_COMMIT.value,
                'stage_id':'FX-A1','task_id':'FX-A1-A0','category':'TRUE_UNRESOLVED_BLOCKER',
                'reason':'Actual no-change checkpoint requires explicit disposition.','evidence_refs':['final'],
                'requested_treatment':'HARD_GATE'}))])
        executor = ExecutorRuntime(adapter, policy(self.repo), {"FX-A1-A0": policy(self.repo)}, current_verified_profiles())
        context = adapter.start_context(workspace=self.repo, purpose=ContextPurpose.DEVELOPMENT,
                                        model="gpt-6.1-sol", reasoning_effort="low", tool_policy=policy(self.repo))
        executor.main_context = context.thread_id
        adapter.authorize_commit(context.thread_id, acceptance_ref="accepted", report_ref="report")
        state = WorkflowState("FX", "FX-A1", task_id="FX-A1-A0").as_dict()
        invocation = executor.invoke(Node.EXECUTOR_LOCAL_COMMIT, state, {"final": "No implementation changes"})
        self.assertIsNone(invocation.commit_receipt)
        self.assertEqual(invocation.result["action"], "HUMAN_REQUIRED")
        self.assertEqual(adapter.runtimes[context.thread_id].phase, ToolPhase.SUSPENDED)
        self.assertEqual(run(["git", "rev-list", "--count", "HEAD"], self.repo).stdout.strip(), "1")

    def test_explicit_review_transfer_suspends_old_writer_and_is_irreversible(self):
        adapter = FakeWorkflowAdapter([
            (Node.EXECUTOR_IMPLEMENT, response(Node.EXECUTOR_IMPLEMENT, "REPORT_READY", evidence=PASS_EVIDENCE)),
            (Node.INDEPENDENT_REVIEW, response(Node.INDEPENDENT_REVIEW, "REVIEW_READY")),
            (Node.STAGE_ACCEPTANCE, response(Node.STAGE_ACCEPTANCE, "REVIEW_READY")),
        ])
        executor = ExecutorRuntime(adapter, policy(self.repo), {"FX-A1-A0": policy(self.repo)}, current_verified_profiles())
        state = WorkflowState("FX", "FX-A1", task_id="FX-A1-A0", formal_task_intent_ref='intent-ref', formal_constraint_ref="final-ref").as_dict()
        executor.invoke(Node.EXECUTOR_IMPLEMENT, state, {"intent-ref": json.dumps(intent()), "final-ref": "Explicit frozen input"})
        old_writer = executor.main_context
        review = executor.invoke(Node.INDEPENDENT_REVIEW, state, {"final-ref": "Explicit frozen input"})
        self.assertEqual(adapter.runtimes[review.context_ref].profile, ToolProfile.READ_ONLY_REVIEW)
        with self.assertRaises(WorkflowError):
            executor.transfer_review_for_repair("FX-A1-A0", "unknown-context")
        executor.transfer_review_for_repair("FX-A1-A0", review.context_ref)
        self.assertEqual(adapter.runtimes[old_writer].phase, ToolPhase.SUSPENDED)
        self.assertEqual(adapter.registry.get(review.context_ref).freshness, FreshnessState.REVIEW_CONVERTED_TO_DEVELOPMENT)
        with self.assertRaises(LoomModeError):
            adapter.registry.assert_fresh_review(review.context_ref)
        next_review = executor.invoke(Node.STAGE_ACCEPTANCE, state, {"final-ref": "Explicit frozen input"})
        self.assertNotEqual(next_review.context_ref, review.context_ref)

    def test_preflight_rejects_missing_inputs_profiles_commands_and_unsupported_action_without_context(self):
        adapter = FakeWorkflowAdapter([])
        state = WorkflowState('FX', 'FX-A1', task_id='FX-A1-A0', formal_task_intent_ref='intent', formal_constraint_ref='final').as_dict()
        materials = {'intent': json.dumps(intent()), 'final': 'Frozen exact calc.py input'}
        base = policy(self.repo)
        executor = ExecutorRuntime(adapter, base, {'FX-A1-A0': base}, current_verified_profiles())
        for inputs in ({}, {'intent': materials['intent']}, {'final': materials['final']}):
            with self.assertRaises(WorkflowError):
                executor.invoke(Node.EXECUTOR_IMPLEMENT, state, inputs)
        with self.assertRaises(WorkflowError):
            executor.invoke(Node.TASK_SELECTION, state, materials)
        with self.assertRaises(WorkflowError):
            executor.invoke(Node.EXECUTOR_IMPLEMENT, state, materials, {'activity': 'EXECUTOR_IMPLEMENT', 'model': 'unverified', 'reasoning_effort': None, 'reason': 'fixture'})
        missing = replace(base, test_specs=(TestSpec('missing', ('loommode-no-such-command-B4',)),))
        other = ExecutorRuntime(adapter, missing, {'FX-A1-A0': missing}, current_verified_profiles())
        with self.assertRaises(LoomModeError):
            other.invoke(Node.EXECUTOR_IMPLEMENT, state, materials)
        absent = replace(base, workspace=self.root / 'does-not-exist')
        with self.assertRaises(LoomModeError):
            ExecutorRuntime(adapter, absent, {'FX-A1-A0': absent}, current_verified_profiles()).invoke(Node.EXECUTOR_IMPLEMENT, state, materials)
        with self.assertRaises(LoomModeError):
            replace(base, writable_paths=('.git/config',), readable_paths=('.git/config',), stageable_paths=()).preflight()
        self.assertEqual(adapter.runtimes, {})
        self.assertEqual(adapter.resumed, [])
        self.assertEqual(adapter.prompts, [])

    def test_preflight_resolves_command_from_declared_cwd_and_preserves_new_outputs(self):
        directory = self.repo / 'checks'
        directory.mkdir()
        command = directory / 'local-tool'
        command.write_text('fixture executable; never invoked')
        command.chmod(0o700)
        spec = TestSpec('local', ('./local-tool',), cwd='checks')
        from loommode.tools.test_runner import FixedTestRunner
        FixedTestRunner(self.repo, (spec,)).preflight()
        with self.assertRaises(LoomModeError):
            FixedTestRunner(self.repo, (replace(spec, cwd='.'),)).preflight()
        with self.assertRaises(LoomModeError):
            FixedTestRunner(self.repo, (replace(spec, cwd='../outside'),)).preflight()
        replace(policy(self.repo), readable_paths=('new/nested/output.txt',), writable_paths=('new/nested/output.txt',),
                stageable_paths=(), test_specs=()).preflight()

    def test_engine_known_preflight_failure_does_not_reserve_or_allocate(self):
        missing = replace(policy(self.repo), test_specs=(TestSpec('missing', ('loommode-no-such-command-B4',)),))
        adapter = FakeWorkflowAdapter([])
        runtime = ExecutorRuntime(adapter, missing, {'FX-A1-A0': missing}, current_verified_profiles())
        engine, scripted = make_engine(self.root / 'engine', normal_script(), workspace=self.repo)
        for _ in range(30):
            if engine.state.current_node == Node.EXECUTOR_IMPLEMENT.value:
                break
            engine.step()
        scripted.preflight = runtime.preflight
        with self.assertRaisesRegex(WorkflowError, 'declared executable unavailable'):
            engine.step()
        self.assertEqual(engine.state.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION', []), [])
        failure = engine.artifacts.read_json(engine.state.artifact_refs['HOST_TASK_FAILURE'][-1])
        self.assertFalse(failure['may_have_dev_effects'])
        self.assertEqual(adapter.runtimes, {})
        self.assertEqual(adapter.prompts, [])

    def test_role_missing_known_material_or_file_stops_before_allocation(self):
        adapter = FakeWorkflowAdapter([])
        roles = RoleRuntime(adapter, self.role_files, ToolPolicy(self.repo, ToolProfile.READ_ONLY_REVIEW, ('calc.py',)), current_verified_profiles(), 'FX-A1')
        state = WorkflowState('FX', 'FX-A1', task_id='FX-A1-A0', formal_task_intent_ref='intent').as_dict()
        with self.assertRaises(WorkflowError):
            roles.invoke(Role.CONSTRAINT, Node.CONSTRAINT_DRAFT, state, {})
        self.role_files[Role.CONSTRAINT].unlink()
        with self.assertRaises(OSError):
            roles.invoke(Role.CONSTRAINT, Node.CONSTRAINT_DRAFT, state, {'intent': json.dumps(intent())})
        self.assertEqual(adapter.runtimes, {})

    def test_adapter_custom_schema_requires_local_validator_and_terminal_success(self):
        server = Path(__file__).parent / "fixtures" / "fake_app_server.py"
        adapter = ThinCodexAdapter(client=AppServerClient((sys.executable, str(server)), self.repo),
                                  workspace_guard=WorkspaceGuard((self.root,)), config=AdapterConfig(default_turn_deadline_seconds=3))
        try:
            adapter.connect()
            context = adapter.start_context(workspace=self.repo, model=None, reasoning_effort=None,
                                            purpose=ContextPurpose.READ_ONLY_ROLE,
                                            tool_policy=ToolPolicy(self.repo, ToolProfile.READ_ONLY_REVIEW, ("calc.py",)))
            for raw_prompt, validator in [("ROLE_RESULT", lambda raw: parse_result(raw, Node.STAGE_PLANNING)),
                                          ("ROLE_RESULT TERMINAL_FAILED", lambda raw: parse_result(raw, Node.STAGE_PLANNING)),
                                          ("ROLE_RESULT", None)]:
                turn = adapter.run_turn(thread_id=context.thread_id, prompt=raw_prompt, tool_profile=ToolProfile.READ_ONLY_REVIEW,
                                        output_schema=result_schema(Node.STAGE_PLANNING), result_validator=validator)
                self.assertEqual(turn.success, raw_prompt == "ROLE_RESULT" and validator is not None)
                if turn.success:
                    self.assertEqual(turn.as_dict()["structured_result"]["action"], "HUMAN_REQUIRED")
        finally:
            adapter.close()
