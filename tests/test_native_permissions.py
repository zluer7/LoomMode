"""Native mode configuration and Host commit regression; not sandbox proof."""
import sys
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from loommode.codex.adapter import AdapterConfig, AdapterTurnResult, ThinCodexAdapter
from loommode.codex.app_server import AppServerClient
from loommode.codex.context import ContextPurpose
from loommode.codex.errors import LoomModeError
from loommode.workflow.errors import WorkflowError
from loommode.roles.prompts import build_prompt
from loommode.roles.runtime import current_verified_profiles
from loommode.tools.filesystem import WorkspaceGuard
from loommode.tools.runtime import ToolPhase, ToolProfile
from loommode.tools.test_runner import TestSpec
from loommode.workflow.executor import ExecutorRuntime
from loommode.workflow.state import WorkflowState
from loommode.workflow.transitions import Node
from tests.support import make_repo, run
from tests.test_workflow_runtime import policy
from tests.workflow_support import response, PASS_EVIDENCE, intent


class NativePermissionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = make_repo(self.root / "repo")
        server = Path(__file__).parent / "fixtures/fake_app_server.py"
        self.client = AppServerClient((sys.executable, str(server)), self.repo)
        self.adapter = ThinCodexAdapter(client=self.client, workspace_guard=WorkspaceGuard((self.root,)),
                                       config=AdapterConfig(executor_workspace_development=True))
        self.adapter.connect()

    def tearDown(self):
        self.adapter.close()
        self.tmp.cleanup()

    def start(self, purpose, profile):
        thread_id = f"native-context-{len(self.adapter._owned) + 1}"
        with patch.object(self.client, "request", return_value={"thread": {"id": thread_id}}) as rpc:
            handle = self.adapter.start_context(workspace=self.repo, model=None, reasoning_effort=None,
                                                purpose=purpose, tool_policy=policy(self.repo, profile))
            return handle, rpc.call_args.args[1]

    def test_roles_and_fresh_reviews_keep_no_native_write_environment(self):
        for purpose in (ContextPurpose.READ_ONLY_ROLE, ContextPurpose.FRESH_REVIEW):
            with self.subTest(purpose=purpose):
                _, params = self.start(purpose, ToolProfile.READ_ONLY_REVIEW)
                self.assertEqual(params["sandbox"], "read-only")
                self.assertEqual(params["environments"], [])
                self.assertFalse(params["config"]["features"]["shell_tool"])
                self.assertFalse(any(t["name"] in {"loommode_replace_file", "loommode_git_stage", "loommode_git_commit"}
                                     for t in params["dynamicTools"]))

    def test_development_uses_native_environment_and_rejects_host_mutation_callbacks(self):
        handle, params = self.start(ContextPurpose.DEVELOPMENT, ToolProfile.BOUNDED_DEVELOPMENT)
        self.assertEqual(params["sandbox"], "workspace-write")
        self.assertNotIn("environments", params)
        self.assertTrue(params["config"]["features"]["shell_tool"])
        self.assertEqual(params["config"]["sandbox_workspace_write"]["writable_roots"], [])
        for name in ("loommode_replace_file", "loommode_git_stage", "loommode_git_commit"):
            with self.assertRaises(LoomModeError):
                self.adapter._handle_dynamic_tool({"threadId": handle.thread_id, "tool": name, "arguments": {}})
        calls = []
        # Exercise the real transport construction; only the fake completion is deterministic.
        original = self.client.request
        def observe(method, params, **kwargs):
            calls.append((method, params))
            return original(method, params, **kwargs)
        with patch.object(self.client, "request", side_effect=observe):
            turn = self.adapter.run_turn(thread_id=handle.thread_id, prompt="NORMAL", tool_profile=ToolProfile.BOUNDED_DEVELOPMENT)
        self.assertTrue(turn.success)
        params = next(p for method, p in calls if method == "turn/start")
        self.assertEqual(params["sandboxPolicy"]["writableRoots"], [str(self.repo.resolve())])
        self.assertFalse(params["sandboxPolicy"]["networkAccess"])
        self.assertEqual(params["environments"][0]["environmentId"], "local")
        self.adapter.suspend_mutations(handle.thread_id)
        with patch.object(self.client, "request", side_effect=observe):
            self.adapter.run_turn(thread_id=handle.thread_id, prompt="NORMAL", tool_profile=ToolProfile.BOUNDED_DEVELOPMENT)
        self.assertEqual(calls[-1][1]["sandboxPolicy"]["type"], "readOnly")
        self.assertEqual(calls[-1][1]["environments"], [])

    def test_parent_process_cwd_is_rejected_even_when_workspace_is_allowlisted(self):
        self.client.cwd = self.root.resolve()
        with self.assertRaises(LoomModeError):
            self.start(ContextPurpose.DEVELOPMENT, ToolProfile.BOUNDED_DEVELOPMENT)

    def supply(self):
        binding = {'project': 'FX', 'stage_id': 'FX-A1', 'task_id': 'FX-A1-A0',
                   'intent_ref': 'actual-intent-ref', 'final_ref': 'actual-final-ref', 'scope': ['calc.py']}
        source = {'origin': 'OWNER_NORMAL_SUPPLY_AUTHORIZATION', **binding,
                  'workspace': str(self.repo.resolve()), 'reason': 'Explicit fixture ordinary local dependency supply'}
        self.adapter.normal_supply_authority['owner-supply'] = json.dumps(source)
        return replace(policy(self.repo), normal_supply_authority_ref='owner-supply'), binding, source

    def test_normal_supply_actual_host_binding_enables_only_implementation_payload(self):
        task, binding, _ = self.supply()
        # The stage superset declares a future optional command; current Task does not need it.
        future = TestSpec('future', ('loommode-no-such-future-command-B4',))
        stage = replace(policy(self.repo), test_specs=task.test_specs + (future,))
        with patch.object(self.client, 'request', return_value={'thread': {'id': 'supply-context'}}):
            handle = self.adapter.start_context(workspace=self.repo, model=None, reasoning_effort=None,
                purpose=ContextPurpose.DEVELOPMENT, tool_policy=stage, task_policy=task, task_binding=binding)
        calls = []
        original = self.client.request
        def observe(method, params, **kwargs):
            calls.append((method, params))
            return original(method, params, **kwargs)
        with patch.object(self.client, 'request', side_effect=observe):
            result = self.adapter.run_turn(thread_id=handle.thread_id, prompt='NORMAL', tool_profile=ToolProfile.BOUNDED_DEVELOPMENT)
        self.assertTrue(result.success)
        payload = next(p for m, p in calls if m == 'turn/start')
        self.assertTrue(payload['sandboxPolicy']['networkAccess'])
        self.assertEqual(payload['sandboxPolicy']['writableRoots'], [str(self.repo.resolve())])
        self.assertEqual(payload['environments'][0]['environmentId'], 'local')
        for phase in ('suspended', 'commit'):
            if phase == 'suspended':
                self.adapter.suspend_mutations(handle.thread_id)
            else:
                self.adapter.authorize_commit(handle.thread_id, acceptance_ref='actual-acceptance', report_ref='actual-report')
            calls.clear()
            with patch.object(self.client, 'request', side_effect=observe):
                self.adapter.run_turn(thread_id=handle.thread_id, prompt='NORMAL', tool_profile=ToolProfile.BOUNDED_DEVELOPMENT)
            payload = next(p for m, p in calls if m == 'turn/start')
            self.assertEqual(payload['sandboxPolicy'], {'type': 'readOnly', 'networkAccess': False})
            self.assertEqual(payload['environments'], [])
        # Supply never changes the exact Host-only commit gate.
        with self.assertRaises(LoomModeError):
            self.adapter.host_exact_commit(handle.thread_id, paths=['test_calc.py'], message='[foreign] push')

    def test_normal_supply_absent_mismatched_unsupported_and_readonly_reject_before_rpc(self):
        task, binding, source = self.supply()
        for change in ({'task_id': 'FX-A1-A9'}, {'scope': ['test_calc.py']}, {'intent_ref': 'different-intent'}, {'final_ref': 'different-final'}):
            self.adapter.normal_supply_authority['owner-supply'] = json.dumps({**source, **change})
            with patch.object(self.client, 'request') as rpc, self.assertRaises(LoomModeError):
                self.adapter.start_context(workspace=self.repo, model=None, reasoning_effort=None,
                    purpose=ContextPurpose.DEVELOPMENT, tool_policy=policy(self.repo), task_policy=task, task_binding=binding)
            rpc.assert_not_called()
        self.adapter.normal_supply_authority.clear()
        with patch.object(self.client, 'request') as rpc, self.assertRaises(LoomModeError):
            self.adapter.start_context(workspace=self.repo, model=None, reasoning_effort=None,
                purpose=ContextPurpose.DEVELOPMENT, tool_policy=policy(self.repo), task_policy=task, task_binding=binding)
        rpc.assert_not_called()
        self.adapter.normal_supply_authority['owner-supply'] = json.dumps(source)
        self.adapter.config = replace(self.adapter.config, executor_workspace_development=False)
        with self.assertRaises(LoomModeError):
            self.adapter.preflight_task_policy(task, binding)
        with self.assertRaises(LoomModeError):
            replace(task, profile=ToolProfile.READ_ONLY_REVIEW)
        self.assertEqual(self.adapter._owned, set())

    def test_next_task_resume_uses_current_checks_and_fresh_clears_supply(self):
        first, _, source = self.supply()
        source.update(intent_ref='intent-ref', final_ref='final-ref')
        self.adapter.normal_supply_authority['owner-supply'] = json.dumps(source)
        command = self.repo / 'first-tool'
        command.write_text('fixture executable; never invoked')
        command.chmod(0o700)
        first = replace(first, test_specs=(TestSpec('first', ('./first-tool',)),))
        second = replace(policy(self.repo), commit_messages=('[FX-A1-A1] exact commit',))
        stage = replace(first, normal_supply_authority_ref=None, test_specs=first.test_specs + second.test_specs,
                        commit_messages=first.commit_messages + second.commit_messages)
        executor = ExecutorRuntime(self.adapter, stage, {'FX-A1-A0': first, 'FX-A1-A1': second}, current_verified_profiles())
        state = WorkflowState('FX', 'FX-A1', task_id='FX-A1-A0', formal_task_intent_ref='intent-ref', formal_constraint_ref='final-ref').as_dict()
        initial = self.prompt_invocation(executor, Node.EXECUTOR_IMPLEMENT, state)
        self.assertIn('Local supply within that scope is allowed', initial['prompt'])
        command.unlink()
        self.adapter.normal_supply_authority.clear()
        state['task_id'] = 'FX-A1-A1'
        resumed = self.prompt_invocation(executor, Node.EXECUTOR_IMPLEMENT, state)
        self.assertEqual(initial['thread_id'], resumed['thread_id'])
        self.assertIsNone(self.adapter._runtime(resumed['thread_id']).policy.normal_supply_authority_ref)
        self.assertNotIn('Local supply within that scope is allowed', resumed['prompt'])
        # Read-only projection clears even an explicitly supplied stage-level ref.
        readonly_executor = ExecutorRuntime(self.adapter, replace(policy(self.repo), normal_supply_authority_ref='owner-supply'),
                                           {}, current_verified_profiles())
        fresh = self.prompt_invocation(readonly_executor, Node.STAGE_REVIEW, WorkflowState('FX', 'FX-A1').as_dict())
        self.assertEqual(fresh['tool_profile'], ToolProfile.READ_ONLY_REVIEW)
        self.assertIsNone(self.adapter._runtime(fresh['thread_id']).policy.normal_supply_authority_ref)
        self.assertNotIn('Local supply within that scope is allowed', fresh['prompt'])

    def test_checkpoint_wrong_phase_rejects_before_resume_or_turn(self):
        handle, _ = self.start(ContextPurpose.DEVELOPMENT, ToolProfile.BOUNDED_DEVELOPMENT)
        executor = ExecutorRuntime(self.adapter, policy(self.repo), {'FX-A1-A0': policy(self.repo)}, current_verified_profiles())
        executor.main_context = handle.thread_id
        state = WorkflowState('FX', 'FX-A1', task_id='FX-A1-A0').as_dict()
        with patch.object(self.client, 'request') as rpc, self.assertRaises(LoomModeError):
            executor.invoke(Node.EXECUTOR_LOCAL_COMMIT, state, {})
        rpc.assert_not_called()

    def test_review_conversion_reenables_native_tools_only_after_explicit_transfer(self):
        handle, _ = self.start(ContextPurpose.FRESH_REVIEW, ToolProfile.READ_ONLY_REVIEW)
        self.adapter.authorize_development(handle.thread_id)
        with patch.object(self.client, "request", return_value={"thread": {"id": handle.thread_id}}) as rpc:
            self.adapter.resume_context(thread_id=handle.thread_id, workspace=self.repo,
                                        tool_profile=ToolProfile.BOUNDED_DEVELOPMENT)
        self.assertEqual(rpc.call_args.args[1]["sandbox"], "workspace-write")
        self.assertNotIn("environments", rpc.call_args.args[1])
        self.assertTrue(rpc.call_args.args[1]["config"]["features"]["shell_tool"])
        with self.assertRaises(LoomModeError):
            self.adapter.registry.assert_fresh_review(handle.thread_id)

    def test_host_commit_requires_gate_and_executor_commit_node_makes_no_model_call(self):
        handle, _ = self.start(ContextPurpose.DEVELOPMENT, ToolProfile.BOUNDED_DEVELOPMENT)
        path = self.repo / "calc.py"
        path.write_text(path.read_text().replace("left - right", "left + right"))
        with self.assertRaises(LoomModeError):
            self.adapter.host_exact_commit(handle.thread_id, paths=["calc.py"], message="[FX-A1-A0] exact commit")
        self.assertEqual(run(["git", "rev-list", "--count", "HEAD"], self.repo).stdout.strip(), "1")
        executor = ExecutorRuntime(self.adapter, policy(self.repo), {"FX-A1-A0": policy(self.repo)}, current_verified_profiles())
        executor.main_context = handle.thread_id
        state = WorkflowState("FX", "FX-A1", task_id="FX-A1-A0", current_node=Node.COMMIT_AUTHORIZATION.value,
                              acceptance_ref="accepted", latest_execution_report_ref="saved-report").as_dict()
        # The real Host binds checkpoint ownership even when dirty work needs a
        # commit rather than NO_DEV_CHANGE. This fixture bypasses Engine assembly.
        state["host_checkpoint_binding"] = {"host_context_ref": handle.thread_id,
            "project": "FX", "stage_id": "FX-A1", "task_id": "FX-A1-A0",
            "workspace": str(self.repo.resolve()), "acceptance_ref": "accepted", "report_ref": "saved-report"}
        executor.authorize_commit(state)
        with patch.object(self.adapter, "run_turn", side_effect=AssertionError("commit must be Host-only")):
            invocation = executor.invoke(Node.EXECUTOR_LOCAL_COMMIT, state, {})
        self.assertEqual(invocation.result["action"], "COMMIT_COMPLETE")
        self.assertEqual(invocation.commit_receipt["staged_files"], ["calc.py"])
        self.assertEqual(invocation.commit_receipt["final_status"], "")
        self.assertEqual(run(["git", "rev-list", "--count", "HEAD"], self.repo).stdout.strip(), "2")
        with self.assertRaises(LoomModeError):
            self.adapter.host_exact_commit(handle.thread_id, paths=["calc.py"], message="[FX-A1-A0] exact commit")

    def test_host_commit_protects_preexisting_staged_files(self):
        handle, _ = self.start(ContextPurpose.DEVELOPMENT, ToolProfile.BOUNDED_DEVELOPMENT)
        path = self.repo / "test_calc.py"
        path.write_text(path.read_text() + "\n# pre-existing staged change\n")
        run(["git", "add", "--", "test_calc.py"], self.repo)
        self.adapter.authorize_commit(handle.thread_id, acceptance_ref="accepted", report_ref="report")
        with self.assertRaises(LoomModeError):
            self.adapter.host_exact_commit(handle.thread_id, paths=["calc.py"], message="[FX-A1-A0] exact commit")
        self.assertEqual(run(["git", "diff", "--cached", "--name-only"], self.repo).stdout.strip(), "test_calc.py")

    def prompt_invocation(self, executor, node, state):
        action = "REPORT_READY" if node == Node.EXECUTOR_IMPLEMENT else "REVIEW_READY"
        result = response(node, action, evidence=PASS_EVIDENCE) if node == Node.EXECUTOR_IMPLEMENT else response(node, action)
        captured = []
        def turn(**kwargs):
            captured.append({**kwargs, "actual_phase": self.adapter._runtime(kwargs["thread_id"]).phase})
            return AdapterTurnResult(True, kwargs["thread_id"], "prompt-check", "completed",
                                     result, (), (), 0, None, ())
        original_request = self.client.request
        def context_request(method, params, **kwargs):
            # The legacy fake peer rejects shell_tool=True at thread/start.
            # Keep real Adapter policy/phase checks; substitute only context RPC
            # receipts and completion for this runtime-to-prompt contract test.
            if method == "thread/start":
                return {"thread": {"id": f"prompt-context-{len(self.adapter._owned) + 1}"}}
            if method == "thread/resume":
                return {"thread": {"id": params["threadId"]}}
            return original_request(method, params, **kwargs)
        with patch.object(self.client, "request", side_effect=context_request), patch.object(self.adapter, "run_turn", side_effect=turn):
            executor.invoke(node, state, {'intent-ref': json.dumps(intent(state['task_id'])), "final-ref": "Explicit frozen scope: calc.py only"})
        return captured[0]

    def test_native_implementation_prompt_reinjects_current_grant_on_resume(self):
        first = policy(self.repo)
        second = replace(first, test_specs=(TestSpec("resume_unit", first.test_specs[0].argv),),
                         commit_messages=("[FX-A1-A1] exact commit",))
        stage = replace(first, test_specs=first.test_specs + second.test_specs,
                        commit_messages=first.commit_messages + second.commit_messages)
        executor = ExecutorRuntime(self.adapter, stage,
                                   {"FX-A1-A0": first, "FX-A1-A1": second}, current_verified_profiles())
        calls = []
        for task in ("FX-A1-A0", "FX-A1-A1"):
            state = WorkflowState("FX", "FX-A1", task_id=task, formal_task_intent_ref='intent-ref', formal_constraint_ref="final-ref").as_dict()
            calls.append(self.prompt_invocation(executor, Node.EXECUTOR_IMPLEMENT, state))
        self.assertEqual(calls[0]["thread_id"], calls[1]["thread_id"])
        for call in calls:
            self.assertEqual(call["actual_phase"], ToolPhase.IMPLEMENTATION)
            self.assertIn("Native shell is already enabled only for this approved implementation", call["prompt"])
            self.assertNotIn("change tools, call shell", call["prompt"])
            self.assertIn('"writable_paths": ["calc.py"]', call["prompt"])
            self.assertIn("shell checks cannot replace", call["prompt"])
            self.assertIn("Do not modify protected or unrelated files, stage, commit", call["prompt"])
        self.assertIn('"fixed_test_ids": ["resume_unit"]', calls[1]["prompt"])
        self.assertNotIn('"fixed_test_ids": ["unit"]', calls[1]["prompt"])

    def test_native_off_implementation_and_fresh_runtime_keep_shell_prohibition(self):
        executor = ExecutorRuntime(self.adapter, policy(self.repo), {"FX-A1-A0": policy(self.repo)}, current_verified_profiles())
        state = WorkflowState("FX", "FX-A1", task_id="FX-A1-A0", formal_task_intent_ref='intent-ref', formal_constraint_ref="final-ref").as_dict()
        native = self.prompt_invocation(executor, Node.EXECUTOR_IMPLEMENT, state)
        fresh = self.prompt_invocation(executor, Node.INDEPENDENT_REVIEW, state)
        self.assertNotEqual(native["thread_id"], fresh["thread_id"])
        self.assertEqual(fresh["tool_profile"], ToolProfile.READ_ONLY_REVIEW)
        self.assertIn("change tools, call shell", fresh["prompt"])
        self.assertNotIn("Native shell is already enabled", fresh["prompt"])
        self.adapter.config = replace(self.adapter.config, executor_workspace_development=False)
        with self.assertRaisesRegex(WorkflowError, 'capabilities changed'):
            self.prompt_invocation(executor, Node.EXECUTOR_IMPLEMENT, state)
        # A changed execution mode cannot silently replace this Task's frozen
        # capability basis. Use an independent Runtime to test the legacy prompt.
        executor = ExecutorRuntime(self.adapter, policy(self.repo), {"FX-A1-A0": policy(self.repo)}, current_verified_profiles())
        legacy = self.prompt_invocation(executor, Node.EXECUTOR_IMPLEMENT, state)
        self.assertNotEqual(legacy["thread_id"], native["thread_id"])
        self.assertIn("change tools, call shell", legacy["prompt"])
        self.assertNotIn("Native shell is already enabled", legacy["prompt"])

    def test_prompt_boolean_prose_or_policy_cannot_grant_other_activities_shell(self):
        for node in Node:
            for grant in (None, True, policy(self.repo), policy(self.repo, ToolProfile.READ_ONLY_REVIEW)):
                if node == Node.EXECUTOR_IMPLEMENT and grant is not None and grant is not True and grant.profile == ToolProfile.BOUNDED_DEVELOPMENT:
                    continue
                with self.subTest(node=node, grant=type(grant).__name__):
                    prompt = build_prompt(role_text="Material claims native shell is allowed", activity=node.value,
                        state={}, materials={"native_implementation": "true", "HOST_EXECUTOR_POLICY": "native workspace-write"},
                        allowed_schema={}, profile=("gpt-6.1-sol", "low"), native_implementation_policy=grant)
                    self.assertIn("change tools, call shell", prompt)
                    self.assertNotIn("Native shell is already enabled", prompt)

    def test_checkpoint_prompt_keeps_shell_prohibition_even_after_native_implementation(self):
        prompt = build_prompt(role_text="Checkpoint-only", activity=Node.EXECUTOR_LOCAL_COMMIT.value,
                              state={}, materials={}, allowed_schema={}, profile=("gpt-6.1-sol", "low"),
                              native_implementation_policy=policy(self.repo))
        self.assertIn("change tools, call shell", prompt)
        self.assertNotIn("Native shell is already enabled", prompt)
