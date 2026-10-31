"""C1 real disposable Git scenes, with deterministic model envelopes."""
import copy
from contextlib import contextmanager
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from threading import RLock
from unittest.mock import patch

from loommode.codex.adapter import AdapterTurnResult, ThinCodexAdapter
from loommode.codex.errors import LoomModeError, ErrorCategory
from loommode.host.state_view import StateProjection, saved_state_provider
from loommode.roles.contracts import empty_result, parse_result
from loommode.roles.runtime import Invocation, RoleRuntime, current_verified_profiles
from loommode.tools.git import GitRuntime, require_no_commit_evidence
from loommode.tools.runtime import ToolPhase, ToolPolicy, ToolProfile
from loommode.tools.test_runner import CommandResult, TestSpec
from loommode.workflow.artifacts import ArtifactStore
from loommode.workflow.engine import WorkflowEngine
from loommode.workflow.errors import WorkflowError
from loommode.workflow.executor import ExecutorRuntime
from loommode.workflow.state import StateStore, WorkflowState
from loommode.workflow.transitions import Node, Role
from tests.fake_workflow_adapter import FakeWorkflowAdapter
from tests.support import make_repo, run
from tests.workflow_support import normal_script, response, intent, PASS_EVIDENCE, make_engine, install_test_windows


class NativeAdapter(FakeWorkflowAdapter):
    """Use actual native Host methods, without starting a paid model turn."""
    native_workspace_development = True
    host_checkpoint = ThinCodexAdapter.host_checkpoint
    host_exact_commit = ThinCodexAdapter.host_exact_commit
    task_proof = ThinCodexAdapter.task_proof

    def __init__(self, script):
        super().__init__(script)
        # Borrowed production Host checkpoint methods preserve serialization.
        self._lifecycle_lock = RLock()
        self._degraded = None

    def _runtime(self, thread_id):
        return self.runtimes[thread_id]


class ClaimingAdapter(FakeWorkflowAdapter):
    """A model that claims success even when it omitted/failed required checks."""
    run_required_test = True

    def run_turn(self, **kwargs):
        node = Node(kwargs["prompt"].split("\nACTIVITY: ")[1].split("\n", 1)[0])
        if node != Node.EXECUTOR_IMPLEMENT:
            return super().run_turn(**kwargs)
        expected, result = self.script.pop(0)
        assert expected == node
        self.prompts.append(kwargs)
        runtime = self.runtimes[kwargs["thread_id"]]
        index = runtime.audit_index()
        if self.run_required_test:
            runtime.handle_call({"tool": "loommode_run_test", "arguments": {"test_id": "unit"}})
        structured = kwargs["result_validator"](json.dumps(result))
        return AdapterTurnResult(True, kwargs["thread_id"], "model-success-claim", "completed", structured,
                                 runtime.audit_since(index), (), 0, None, ("turn/completed",))


class FollowingCommitAdapter(FakeWorkflowAdapter):
    def run_turn(self, **kwargs):
        prompt = kwargs["prompt"]
        if "\nACTIVITY: EXECUTOR_IMPLEMENT\n" in prompt:
            state = json.loads(prompt.split("\nCURRENT STATE: ")[1].split("\nEXPLICIT MATERIAL")[0])
            if state["task_id"] == "FX-A1-A1":
                edited = self.runtimes[kwargs["thread_id"]].handle_call({"tool": "loommode_replace_file", "arguments": {
                    "path": "calc.py", "expected": "return left + right", "replacement": "return left + right  # accepted follow-up"}})
                assert edited["success"]
        return super().run_turn(**kwargs)


class NoChangeScene:
    def __init__(self, root, *, native=False, adapter_type=None, allow=True, scope=None, grant=True,
                 spec=None, dirty=None, mixed=False, task_git_grant=True):
        self.root = root
        self.repo = make_repo(root / "repo")
        if not mixed:
            path = self.repo / "calc.py"
            path.write_text(path.read_text().replace("left - right", "left + right"))
            assert run(["git", "add", "--", "calc.py"], self.repo).returncode == 0
            assert run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid.local",
                        "commit", "-qm", "correct Task-start baseline"], self.repo).returncode == 0
        if dirty:
            dirty(self.repo)
        self.before = self.git_facts()
        spec = spec or TestSpec("unit", (sys.executable, "-m", "unittest", "-v"))
        first = ToolPolicy(self.repo, ToolProfile.BOUNDED_DEVELOPMENT, ("calc.py", "test_calc.py"),
                           ("calc.py",), ("calc.py",) if task_git_grant else (), (spec,),
                           ("[FX-A1-A0] exact commit",) if task_git_grant else (), allow_no_dev_change=allow and not mixed)
        script = normal_script()
        script[2][1]["intent"].update(goal="Verify the already correct arithmetic; Dev change is optional",
                                     scope=scope or ["calc.py"])
        script[5][1]["artifacts"][0]["content"] = "Verify existing calc.py, run required unit, self-review; no Dev change is permitted when already correct."
        script[6][1]["artifacts"][0]["content"] = "Existing behavior verified by required unit and self-review; no changes needed."
        policies = {"FX-A1-A0": first}
        if mixed:
            script[2][1]["intent"]["goal"] = "Repair arithmetic implementation"
            script[5][1]["artifacts"][0]["content"] = "Repair calc.py; required unit, report and self-review."
            second = replace(first, commit_messages=("[FX-A1-A1] exact commit",), allow_no_dev_change=allow)
            policies["FX-A1-A1"] = second
            second_task = copy.deepcopy(normal_script()[2:9])
            second_task[0][1]["intent"] = intent("FX-A1-A1")
            second_task[0][1]["intent"]["goal"] = "Verify correct arithmetic; Dev change optional"
            second_task[3][1]["artifacts"][0]["content"] = "Verify existing calc.py; required unit; no Dev change needed if correct."
            second_task[-1][1]["action"] = "NO_DEV_CHANGE"
            script[9:9] = second_task
            stage = replace(first, commit_messages=first.commit_messages + second.commit_messages)
        else:
            script[8][1]["action"] = "NO_DEV_CHANGE"
            stage = replace(first, allow_no_dev_change=False)
        if native:
            script = [item for item in script if item[0] != Node.EXECUTOR_LOCAL_COMMIT]
        self.adapter = (adapter_type or (NativeAdapter if native else FakeWorkflowAdapter))(script)
        role_files = {}
        for role in Role:
            if role == Role.EXECUTOR:
                continue
            path = root / f"{role.value}.md"
            path.write_text("## Part I — Fixed Role Definition\nFixture duties\n## Part II — Long-term Role Experience\nNone.", encoding="utf-8")
            role_files[role] = path
        profiles = current_verified_profiles()
        roles = RoleRuntime(self.adapter, role_files, ToolPolicy(self.repo, ToolProfile.READ_ONLY_REVIEW, ("calc.py", "test_calc.py")), profiles, "FX-A1")
        self.executor = ExecutorRuntime(self.adapter, stage, policies, profiles)
        self.artifacts = ArtifactStore(root / "Records", "FX", "FX-A1")
        self.store = StateStore(root / "DevEnv", "FX", "FX-A1")
        self.engine = WorkflowEngine(WorkflowState("FX", "FX-A1"), self.store, self.artifacts, roles, self.executor,
                                     {"owner": "Explicit fixture Stage authorization; exact local checkpoint grant"},
                                     stage_authorization_ref="owner", local_commit_authorized=grant)
        install_test_windows(self.engine)

    def git_facts(self):
        return {"head": run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip(),
                "count": run(["git", "rev-list", "--count", "HEAD"], self.repo).stdout.strip(),
                "index": run(["git", "diff", "--cached", "--name-only"], self.repo).stdout,
                "status": run(["git", "status", "--porcelain=v1"], self.repo).stdout}

    def advance(self, node):
        for _ in range(60):
            if self.engine.state.current_node == node.value:
                return
            self.engine.step()
        raise AssertionError(f"did not reach {node}")

    def runtime(self):
        return self.adapter.runtimes[self.executor.main_context]

    def checkpoint(self):
        return self.artifacts.read_json(self.engine.state.task_checkpoint_refs[self.engine.state.task_id])

    def projection(self, provider=None):
        return StateProjection(project="FX", stage_id="FX-A1", workspace=self.repo, artifacts=self.artifacts,
                               registry=self.adapter.registry, state_provider=provider or (lambda: self.engine.state),
                               source_ref=str(self.store.path), authority_materials=self.engine.authority)


class NoDevChangeTests(unittest.TestCase):
    @contextmanager
    def assertGuardFailure(self, exception_type, expected_regex):
        # Production deliberately scrubs outward error details. Check the
        # actual retained cause as well, instead of requiring secret-bearing
        # original text to be exposed to the model/user again.
        with self.assertRaises(exception_type) as caught:
            yield
        chain, current = [], caught.exception
        while current is not None and len(chain) < 8:
            chain.append(str(current))
            current = current.__cause__
        self.assertRegex('\n'.join(chain), expected_regex)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def scene(self, **kwargs):
        return NoChangeScene(self.root, **kwargs)

    def assert_no_commit(self, scene):
        self.assertEqual(scene.git_facts(), scene.before)
        self.assertIsNone(scene.engine.state.commit_receipt)
        self.assertFalse(any(a.tool in {"loommode_git_stage", "loommode_git_commit"} and a.result == "success"
                             for a in scene.runtime().audit))

    def test_legacy_full_closure_preserves_head_count_index_and_cleans_task(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        checkpoint = scene.checkpoint()
        evidence = checkpoint["evidence"]
        self.assertEqual(checkpoint["origin"], "HOST_NO_DEV_CHANGE")
        self.assertNotIn("commit_hash", json.dumps(evidence))
        self.assertNotIn("receipt", checkpoint)
        self.assertEqual(evidence["binding"]["acceptance_ref"], scene.engine.state.acceptance_ref)
        self.assertEqual(evidence["required_tests"]["unit"]["result"]["exit_code"], 0)
        self.assert_no_commit(scene)
        scene.engine.state.active_blocker_id = "resolved-blocker"
        scene.engine.state.blocker_ledger["resolved-blocker"] = {"repair_used": True, "new_basis_used": False,
                                                               "decision_treatment_used": False, "decision_flow_used": False, "basis_id": None}
        scene.engine.state.pending_override = {"activity": "EXECUTOR_IMPLEMENT", "model": None,
                                               "reasoning_effort": "low", "reason": "unused Task override"}
        scene.engine.state.pending_override_task_id = scene.engine.state.task_id
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, Node.TASK_SELECTION.value)
        self.assertIsNone(scene.engine.state.active_blocker_id)
        self.assertIsNone(scene.engine.state.pending_override)
        self.assertIsNone(scene.engine.state.pending_override_task_id)
        self.assertEqual(scene.runtime().phase, ToolPhase.SUSPENDED)
        self.assertEqual(sum("\nACTIVITY: TASK_SELECTION\n" in p["prompt"] for p in scene.adapter.prompts), 1)

    def test_native_uses_real_host_disposition_without_checkpoint_model_turn(self):
        scene = self.scene(native=True)
        scene.advance(Node.TASK_COMPLETE)
        self.assertEqual(scene.engine.state.last_result["action"], "NO_DEV_CHANGE")
        self.assertEqual(scene.engine.state.last_result["invocation"]["origin"], "HOST_CHECKPOINT")
        self.assertFalse(any("\nACTIVITY: EXECUTOR_LOCAL_COMMIT\n" in p["prompt"] for p in scene.adapter.prompts))
        self.assert_no_commit(scene)
        scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, "TASK_SELECTION")

    def test_stage_close_receives_all_actual_commit_and_no_change_proofs(self):
        scene = self.scene(mixed=True)
        scene.advance(Node.STAGE_SETTLEMENT)
        refs = scene.engine.state.task_checkpoint_refs
        self.assertEqual(set(refs), {"FX-A1-A0", "FX-A1-A1"})
        bodies = {ref: scene.artifacts.read(ref) for ref in refs.values()}
        committed = json.loads(bodies[refs["FX-A1-A0"]])
        unchanged = json.loads(bodies[refs["FX-A1-A1"]])
        self.assertEqual(committed["origin"], "HOST_COMMIT_RECEIPT")
        self.assertEqual(committed["receipt"]["commit_hash"], scene.git_facts()["head"])
        self.assertEqual(unchanged["origin"], "HOST_NO_DEV_CHANGE")
        require_no_commit_evidence(unchanged["evidence"])
        self.assertNotIn(scene.engine.state.artifact_refs["DECISION"][-1], bodies)
        for node in (Node.STAGE_REVIEW, Node.INDEPENDENT_REVIEW, Node.STAGE_ACCEPTANCE):
            with self.subTest(fresh=node):
                materials = scene.engine._materials(scene.engine.state, node)
                self.assertTrue(set(bodies).isdisjoint(materials))
                self.assertNotIn(scene.engine.state.latest_execution_report_ref, materials)
                self.assertNotIn(scene.engine.state.acceptance_ref, materials)
        scene.engine.run()
        self.assertEqual(scene.engine.state.current_node, "COMPLETED")
        self.assertFalse(scene.engine.state.owner_accepted)
        for node in (Node.STAGE_SETTLEMENT, Node.STAGE_MACHINE_CLOSE, Node.STAGE_CLOSE_SYNC,
                     Node.ROLE_MEMORY_CONSOLIDATION, Node.OWNER_SUMMARY):
            prompts = [p["prompt"] for p in scene.adapter.prompts if "\nACTIVITY: " + node.value + "\n" in p["prompt"]]
            self.assertTrue(prompts, node)
            for prompt in prompts:
                for ref, body in bodies.items():
                    self.assertIn(ref.replace("\\", "\\\\"), prompt)
                    self.assertIn(json.dumps(body, ensure_ascii=False), prompt)

    def test_stage_close_missing_checkpoint_refuses_before_role_dispatch(self):
        scene = self.scene(mixed=True)
        scene.advance(Node.STAGE_MACHINE_CLOSE)
        ref = scene.engine.state.task_checkpoint_refs["FX-A1-A0"]
        Path(ref.split("#sha256=")[0]).unlink()
        calls = len(scene.adapter.prompts)
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts), calls)
        self.assertEqual(scene.engine.state.current_node, "FAILED")
        self.assertEqual(len(scene.engine.state.task_checkpoint_refs), 2)

    def test_stage_close_changed_checkpoint_digest_refuses_before_role_dispatch(self):
        scene = self.scene(mixed=True)
        scene.advance(Node.STAGE_MACHINE_CLOSE)
        ref = scene.engine.state.task_checkpoint_refs["FX-A1-A1"]
        Path(ref.split("#sha256=")[0]).write_text('{"disposition":"COMMIT_COMPLETE"}', encoding="utf-8")
        calls = len(scene.adapter.prompts)
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts), calls)
        self.assertEqual(scene.engine.state.current_node, "FAILED")
        self.assertEqual(len(scene.engine.state.task_checkpoint_refs), 2)

    def test_native_optional_checkpoint_cannot_commit_preexisting_writable_diff(self):
        scene = self.scene(native=True, dirty=lambda repo: (repo / "calc.py").write_text(
            (repo / "calc.py").read_text() + "\n# pre-existing user-only note\n"))
        with self.assertRaises(WorkflowError):
            scene.advance(Node.TASK_COMPLETE)
        self.assert_no_commit(scene)
        self.assertFalse(scene.engine.state.task_checkpoint_refs)
        self.assertEqual(scene.engine.state.current_node, "FAILED")

    def test_optional_git_tools_preserve_preexisting_staged_diff(self):
        def dirty(repo):
            path = repo / "calc.py"
            path.write_text(path.read_text() + "\n# pre-existing staged user-only note\n")
            self.assertEqual(run(["git", "add", "--", "calc.py"], repo).returncode, 0)
        scene = self.scene(dirty=dirty)
        scene.advance(Node.COMMIT_AUTHORIZATION)
        scene.engine.step()
        runtime = scene.runtime()
        self.assertEqual(runtime.phase, ToolPhase.COMMIT_AUTHORIZED)
        for tool, arguments in (("loommode_git_stage", {"paths": ["calc.py"]}),
                                ("loommode_git_commit", {"message": runtime.policy.commit_messages[0]})):
            with self.subTest(tool=tool):
                result = runtime.handle_call({"tool": tool, "arguments": arguments})
                self.assertFalse(result["success"])
                self.assertEqual(result["output"]["error"]["category"], "TOOL_PERMISSION_ERROR")
                self.assertIn("clean Task-start", result["output"]["error"]["message"])
        self.assert_no_commit(scene)

    def test_native_optional_actual_diff_cannot_replace_unknown_original_baseline(self):
        scene = self.scene(native=True, mixed=True)
        scene.executor.task_policies["FX-A1-A0"] = replace(
            scene.executor.task_policies["FX-A1-A0"], allow_no_dev_change=True)
        scene.advance(Node.EXECUTOR_LOCAL_COMMIT)
        at_gate = scene.git_facts()
        self.assertTrue(at_gate["status"])
        self.assertEqual(scene.runtime().task_start_inventory["status"], "")
        scene.runtime().task_start_inventory = None
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        self.assertEqual(scene.git_facts(), at_gate)
        self.assertIsNone(scene.runtime().last_commit_receipt)
        self.assertFalse(scene.engine.state.task_checkpoint_refs)
        self.assertFalse(any(a.tool in {"loommode_git_stage", "loommode_git_commit"} and a.result == "success"
                             for a in scene.runtime().audit))

    def test_native_optional_reconfiguration_preserves_dirty_start_before_actual_diff(self):
        note = "\n# pre-existing user-only note\n"
        scene = self.scene(native=True, dirty=lambda repo: (repo / "calc.py").write_text(
            (repo / "calc.py").read_text() + note))
        scene.advance(Node.COMMIT_AUTHORIZATION)
        runtime = scene.runtime()
        original = copy.deepcopy(runtime.task_start_inventory)
        path = scene.repo / "calc.py"
        path.write_text(path.read_text().replace(note, ""))
        runtime.configure_task(runtime.policy, task_binding=runtime.task_binding)
        self.assertEqual(runtime.task_start_inventory, original)
        path.write_text(path.read_text() + "\n# actual later Task diff\n")
        at_gate = scene.git_facts()
        with self.assertRaises(WorkflowError):
            scene.advance(Node.TASK_COMPLETE)
        self.assertEqual(scene.git_facts(), at_gate)
        self.assertEqual(runtime.task_start_inventory, original)
        self.assertIsNone(runtime.last_commit_receipt)
        self.assertFalse(scene.engine.state.task_checkpoint_refs)
        self.assertFalse(any(a.tool in {"loommode_git_stage", "loommode_git_commit"} and a.result == "success"
                             for a in runtime.audit))

    def test_model_claim_without_host_evidence_cannot_complete(self):
        script = normal_script()
        script[8][1]["action"] = "NO_DEV_CHANGE"
        engine, _ = make_engine(self.root, script)
        with self.assertGuardFailure(WorkflowError, "separate Host no-commit evidence"):
            engine.run()
        self.assertEqual(engine.state.current_node, "FAILED")
        self.assertFalse(engine.state.task_checkpoint_refs)

    def test_no_change_is_allowed_only_at_checkpoint_node(self):
        self.assertEqual(parse_result(json.dumps(empty_result("NO_DEV_CHANGE")), Node.EXECUTOR_LOCAL_COMMIT)["action"], "NO_DEV_CHANGE")
        for node in (Node.EXECUTOR_IMPLEMENT, Node.PROMOTER_RESULT_REVIEW, Node.STAGE_SETTLEMENT):
            with self.subTest(node=node), self.assertRaises(WorkflowError):
                parse_result(json.dumps(empty_result("NO_DEV_CHANGE")), node)

    def test_explicit_permission_defaults_to_false_in_both_paths(self):
        for native in (False, True):
            with self.subTest(native=native), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp), native=native, allow=False)
                with self.assertGuardFailure(WorkflowError, "no-change is not permitted"):
                    scene.advance(Node.TASK_COMPLETE)
                self.assert_no_commit(scene)

    def test_task_requiring_new_code_cannot_use_existing_passing_tests_as_no_change(self):
        scene = self.scene(allow=False)
        selection = next(result for node, result in scene.adapter.script if node == Node.TASK_SELECTION)
        selection["intent"]["goal"] = "Implement a new multiplication API in calc.py"
        final = next(result for node, result in scene.adapter.script if node == Node.CONSTRAINT_FINALIZE)
        final["artifacts"][0]["content"] = "A Dev modification implementing multiplication is required; unit check is required."
        with self.assertGuardFailure(WorkflowError, "no-change is not permitted"):
            scene.advance(Node.TASK_COMPLETE)
        self.assert_no_commit(scene)

    def test_missing_stage_or_task_git_grant_is_not_renamed_no_change(self):
        for stage_grant, task_grant in ((False, True), (True, False)):
            with self.subTest(stage=stage_grant, task=task_grant), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp), grant=stage_grant, task_git_grant=task_grant, adapter_type=ClaimingAdapter)
                with self.assertGuardFailure(WorkflowError, "grant"):
                    scene.advance(Node.TASK_COMPLETE)
                self.assert_no_commit(scene)

    def test_unclear_or_different_task_scope_cannot_no_change(self):
        scene = self.scene(scope=["whole calculation behavior"])
        with self.assertGuardFailure(WorkflowError, "scope"):
            scene.advance(Node.TASK_COMPLETE)
        # Scope preflight rejects before a development runtime even exists.
        self.assertEqual(scene.git_facts(), scene.before)
        self.assertIsNone(scene.executor.main_context)
        self.assertTrue(all(runtime.profile == ToolProfile.READ_ONLY_REVIEW
                            for runtime in scene.adapter.runtimes.values()))

    def test_missing_report_acceptance_and_report_result_block_verification(self):
        for field in ("latest_execution_report_ref", "acceptance_ref", "formal_constraint_ref", "REPORT_RESULT"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp))
                scene.advance(Node.COMMIT_AUTHORIZATION)
                if field == "REPORT_RESULT":
                    scene.engine.state.artifact_refs[field] = []
                else:
                    setattr(scene.engine.state, field, None)
                with self.assertRaises(WorkflowError):
                    scene.engine.step()
                self.assert_no_commit(scene)

    def test_not_run_failed_truncated_and_timed_out_fixed_tests_cannot_use_model_flags(self):
        specs = [
            ("not-run", None, False),
            ("failed", TestSpec("unit", (sys.executable, "-c", "raise SystemExit(1)")), True),
            ("truncated", TestSpec("unit", (sys.executable, "-c", "print('x'*200)"), output_limit=16), True),
            ("timeout", TestSpec("unit", (sys.executable, "-c", "import time; time.sleep(1)"), timeout_seconds=0.02), True),
        ]
        for label, spec, run_test in specs:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp), adapter_type=ClaimingAdapter, spec=spec)
                scene.adapter.run_required_test = run_test
                with self.assertRaises(WorkflowError):
                    scene.advance(Node.TASK_COMPLETE)
                self.assert_no_commit(scene)
                self.assertIsNone(scene.runtime().last_no_commit_evidence)

    def test_user_existing_worktree_staged_untracked_or_ignored_facts_are_preserved_and_refused(self):
        def worktree(repo):
            (repo / "test_calc.py").write_text((repo / "test_calc.py").read_text() + "\n# user\n")
        def staged(repo):
            worktree(repo)
            assert run(["git", "add", "--", "test_calc.py"], repo).returncode == 0
        def untracked(repo):
            (repo / "unknown").mkdir()
            (repo / "unknown" / "user.txt").write_text("user data")
        def ignored(repo):
            (repo / ".git" / "info" / "exclude").write_text("ignored/\n")
            (repo / "ignored").mkdir()
            (repo / "ignored" / "user.txt").write_text("user data")
        for name, dirty in (("worktree", worktree), ("staged", staged), ("untracked", untracked), ("ignored", ignored)):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp), dirty=dirty)
                with self.assertGuardFailure(WorkflowError, "clean Task-start"):
                    scene.advance(Node.TASK_COMPLETE)
                self.assert_no_commit(scene)

    def test_hidden_index_flag_cannot_claim_clean_inventory(self):
        scene = self.scene(dirty=lambda repo: run(["git", "update-index", "--assume-unchanged", "calc.py"], repo))
        with self.assertGuardFailure(WorkflowError, "hidden"):
            scene.advance(Node.TASK_COMPLETE)
        self.assert_no_commit(scene)

    def test_failed_unknown_truncated_inventory_and_permissions_fail_closed(self):
        for category in ("failed", "unknown", "truncated", "permission"):
            with self.subTest(category=category), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp))
                original = GitRuntime._run
                def denied(runtime, args):
                    if "ls-files" in args and "--stage" in args:
                        if category == "permission":
                            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "inventory permission denied")
                        if category == "unknown":
                            return CommandResult(0, "\ufffd", "", 0, False, False)
                        return CommandResult(1 if category == "failed" else 0, "", "", 0, False, category == "truncated")
                    return original(runtime, args)
                with patch.object(GitRuntime, "_run", denied), self.assertRaises(WorkflowError):
                    scene.advance(Node.TASK_COMPLETE)
                self.assert_no_commit(scene)

    def test_dirty_task_start_cannot_become_clean_baseline_by_reconfiguration(self):
        scene = self.scene(dirty=lambda repo: (repo / "user.txt").write_text("pre-existing"))
        scene.advance(Node.COMMIT_AUTHORIZATION)
        runtime = scene.runtime()
        original_baseline = copy.deepcopy(runtime.task_start_inventory)
        (scene.repo / "user.txt").unlink()
        runtime.configure_task(runtime.policy, task_binding=runtime.task_binding)
        self.assertEqual(runtime.task_start_inventory, original_baseline)
        with self.assertGuardFailure(WorkflowError, "clean Task-start"):
            scene.advance(Node.TASK_COMPLETE)

    def test_completion_rechecks_inventory_and_formal_bytes(self):
        for changed in ("worktree", "index", "untracked", "final", "report", "acceptance"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp))
                scene.advance(Node.TASK_COMPLETE)
                if changed in {"worktree", "index"}:
                    (scene.repo / "calc.py").write_text((scene.repo / "calc.py").read_text() + "\n# later effect\n")
                    if changed == "index":
                        run(["git", "add", "--", "calc.py"], scene.repo)
                elif changed == "untracked":
                    (scene.repo / "later.txt").write_text("later effect")
                else:
                    field = {"final": "formal_constraint_ref", "report": "latest_execution_report_ref", "acceptance": "acceptance_ref"}[changed]
                    Path(getattr(scene.engine.state, field).split("#sha256=")[0]).write_text("tampered formal evidence", encoding="utf-8")
                with self.assertRaises(WorkflowError):
                    scene.engine.step()
                self.assertEqual(scene.engine.state.current_node, "FAILED")
                self.assertEqual(scene.runtime().phase, ToolPhase.SUSPENDED)

    def test_wrong_identity_tampered_or_unknown_proof_cannot_complete(self):
        for changed in ("task", "binding", "tests", "version", "extra", "receipt"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                scene = NoChangeScene(Path(temp))
                scene.advance(Node.TASK_COMPLETE)
                value = scene.checkpoint()
                if changed == "task":
                    value["task_id"] = "FX-A1-OTHER"
                elif changed == "binding":
                    value["evidence"]["binding"]["host_context_ref"] = "another-host"
                elif changed == "tests":
                    value["evidence"]["required_tests"]["unit"]["result"]["truncated"] = True
                elif changed == "version":
                    value["evidence"]["schema_version"] = 999
                elif changed == "extra":
                    value["evidence"]["commit_hash"] = "a" * 40
                else:
                    value["receipt"] = {"commit_hash": "a" * 40}
                ref = scene.artifacts.save("DECISION", json.dumps(value), task_id=scene.engine.state.task_id)
                scene.engine.state.task_checkpoint_refs[scene.engine.state.task_id] = ref
                with self.assertRaises(WorkflowError):
                    scene.engine.step()
                self.assert_no_commit(scene)

    def test_host_no_commit_cannot_replay_and_save_failure_stops_unknown_effects(self):
        scene = self.scene()
        scene.advance(Node.EXECUTOR_LOCAL_COMMIT)
        original = scene.artifacts.save
        def failed(kind, content, **kwargs):
            if '"origin": "HOST_NO_DEV_CHANGE"' in content:
                raise WorkflowError("no-commit evidence saving failed")
            return original(kind, content, **kwargs)
        with patch.object(scene.artifacts, "save", failed), self.assertGuardFailure(WorkflowError, "saving failed"):
            scene.engine.step()
        self.assertEqual(scene.engine.state.current_node, "FAILED")
        self.assertEqual(scene.engine.state.in_flight_activity, "EXECUTOR_LOCAL_COMMIT")
        self.assertFalse(scene.engine.state.task_checkpoint_refs)
        self.assert_no_commit(scene)
        prompts = len(scene.adapter.prompts)
        scene.engine.step()
        self.assertEqual(len(scene.adapter.prompts), prompts)
        with self.assertRaises(LoomModeError):
            scene.runtime().host_no_dev_change(scene.executor.checkpoint_binding)
        with self.assertRaises(LoomModeError):
            scene.runtime().authorize_commit(acceptance_ref="again", report_ref="again")

    def test_stage_record_has_no_fake_commits_and_fresh_input_hides_checkpoint_verdict(self):
        scene = self.scene()
        state = scene.engine.run()
        self.assertEqual(state.current_node, "COMPLETED")
        self.assertTrue(state.stage_closed)
        self.assertFalse(state.owner_accepted)
        record = scene.artifacts.read_json(state.artifact_refs["STAGE_RECORD"][-1])
        self.assertEqual(record["task_commits"], {})
        self.assertEqual(set(record["task_no_commits"]), {"FX-A1-A0"})
        proof_ref = state.task_checkpoint_refs["FX-A1-A0"]
        fresh = next(p["prompt"] for p in scene.adapter.prompts if "\nACTIVITY: STAGE_ACCEPTANCE\n" in p["prompt"])
        self.assertNotIn(proof_ref, fresh)
        self.assertNotIn("HOST_NO_DEV_CHANGE", fresh)
        self.assertNotIn(scene.checkpoint()["evidence"]["verification_id"], fresh)
        call_state = json.loads(fresh.split("\nCURRENT STATE: ")[1].split("\nEXPLICIT MATERIAL")[0])
        self.assertEqual(call_state["task_checkpoint_refs"], {})

    def test_real_commit_then_no_commit_preserves_separate_stage_history(self):
        scene = self.scene(mixed=True)
        scene.engine.run()
        record = scene.artifacts.read_json(scene.engine.state.artifact_refs["STAGE_RECORD"][-1])
        self.assertEqual(set(record["task_commits"]), {"FX-A1-A0"})
        self.assertEqual(set(record["task_no_commits"]), {"FX-A1-A1"})
        self.assertEqual(scene.git_facts()["count"], "2")
        self.assertEqual(record["task_commits"]["FX-A1-A0"]["staged_files"], ["calc.py"])
        self.assertIsNone(scene.engine.state.commit_receipt)
        view = scene.projection().capture().view
        self.assertEqual(view["checkpoints"]["FX-A1-A0"]["disposition"], "COMMIT_COMPLETE")
        self.assertEqual(view["checkpoints"]["FX-A1-A1"]["disposition"], "NO_DEV_CHANGE")

    def test_no_commit_then_following_actual_commit_has_no_missing_hash_dependency(self):
        scene = self.scene(adapter_type=FollowingCommitAdapter)
        first = scene.executor.task_policies["FX-A1-A0"]
        second = replace(first, commit_messages=("[FX-A1-A1] exact commit",), allow_no_dev_change=False)
        scene.executor.task_policies["FX-A1-A1"] = second
        scene.executor.stage_policy = replace(scene.executor.stage_policy, commit_messages=first.commit_messages + second.commit_messages)
        second_task = copy.deepcopy(normal_script()[2:9])
        second_task[0][1]["intent"] = intent("FX-A1-A1")
        second_task[0][1]["intent"]["goal"] = "Add the approved calculation comment"
        selection = next(i for i, item in enumerate(scene.adapter.script) if item[0] == Node.TASK_SELECTION and item[1]['action'] == 'STAGE_READY')
        scene.adapter.script[selection:selection] = second_task
        scene.engine.run()
        record = scene.artifacts.read_json(scene.engine.state.artifact_refs["STAGE_RECORD"][-1])
        self.assertEqual(set(record["task_no_commits"]), {"FX-A1-A0"})
        self.assertEqual(set(record["task_commits"]), {"FX-A1-A1"})
        self.assertEqual(scene.git_facts()["count"], "3")
        self.assertEqual(scene.engine.state.commit_receipt["commit_hash"], record["task_commits"]["FX-A1-A1"]["commit_hash"])

    def test_projection_and_read_only_saved_state_verify_disposition_without_replaying(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        saved_before = scene.store.path.read_bytes()
        snapshot = scene.projection(saved_state_provider(scene.store)).capture()
        checkpoint = snapshot.view["latest_accepted"]["checkpoint"]
        self.assertEqual(checkpoint["verification"], "VERIFIED")
        self.assertEqual(checkpoint["disposition"], "NO_DEV_CHANGE")
        self.assertIsNone(checkpoint["receipt"])
        self.assertIn("无需 Dev commit", snapshot.summary())
        self.assertEqual(scene.store.path.read_bytes(), saved_before)
        self.assert_no_commit(scene)
        state = scene.store.load_for_restart()
        self.assertEqual(state.current_node, "RECOVERY_REQUIRED")
        self.assert_no_commit(scene)

    def test_projection_rejects_wrong_no_commit_pointer_or_formal_tampering(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        scene.engine.state.acceptance_ref = scene.artifacts.save("ACCEPTANCE", json.dumps(response(
            Node.PROMOTER_RESULT_REVIEW, "TASK_ACCEPTED", evidence=PASS_EVIDENCE)), task_id="FX-A1-A0")
        self.assertEqual(scene.projection().capture().view["checkpoints"]["FX-A1-A0"]["verification"], "UNVERIFIED")

    def test_existing_schema_one_has_no_new_fields_and_unknown_state_still_rejects(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        payload = json.loads(scene.store.path.read_text())
        self.assertEqual(payload["schema_version"], 1)
        self.assertNotIn("no_commit_evidence", payload)
        payload["no_commit_evidence"] = {}
        scene.store.path.write_text(json.dumps(payload))
        with self.assertRaises(WorkflowError):
            scene.store.load_for_restart()
        self.assertEqual(scene.projection(saved_state_provider(scene.store)).capture().view["availability"], "UNAVAILABLE")

    def test_saved_proof_strict_types_and_versions_are_rejected(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        original = scene.checkpoint()["evidence"]
        changes = [("schema_version", True), ("required_tests", []), ("binding", {}), ("policy", {})]
        for key, changed in changes:
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value[key] = changed
                with self.assertRaises(LoomModeError):
                    require_no_commit_evidence(value)
        for field in ("cwd", "timeout_seconds", "output_limit"):
            with self.subTest(test_spec_field=field):
                value = copy.deepcopy(original)
                value["policy"]["fixed_tests"][0][field] = False
                with self.assertRaises(LoomModeError):
                    require_no_commit_evidence(value)
        for number in (float("nan"), float("inf")):
            with self.subTest(timeout=number):
                value = copy.deepcopy(original)
                value["policy"]["fixed_tests"][0]["timeout_seconds"] = number
                with self.assertRaises(LoomModeError):
                    require_no_commit_evidence(value)

    def test_legacy_special_origin_cannot_replace_standard_host_proof(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        proof = scene.checkpoint()
        proof["origin"] = "HOST_EXISTING_CHECKPOINT_RECOVERY"
        ref = scene.artifacts.save("DECISION", json.dumps(proof), task_id=scene.engine.state.task_id)
        scene.engine.state.task_checkpoint_refs[scene.engine.state.task_id] = ref
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        self.assert_no_commit(scene)

    def test_unknown_task_start_baseline_cannot_be_inferred_from_clean_current(self):
        scene = self.scene()
        scene.advance(Node.EXECUTOR_LOCAL_COMMIT)
        scene.runtime().task_start_inventory = None
        with self.assertGuardFailure(WorkflowError, "unknown Git inventory"):
            scene.engine.step()
        self.assert_no_commit(scene)

    def test_transferred_review_context_cannot_claim_original_task_start(self):
        scene = self.scene()
        review = next(i for i, item in enumerate(scene.adapter.script) if item[0] == Node.PROMOTER_RESULT_REVIEW)
        scene.adapter.script[review] = (Node.PROMOTER_RESULT_REVIEW, response(Node.PROMOTER_RESULT_REVIEW, "REQUEST_INDEPENDENT_REVIEW"))
        scene.adapter.script[review + 1:review + 1] = [
            (Node.INDEPENDENT_REVIEW, response(Node.INDEPENDENT_REVIEW, "REVIEW_READY")),
            (Node.PROMOTER_RESULT_REVIEW, response(Node.PROMOTER_RESULT_REVIEW, "TASK_REPAIR", blocker_id="review-clarification",
                                                  handoff="Verify the same unchanged behavior in this explicitly converted review", repair_from_review=True)),
            (Node.EXECUTOR_IMPLEMENT, response(Node.EXECUTOR_IMPLEMENT, "REPORT_READY", evidence=PASS_EVIDENCE)),
            (Node.PROMOTER_RESULT_REVIEW, response(Node.PROMOTER_RESULT_REVIEW, "TASK_ACCEPTED", evidence=PASS_EVIDENCE)),
        ]
        with self.assertGuardFailure(WorkflowError, "current Executor Host context"):
            scene.advance(Node.TASK_COMPLETE)
        self.assertNotEqual(scene.executor.main_context, scene.executor.task_start_contexts["FX-A1-A0"])
        self.assert_no_commit(scene)

    def test_saved_formal_json_duplicate_keys_and_nonfinite_values_fail_closed(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        for raw in ('{"action":"TASK_REPAIR","action":"TASK_ACCEPTED"}', '{"number":NaN}'):
            with self.subTest(raw=raw):
                ref = scene.artifacts.save("DECISION", raw, task_id="FX-A1-A0")
                with self.assertRaises(WorkflowError):
                    scene.artifacts.read_json(ref)

    def test_required_artifact_tamper_or_report_result_flags_cannot_pass_completion(self):
        scene = self.scene()
        scene.advance(Node.TASK_COMPLETE)
        ref = scene.engine.state.artifact_refs["REPORT_RESULT"][-1]
        Path(ref.split("#sha256=")[0]).write_text(json.dumps(empty_result("REPORT_READY")))
        with self.assertRaises(WorkflowError):
            scene.engine.step()
        self.assert_no_commit(scene)


if __name__ == "__main__":
    unittest.main()
