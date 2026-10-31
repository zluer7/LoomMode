"""Deterministic Adapter double driving real runtimes and real bounded Git."""
import copy
import json
from types import SimpleNamespace
from loommode.codex.adapter import AdapterTurnResult
from loommode.codex.context import ContextRegistry
from loommode.tools.runtime import BoundedToolRuntime
from loommode.workflow.transitions import Node
from loommode.workflow.errors import WorkflowError
from tests.workflow_support import governed_script, fill_governance_result, mediation


class FakeWorkflowAdapter:
    def __init__(self, script):
        self.script = governed_script(script) if script and isinstance(script[0], tuple) else copy.deepcopy(script)
        self.registry = ContextRegistry()
        self.runtimes = {}
        self.prompts = []
        self.resumed = []
        self.commit_gate_observations = []

    def start_context(self, **kwargs):
        thread_id = f"fake-adapter-{len(self.runtimes) + 1}"
        self.runtimes[thread_id] = BoundedToolRuntime(kwargs["tool_policy"])
        self.registry.create(thread_id=thread_id, workspace=kwargs["workspace"], purpose=kwargs["purpose"],
                             model=kwargs["model"], reasoning_effort=kwargs["reasoning_effort"],
                             tool_profile=kwargs["tool_policy"].profile.value, codex_version="deterministic-double",
                             activity_metadata=kwargs.get("activity_metadata"))
        return SimpleNamespace(thread_id=thread_id)

    def resume_context(self, **kwargs):
        self.resumed.append(kwargs["thread_id"])
        self.registry.get(kwargs["thread_id"])
        return SimpleNamespace(thread_id=kwargs["thread_id"])

    def release_context(self, thread_id, *, reason):
        from loommode.codex.context import ResourceState
        receipt = {'released': True, 'reason': reason, 'proof': 'SCRIPTED_REGISTRY_RETIREMENT_NO_NATIVE_PROCESS'}
        self.registry.resource(thread_id, ResourceState.RELEASED, receipt=receipt)
        return receipt

    def configure_task(self, thread_id, policy, **kwargs):
        self.runtimes[thread_id].configure_task(policy, **kwargs)

    def authorize_development(self, thread_id):
        from loommode.tools.runtime import ToolProfile
        self.registry.authorize_development(thread_id, ToolProfile.BOUNDED_DEVELOPMENT.value)
        self.runtimes[thread_id].set_profile(ToolProfile.BOUNDED_DEVELOPMENT)

    def suspend_mutations(self, thread_id):
        self.runtimes[thread_id].suspend_mutations()

    def authorize_commit(self, thread_id, **kwargs):
        self.runtimes[thread_id].authorize_commit(**kwargs)

    def commit_receipt(self, thread_id):
        return self.runtimes[thread_id].last_commit_receipt

    def host_no_dev_change(self, thread_id, **kwargs):
        return self.runtimes[thread_id].host_no_dev_change(kwargs["binding"])

    def verify_no_dev_change(self, thread_id, **kwargs):
        self.runtimes[thread_id].verify_no_dev_change(kwargs["evidence"], kwargs["binding"])

    def run_turn(self, **kwargs):
        node = Node(kwargs["prompt"].split("\nACTIVITY: ")[1].split("\n", 1)[0])
        if node == Node.DECISION_MEDIATION and (not self.script or self.script[0][0] != node):
            expected, result = node, mediation()
        else:
            expected, result = self.script.pop(0)
        if node != expected:
            raise WorkflowError(f"fake Adapter expected {expected}, got {node}")
        state = json.loads(kwargs['prompt'].split('\nCURRENT STATE: ')[1].split('\nEXPLICIT MATERIAL')[0])
        role = self.registry.get(kwargs['thread_id']).activity_metadata.get('role', 'Executor')
        fill_governance_result(node, result, state, role)
        self.prompts.append(kwargs)
        runtime = self.runtimes[kwargs["thread_id"]]
        index = runtime.audit_index()
        if node == Node.EXECUTOR_IMPLEMENT:
            # Observe the actual Host denial, then proceed with allowed implementation.
            for name, arguments in [("loommode_git_stage", {"paths": ["calc.py"]}),
                                    ("loommode_git_commit", {"message": runtime.policy.commit_messages[0]})]:
                denied = runtime.handle_call({"tool": name, "arguments": arguments})
                assert denied["success"] is False
                self.commit_gate_observations.append({"node": node.value, "tool": name, "denied": True})
            # These deliberate denial probes are isolated test evidence, not model tool calls.
            index = runtime.audit_index()
            if "return left - right" in (runtime.workspace / "calc.py").read_text(encoding="utf-8"):
                edited = runtime.handle_call({"tool": "loommode_replace_file", "arguments": {
                    "path": "calc.py", "expected": "return left - right", "replacement": "return left + right"}})
                assert edited["success"]
            tested = runtime.handle_call({"tool": "loommode_run_test", "arguments": {"test_id": "unit"}})
            assert tested["success"] and tested["output"]["passed"]
        if node == Node.EXECUTOR_LOCAL_COMMIT and result["action"] == "COMMIT_COMPLETE":
            staged = runtime.handle_call({"tool": "loommode_git_stage", "arguments": {"paths": ["calc.py"]}})
            assert staged["success"], staged
            committed = runtime.handle_call({"tool": "loommode_git_commit", "arguments": {"message": runtime.policy.commit_messages[0]}})
            assert committed["success"], committed
        structured = kwargs["result_validator"](json.dumps(result))
        return AdapterTurnResult(True, kwargs["thread_id"], f"fake-turn-{len(self.prompts)}", "completed", structured,
                                 runtime.audit_since(index), (), 0, None, ("turn/completed",))
