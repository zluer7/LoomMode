"""Backend-neutral Host proof over the original bounded runtime and Git facts.

A context reference names its owning backend. It need not be an app-server
thread, and constructing this facade neither configures nor resets a Task.
"""
from typing import Any
from dataclasses import asdict
import copy
import hashlib
from pathlib import Path
import stat
import time
from .test_runner import test_execution_control, test_isolation

from loommode.codex.errors import ErrorCategory, LoomModeError
from .runtime import BoundedToolRuntime, ToolPhase


class HostTaskProof:
    def __init__(self, runtime: BoundedToolRuntime, *, context_ref: str, backend: str) -> None:
        if not context_ref or backend not in {"codex_app_server", "managed_codex_cli"}:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "explicit Host proof context/backend required")
        self.runtime, self.context_ref, self.backend = runtime, context_ref, backend
        if backend == 'managed_codex_cli':
            runtime.require_test_isolation = True
            runtime.tests.require_isolation = True
        self._managed_tests = None
        self._managed_checkpoint_inventory = None

    def native_test_evidence(self, binding):
        """Snapshot existing owned test results; never execute or infer a pass.

        A poisoned/failed test runtime may still supply its original diagnostic
        receipt. Reading this evidence grants no execution/checkpoint authority.
        """
        runtime = self.runtime
        with runtime._lock:
            if (self.backend != 'codex_app_server' or not binding
                    or binding != runtime.task_binding):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'native test receipt Task binding mismatch')
            specs = [{**asdict(spec), 'argv': list(spec.argv)} for spec in runtime.policy.test_specs]
            ids = [spec['test_id'] for spec in specs]
            if set(runtime.test_results) - set(ids):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'native test receipt has unknown fixed test')
            return copy.deepcopy({'origin': 'HOST_NATIVE_FIXED_TESTS',
                'context_ref': self.context_ref, 'workspace': str(runtime.workspace.resolve()),
                'binding': binding, 'required_test_ids': ids, 'test_specs': specs,
                'tests': runtime.test_results,
                'unrun_test_ids': [test_id for test_id in ids if test_id not in runtime.test_results]})

    def clear_managed_tests(self):
        self._managed_tests = None
        self._managed_checkpoint_inventory = None

    def managed_source_snapshot(self, config):
        """Bounded bytes AND file-set identity, independent of Git HEAD.

        Only explicitly declared test output directories are excluded. Nothing
        is excluded merely because Git ignores it or it has a cache-like name.
        Protected inputs are not opened. Newly created/deleted modules in a
        granted related directory therefore invalidate the previous snapshot.
        """
        root = self.runtime.workspace
        excluded = tuple(Path(p) for p in (*config.test_output_dirs, *config.tool_denied_paths))
        files, total, visited = {}, 0, 0
        def protected(relative):
            return (any(part.lower() in {'.git', '.env', 'credentials'} for part in relative.parts)
                    or any(relative == p or relative.is_relative_to(p) for p in excluded))
        def visit(path):
            nonlocal total, visited
            relative = path.relative_to(root)
            if protected(relative):
                return
            visited += 1
            if visited > 4096:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source enumeration exceeds bound')
            try:
                info = path.lstat()
            except FileNotFoundError:
                files[relative.as_posix()] = None
                return
            if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
                    or not path.resolve().is_relative_to(root)):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source links/reparse denied')
            if stat.S_ISDIR(info.st_mode):
                for child in sorted(path.iterdir()):
                    visit(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                if info.st_size > 4 * 1024 * 1024 or total + info.st_size > 32 * 1024 * 1024:
                    raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source bytes exceed bound')
                data = path.read_bytes()
                total += len(data)
                if len(data) != info.st_size:
                    raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source changed during snapshot')
                files[relative.as_posix()] = hashlib.sha256(data).hexdigest()
            else:
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source must be a unique regular file')
        targets = set(self.runtime.policy.readable_paths) | set(config.tool_read_dirs) | set(config.tool_write_dirs)
        for relative in sorted(targets):
            for component in (root / relative, *(root / relative).parents):
                if component == root:
                    break
                if component.exists():
                    info = component.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                        raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source parent links/reparse denied')
            visit(root / relative)
        return dict(sorted(files.items()))

    def record_managed_tests(self, request, generation, receipt, cancel, *, working_root, records_root):
        """Called once by Host after an implementation, never report correction."""
        before = self.managed_source_snapshot(request.config.managed)
        from loommode.workflow.managed_cli import managed_tool_paths
        protected = managed_tool_paths(request)
        git_before = self.runtime.git.inventory()
        from .sandbox_test import sandbox_test_plan
        plans = {spec.test_id: sandbox_test_plan(request, spec,
                 working_root=working_root, records_root=records_root)
                 for spec in request.policy.test_specs}
        if not plans:
            raise RuntimeError('managed Host tests require explicit sandbox capability')
        for spec in request.policy.test_specs:
            with test_isolation(plans), test_execution_control(time.monotonic() + spec.timeout_seconds, cancel):
                call = self.runtime.handle_call({'tool': 'loommode_run_test', 'arguments': {'test_id': spec.test_id}})
            if not call['success']:
                raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, 'managed Host fixed test failed to execute')
        after = self.managed_source_snapshot(request.config.managed)
        git_after = self.runtime.git.inventory()
        self._managed_tests = copy.deepcopy({'origin': 'HOST_MANAGED_FIXED_TESTS',
            'context_ref': self.context_ref, 'request_fingerprint': request.fingerprint,
            'generation': generation, 'implementation_receipt': self._managed_receipt_identity(receipt),
            'required_test_ids': [s.test_id for s in request.policy.test_specs],
            'tests': self.runtime.test_results, 'source_before': before, 'source_after': after,
            'protected_paths': list(protected),
            'git_before': git_before, 'git_after': git_after})
        if (before != after or protected != managed_tool_paths(request)
                or any(git_before[k] != git_after[k] for k in ('head', 'branch', 'index', 'flags'))):
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed source changed during Host tests')

    def managed_test_evidence(self):
        return copy.deepcopy(self._managed_tests)

    @staticmethod
    def _managed_receipt_identity(receipt):
        if not receipt:
            return None
        result = {key: receipt.get(key) for key in ('attempt_id', 'origin', 'request_fingerprint', 'context_ref',
            'pid', 'exit_code', 'stdin_complete', 'truncated', 'cleanup', 'working_files_removed',
            'outcome', 'terminal_status', 'reservation_ref', 'native_authority', 'production_eligible')}
        result['raw_output_sha256'] = hashlib.sha256(receipt.get('raw_output', '').encode()).hexdigest()
        return result

    def verify_managed_tests(self, request, generation, receipt, saved=None, *, require_passed=True):
        """Pure eligibility check; never runs a test or resets a baseline."""
        self.runtime.assert_usable()
        from loommode.workflow.managed_cli import managed_tool_paths
        facts = self._managed_tests
        current_git = self.runtime.git.inventory()
        checkpoint = self.runtime.last_commit_receipt
        if facts:
            if checkpoint:
                recorded = self._managed_checkpoint_inventory
                if (not recorded or any(current_git[k] != recorded[k] for k in ('head', 'branch', 'index', 'flags', 'tracked'))
                        or current_git['head'] != checkpoint['commit_hash'] or current_git['index_diff']
                        or current_git['branch'] != facts['git_after']['branch']
                        or current_git['head'] == facts['git_after']['head']):
                    raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed checkpoint Git identity changed')
            elif any(current_git[k] != facts['git_after'][k] for k in ('head', 'branch', 'index', 'flags')):
                raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed test Git baseline changed')
        cleanup = (receipt or {}).get('cleanup') or {}
        ids = [spec.test_id for spec in request.policy.test_specs]
        if (not facts or not ids or facts['required_test_ids'] != ids
                or facts['context_ref'] != self.context_ref or facts['generation'] != generation
                or facts['request_fingerprint'] != request.fingerprint
                or facts['implementation_receipt'] != self._managed_receipt_identity(receipt)
                or (receipt or {}).get('outcome') not in {'INVOCATION_READY', 'FAILED'}
                or (receipt or {}).get('exit_code') != 0
                or (receipt or {}).get('terminal_status') != 'completed'
                or not (receipt or {}).get('stdin_complete') or (receipt or {}).get('truncated')
                or not (receipt or {}).get('working_files_removed')
                or cleanup.get('unknown_side_effect') is not False
                or not all(cleanup.get(k) is True for k in ('root_terminated', 'tree_terminated_confirmed',
                    'job_handle_closed', 'io_threads_joined', 'pipes_closed', 'process_handle_closed'))
                or set(facts['tests']) != set(ids) or facts['tests'] != self.runtime.test_results
                or any((require_passed and not row.get('result', {}).get('passed')) or row['result'].get('truncated')
                       or (row['result'].get('termination') or {}).get('unknown_side_effect') is not False
                       or not all((row['result'].get('termination') or {}).get(k) is True
                           for k in ('root_terminated', 'tree_terminated_confirmed', 'output_drained', 'pipes_closed', 'process_handle_closed'))
                       for row in facts['tests'].values())
                or facts['source_before'] != facts['source_after']
                or facts['source_after'] != self.managed_source_snapshot(request.config.managed)
                or facts['protected_paths'] != list(managed_tool_paths(request))
                or (saved is not None and saved != facts)):
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, 'managed Host test/source/cleanup evidence is missing, failed or stale')

    def authorize_commit(self, **kwargs: Any) -> None:
        self.runtime.authorize_commit(**kwargs)

    def no_dev_change(self, binding: dict[str, Any]) -> dict[str, Any]:
        self._check_context(binding)
        return self.runtime.host_no_dev_change(binding)

    def verify_no_dev_change(self, evidence: dict[str, Any], binding: dict[str, Any]) -> None:
        self._check_context(binding)
        self.runtime.verify_no_dev_change(evidence, binding)

    def _check_context(self, binding: dict[str, Any]) -> None:
        if not binding or binding.get("host_context_ref") != self.context_ref:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "checkpoint proof context owner mismatch")

    def exact_commit(self, *, paths: list[str], message: str) -> dict[str, Any]:
        runtime = self.runtime
        runtime.assert_usable()
        if runtime.phase != ToolPhase.COMMIT_AUTHORIZED:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "accepted Host commit phase required")
        if runtime.git.staged_files():
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "pre-existing staged changes require inspection")
        for tool, arguments in (("loommode_git_stage", {"paths": paths}),
                                ("loommode_git_commit", {"message": message})):
            result = runtime.handle_call({"tool": tool, "arguments": arguments})
            if not result["success"]:
                # Runtime output can contain Git stderr or exception details. Only
                # typed, bounded classifications cross into durable workflow evidence.
                output = result.get("output")
                record = output.get("error") if isinstance(output, dict) else None
                category_value = record.get("category") if isinstance(record, dict) else None
                category = (ErrorCategory(category_value) if isinstance(category_value, str) and
                            category_value in ErrorCategory._value2member_map_
                            else ErrorCategory.TOOL_EXECUTION_ERROR)
                message = record.get("message") if isinstance(record, dict) else None
                reason_code = ("DIRTY_TASK_START" if category == ErrorCategory.TOOL_PERMISSION_ERROR and
                               message == "no-change requires a clean Task-start and current inventory" else
                               "POLICY_REJECTED" if category == ErrorCategory.TOOL_PERMISSION_ERROR else
                               "TOOL_TIMEOUT" if category == ErrorCategory.TOOL_TIMEOUT else
                               "GIT_OPERATION_FAILED" if category in {ErrorCategory.TOOL_EXECUTION_ERROR,
                                   ErrorCategory.PROCESS_ERROR, ErrorCategory.WORKSPACE_ERROR} else
                               "TOOL_EXECUTION_FAILED")
                raise LoomModeError(category, "Host exact commit failed",
                                    details={"failed_tool": tool, "reason_code": reason_code})
        if self._managed_tests is not None:
            self._managed_checkpoint_inventory = copy.deepcopy(runtime.git.inventory())
        return result["output"]

    def checkpoint(self, *, paths: list[str], message: str, binding: dict[str, Any]) -> dict[str, Any]:
        runtime = self.runtime
        runtime.assert_usable()
        self._check_context(binding)
        if runtime.phase != ToolPhase.COMMIT_AUTHORIZED:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "accepted Host checkpoint phase required")
        status = runtime.git.status()
        if status.timed_out or status.truncated or status.stderr.strip() or "\ufffd" in status.stdout:
            raise LoomModeError(ErrorCategory.TOOL_EXECUTION_ERROR, "Host checkpoint status is incomplete or ambiguous")
        if status.stdout.strip():
            return {"disposition": "COMMIT_COMPLETE", "receipt": self.exact_commit(paths=paths, message=message),
                    "no_commit_evidence": None}
        return {"disposition": "NO_DEV_CHANGE", "receipt": None, "no_commit_evidence": self.no_dev_change(binding)}
