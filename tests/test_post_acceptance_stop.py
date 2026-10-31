"""Offline scripted judgments through real canonical IPC/leases; no model or Git.

The synthetic clock only exercises manual window scheduling. A5 remains the
source of real model Task acceptance; these new receipts prove mechanics only.
"""
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from loommode.codex.context import ContextPurpose, ContextRegistry
from loommode.host import DecisionEntry, DecisionHost, StateProjection, open_canonical
from loommode.host.canonical import attach_canonical
from loommode.host.ownership import WorkspaceLease
from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node
from tests.workflow_support import make_engine, normal_script


class PostAcceptanceStopTests(unittest.TestCase):
    measurements = []

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix='post-acceptance-', dir=os.environ.get('LOOMMODE_A6_TEST_ROOT'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        self.engine, self.participants = make_engine(
            self.root / 'mechanics', normal_script(), grant=False, workspace=self.workspace)
        # Replace only the existing explicit fixture clock/wrapper, never runtime placement.
        self.engine.step = self.engine._unwrapped_step
        self.clock = [100.0]
        self.callbacks = []
        def schedule(delay, callback):
            self.callbacks.append((delay, callback))
            return SimpleNamespace(cancel=lambda: None)
        self.engine._test_window_configuration = {
            'clock': lambda: self.clock[0], 'scheduler': schedule,
            'test_durations': (1800.0, 3600.0)}
        registry = ContextRegistry()
        scripted_invoke = self.participants.invoke
        def invoke_with_scripted_context(*args):
            reply = scripted_invoke(*args)
            if reply.context_ref not in registry._records:
                purpose = (ContextPurpose.FRESH_REVIEW if reply.context_ref.startswith('fresh-') else
                           ContextPurpose.DEVELOPMENT if reply.context_ref == 'stage-Executor' else
                           ContextPurpose.READ_ONLY_ROLE)
                registry.create(thread_id=reply.context_ref, purpose=purpose, workspace=self.workspace,
                    model='EXPLICIT_OFFLINE_SCRIPT', reasoning_effort='none', tool_profile='SYNTHETIC',
                    codex_version='NOT_A_CODEX_PROCESS', activity_metadata={'stage': 'FX-A1'})
            return reply
        self.participants.invoke = invoke_with_scripted_context
        projection = StateProjection(project='FX', stage_id='FX-A1', workspace=self.workspace,
            artifacts=self.engine.artifacts, registry=registry,
            state_provider=lambda: self.engine.state, source_ref=str(self.engine.store.path),
            authority_materials=self.engine.authority, is_busy=lambda: self.engine._busy)
        self.host = DecisionHost(DecisionEntry(projection), self.engine,
                                 allow_progress=True, allow_owner_events=True)
        factory = self.root / 'factory.py'
        factory.write_text('raise AssertionError("offline factory sentinel")\n', encoding='utf-8')
        self.binding = {'schema_version': 1, 'project': 'FX', 'stage_id': 'FX-A1',
            'workspace': str(self.workspace), 'stage_authorization_ref': 'owner',
            'stage_authorization_sha256': hashlib.sha256(b'Explicit fixture authorization').hexdigest(),
            'decision_role': 'Decision', 'grants': {'allow_progress': True,
                'allow_owner_events': True, 'local_commit_authorized': False},
            'runtime': {'kind': 'development', 'source_root': str(Path(__file__).resolve().parents[1] / 'src'),
                        'approval_ref': 'A6 explicit offline scripted mechanical test only'},
            'factory': {'path': str(factory), 'sha256': hashlib.sha256(factory.read_bytes()).hexdigest()}}
        self.no_process = patch('subprocess.Popen', side_effect=AssertionError('No process/model/Git allowed'))
        self.no_process_mock = self.no_process.start()
        self.addCleanup(self.no_process.stop)
        with patch('loommode.host.canonical._load_factory', return_value=self.host):
            self.owner_client = open_canonical(self.binding)
        self.addCleanup(self.owner_client.owner.close)
        self.client = attach_canonical(self.binding, self.owner_client.owner._path)
        self.assertIsNone(self.client.owner)
        self.assertIsNone(self.client.supervisor)
        snapshot = self.client.status()
        self.client.request({'op': 'start', 'scope': 'current_stage',
                             'expected_revision': snapshot['revision'], 'automatic': False})

    def tearDown(self):
        before = self.engine.store.path.read_bytes()
        self.owner_client.owner.close()
        snapshot = self.owner_client.owner.status()
        health = snapshot['resource_health']
        self.assertEqual(snapshot['canonical_entry']['lease_status'], 'RELEASED')
        self.assertEqual(health['started_workers'], health['joined_workers'])
        self.assertEqual(health['worker_count'], 0)
        self.assertEqual(health['supervisor_count'], 0)
        self.assertEqual(self.engine.store.path.read_bytes(), before)
        self.assertEqual(self.no_process_mock.call_count, 0)
        self.measurements.append({'case': self._testMethodName, 'phase': 'CLOSED',
            'node': self.engine.state.current_node, 'state_status': self.engine.state.status,
            'delegation_status': snapshot['facts']['delegation']['status'],
            'workers_started': health['started_workers'], 'workers_joined': health['joined_workers'],
            'worker_count': health['worker_count'], 'supervisor_count': health['supervisor_count'],
            'lease_status': snapshot['canonical_entry']['lease_status'],
            'actual_os_runtime_directory': str(self.owner_client.owner.lease.directory),
            'canonical_frames_transport': 'AUTHENTICATED_LOOPBACK_IPC_ATTACHED_CLIENT',
            'attached_client_has_owner_fast_path': self.client.owner is not None,
            'runtime_placement_injected': False, 'subprocess_calls': self.no_process_mock.call_count,
            'role_results': 'EXPLICIT_OFFLINE_SCRIPT', 'window_clock': 'EXPLICIT_SYNTHETIC',
            'state_bytes_unchanged_by_close': True})

    def step(self):
        queued = self.client.request({'op': 'advance'})
        result = self.client.status()
        for _ in range(6):
            managed = result['facts']['managed_run']
            last = managed['last_operation'] or {}
            if last.get('sequence') == queued['sequence'] and last.get('worker_joined') and managed['in_flight'] is None:
                break
            result = self.client.request({'op': 'wait', 'after_cursor': managed['update_cursor'], 'timeout': 1})
        else:
            self.fail('IPC wait did not observe this exact joined operation')
        self.assertIsNone(result['facts']['managed_run']['failure'])
        self.assertIsNone(result['facts']['managed_run']['in_flight'])
        self.assertTrue(result['facts']['managed_run']['last_operation']['worker_joined'])
        self.assertLessEqual(result['facts']['managed_run']['last_operation']['steps'], 1)
        return queued, result

    def reach_review_window(self):
        for _ in range(8):
            if self.engine.state.current_node == 'SOFT_REVIEW_WAIT':
                return
            self.step()
        self.fail('scripted stage did not reach its ordinary review window')

    def expire_scripted_window(self):
        window = copy.deepcopy(self.host.windows.current)
        self.assertEqual(window['duration_seconds'], 1800)
        self.clock[0] = window['deadline']
        cursor = self.client.status()['facts']['managed_run']['update_cursor']
        self.callbacks[-1][1]()
        result = self.client.request({'op': 'wait', 'after_cursor': cursor, 'timeout': 5})
        self.assertEqual(self.engine.state.current_node, 'TASK_SELECTION')
        self.assertEqual(result['facts']['managed_run']['phase'], 'WAITING')
        return window

    def reach_acceptance(self):
        self.reach_review_window()
        self.expire_scripted_window()
        for _ in range(12):
            if self.engine.state.current_node == 'COMMIT_AUTHORIZATION':
                return
            self.step()
        self.fail('scripted task did not reach Task acceptance')

    def test_manual_acceptance_waits_and_normal_close_releases_original_lease(self):
        with patch.object(self.participants, 'authorize_commit', wraps=self.participants.authorize_commit) as grant:
            self.reach_acceptance()
            state = self.engine.state
            self.assertEqual(state.status, 'RUNNING')
            self.assertIsNone(state.in_flight_activity)
            self.assertEqual(self.engine.artifacts.read_json(state.acceptance_ref)['action'], 'TASK_ACCEPTED')
            self.assertEqual(len(state.artifact_refs['ACCEPTANCE']), 1)
            self.assertFalse(state.owner_accepted or state.stage_closed or self.engine.commit_authorized)
            self.assertIsNone(state.commit_receipt)
            self.assertEqual(self.client.status()['facts']['managed_run']['phase'], 'WAITING')
            baseline = state.as_dict(), len(self.participants.calls), self.engine.store.path.read_bytes()
            for _ in range(2):
                self.client.request({'op': 'wait', 'after_cursor': self.client.status()['facts']['managed_run']['update_cursor'], 'timeout': 0})
                self.client.status()
            self.assertEqual(baseline, (state.as_dict(), len(self.participants.calls), self.engine.store.path.read_bytes()))
            self.assertNotIn(Node.EXECUTOR_LOCAL_COMMIT, [x['node'] for x in self.participants.calls])
            closed = self.client.request({'op': 'close'})
            self.assertEqual(closed['facts']['managed_run']['phase'], 'CLOSED')
            self.assertEqual(closed['canonical_entry']['lease_status'], 'RELEASED')
            self.assertEqual(closed['resource_health']['started_workers'], closed['resource_health']['joined_workers'])
            self.assertEqual(closed['resource_health']['worker_count'], 0)
            self.assertEqual(self.engine.store.path.read_bytes(), baseline[2])
            lease = WorkspaceLease(self.workspace)
            self.assertTrue(lease.acquire())
            lease.release()
            self.assertEqual(grant.call_count, 0)

    def test_explicit_missing_commit_grant_is_still_rejected_and_events_cannot_replay(self):
        self.reach_acceptance()
        baseline = self.engine.store.path.read_bytes()
        acceptance = self.engine.state.acceptance_ref
        with patch.object(self.participants, 'authorize_commit', wraps=self.participants.authorize_commit) as grant:
            with self.assertRaisesRegex(WorkflowError, 'commit lacks explicit'):
                self.engine._verify_commit_gate(copy.deepcopy(self.engine.state))
            self.assertEqual(grant.call_count, 0)
        # Reuse an already-consumed sequence through the actual supervisor validator.
        from dataclasses import replace
        event = self.owner_client.supervisor.event()
        with self.assertRaisesRegex(WorkflowError, 'sequence'):
            self.owner_client.supervisor.submit(replace(event, sequence=event.sequence - 1))
        self.assertEqual(self.engine.store.path.read_bytes(), baseline)
        self.assertEqual(self.engine.state.acceptance_ref, acceptance)
        self.assertEqual(len(self.engine.state.artifact_refs['ACCEPTANCE']), 1)
        self.assertFalse(self.participants.granted)
        with self.assertRaisesRegex(WorkflowError, 'automatic'):
            self.client.request({'op': 'resume'})
        self.assertEqual(self.engine.store.path.read_bytes(), baseline)

    def test_manual_synthetic_window_expiry_updates_facts_without_dispatch(self):
        self.reach_review_window()
        before = len(self.participants.calls)
        window = self.expire_scripted_window()
        self.assertEqual(len(self.participants.calls), before)
        expected = {**window, 'outcome': 'NO_OBJECTION_OBSERVED', 'owner_accepted': False}
        self.assertIn(expected, self.engine.state.soft_window_events)
        self.assertIsNone(self.engine.state.acceptance_ref)
        self.step()
        self.assertEqual(len(self.participants.calls), before + 1)
        self.assertEqual(self.engine.state.current_node, 'CONSTRAINT_DRAFT')

    @classmethod
    def tearDownClass(cls):
        target = os.environ.get('LOOMMODE_A6_MEASUREMENTS')
        if target:
            with Path(target).open('x', encoding='utf-8') as stream:
                json.dump(cls.measurements, stream, indent=2)
