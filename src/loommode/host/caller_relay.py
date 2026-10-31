"""Narrow live-Host verification of a pinned local notice-relay capture.

The trusted caller supplies the pin at a quiescent Host boundary. This verifies
local provenance and current bindings; it cannot authenticate chat delivery.
Nothing in a role response or Authority body invokes this interface.
"""
import copy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import identity


class CallerRelayVerification:
    activities = frozenset({'TASK_SELECTION', 'CONSTRAINT_DRAFT', 'DISCUSS_NORMAL',
                            'CONSTRAINT_FINALIZE', 'DECISION_MEDIATION'})
    label = 'HOST_CALLER_RELAY_VERIFICATION'

    def __init__(self, host, task_id, caller_id, source_provider):
        engine = host.engine
        identity(task_id)
        if (engine._busy or engine.state.in_flight_activity or engine.state.current_node not in {'STAGE_START', 'STAGE_REVIEW'}
                or getattr(engine, 'caller_relay_verification', None) is not None
                or task_id not in engine.executor.task_policies
                or not isinstance(caller_id, str) or not caller_id.strip()
                or not callable(source_provider)):
            raise WorkflowError('relay requirement needs an initial idle Host, explicit Task/caller and trusted pin provider')
        self.host, self.task_id, self.caller_id = host, task_id, caller_id
        self.source_provider = source_provider
        self.source_pin = self.receipt_ref = self.receipt_body = None
        self.binding = None

    def _identity(self):
        state = self.host.engine.state
        return {'project': state.project, 'stage_id': state.stage_id,
                'task_id': self.task_id, 'workspace': str(self.host.engine.executor.stage_policy.workspace.resolve()),
                'caller_id': self.caller_id}

    @staticmethod
    def _time(value):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                raise ValueError()
            return parsed
        except (TypeError, ValueError) as exc:
            raise WorkflowError('relay requires explicit timezone-aware timestamps') from exc

    def _read_source(self, pin):
        from .bootstrap import _pinned, CallerVerification
        _, raw = _pinned(pin)
        value = CallerVerification._json(raw.decode('utf-8-sig'))
        fields = {'origin', 'project', 'stage_id', 'task_id', 'workspace', 'caller_id',
                  'notice_ref', 'plan_ref', 'decision_ref', 'window', 'relayed_at_utc',
                  'valid_until_utc', 'owner_notice_relayed', 'owner_accepted'}
        if (set(value) != fields or value['origin'] != 'CALLER_LOCAL_NOTICE_RELAY_CAPTURE'
                or value['owner_notice_relayed'] is not True or value['owner_accepted'] is not False
                or any(value[k] != v for k, v in self._identity().items())):
            raise WorkflowError('relay source schema, identity or local-capture classification mismatch')
        now = datetime.now(timezone.utc)
        if not self._time(value['relayed_at_utc']) <= now < self._time(value['valid_until_utc']):
            raise WorkflowError('relay source is future-dated or expired')
        return value

    def capture_if_ready(self):
        """Called only inside the bound Host's serialized operation, before expiry."""
        engine, state = self.host.engine, self.host.engine.state
        if self.receipt_ref is not None or state.current_node != 'SOFT_REVIEW_WAIT':
            return
        if engine._busy or state.in_flight_activity or self.host.stop_requested or state.stage_closed:
            raise WorkflowError('relay capture requires a live known-effect idle window')
        pin = self.source_provider()
        if pin is None:
            return  # Missing evidence is rejected before Task Selection dispatch.
        value = self._read_source(pin)
        window = self.host.windows.current
        if (not window or value['window'] != window or window['node'] != 'SOFT_REVIEW_WAIT'
                or value['notice_ref'] != state.stage_notice_ref
                or value['plan_ref'] != state.stage_plan_ref
                or value['decision_ref'] != state.stage_plan_decision_ref):
            raise WorkflowError('relay capture does not bind the actual current Notice/Plan/Decision/window')
        # Admission happens within the real window, never after a delayed timer
        # callback. A caller timestamp cannot extend a Host monotonic deadline.
        clock = self.host.windows.clock()
        if clock >= window['deadline']:
            raise WorkflowError('relay capture must be verified before the Host review deadline')
        started = datetime.now(timezone.utc) - timedelta(
            seconds=clock - window['deadline'] + window['duration_seconds'])
        if self._time(value['relayed_at_utc']) < started - timedelta(seconds=1):
            raise WorkflowError('relay capture predates the actual current review window')
        refs = [value[k] for k in ('notice_ref', 'plan_ref', 'decision_ref')]
        registered = {r for values in state.artifact_refs.values() for r in values}
        if any(ref not in registered for ref in refs):
            raise WorkflowError('relay source originals must be registered formal Records artifacts')
        for ref in refs:
            engine.artifacts.read(ref)
        if self.host.windows.clock() >= window['deadline']:
            raise WorkflowError('relay source verification crossed the Host review deadline')
        binding = {'window': copy.deepcopy(window), 'notice_ref': state.stage_notice_ref,
                   'plan_ref': state.stage_plan_ref, 'decision_ref': state.stage_plan_decision_ref,
                   'human_events': copy.deepcopy(state.human_events),
                   'owner_window_refs': list(state.owner_window_refs)}
        fact = {'origin': 'HOST_LOCAL_RELAY_SOURCE_VERIFICATION', **self._identity(),
                'source_pin': copy.deepcopy(pin), 'source_class': 'CALLER_LOCAL_CAPTURE_NOT_PLATFORM_AUTHENTICATION',
                'verified_at_utc': datetime.now(timezone.utc).isoformat(),
                'relayed_at_utc': value['relayed_at_utc'], 'valid_until_utc': value['valid_until_utc'],
                'notice_ref': value['notice_ref'], 'plan_ref': value['plan_ref'],
                'decision_ref': value['decision_ref'], 'window': copy.deepcopy(window),
                'owner_notice_relayed_reported': True, 'owner_accepted': False,
                'permissions_expanded': False,
                'limits': 'Host verified pinned local capture and current original bindings; chat delivery is caller-reported, not independently platform-authenticated. This is evidence, not Owner approval, a Grant, expiry or resumption.'}
        body = json.dumps(fact, ensure_ascii=False)
        ref = engine.artifacts.save('DECISION', body)
        working = copy.deepcopy(state)
        working.artifact_refs.setdefault(self.label, []).append(ref)
        engine.store.save(working)
        engine.state = working
        self.source_pin, self.binding = copy.deepcopy(pin), binding
        self.receipt_ref, self.receipt_body = ref, body
        if self.host._delegation:
            from .state_view import _digest
            self.host._delegation['expected_state'] = _digest(working.as_dict())
            self.host._persist_delegation()

    def _check(self, state, *, require_expiry=True):
        engine = self.host.engine
        if not self.receipt_ref:
            raise WorkflowError('required caller relay verification evidence is missing')
        value = self._read_source(self.source_pin)
        bound = self.binding
        if (state.get('project') != self._identity()['project'] or state.get('stage_id') != self._identity()['stage_id']
                or state.get('task_id') not in (None, self.task_id)
                or state.get('stage_notice_ref') != bound['notice_ref']
                or state.get('stage_plan_ref') != bound['plan_ref']
                or state.get('stage_plan_decision_ref') != bound['decision_ref']
                or state.get('human_events') != bound['human_events']
                or state.get('owner_window_refs') != bound['owner_window_refs']
                or self.host.stop_requested or state.get('stage_closed')
                or self.host.windows.run_id != bound['window']['run_id']
                or self.host.windows.epoch != bound['window']['stage_epoch']
                or value['window'] != bound['window']
                or any(value[k] != bound[k] for k in ('notice_ref', 'plan_ref', 'decision_ref'))
                or self.receipt_ref not in state.get('artifact_refs', {}).get(self.label, [])):
            raise WorkflowError('caller relay evidence is stale, revoked or bound to another live State')
        event = {**bound['window'], 'outcome': 'NO_OBJECTION_OBSERVED', 'owner_accepted': False}
        if require_expiry and event not in state.get('soft_window_events', []):
            raise WorkflowError('relay does not substitute for actual current Host window expiry')
        if not require_expiry and (state.get('current_node') != 'SOFT_REVIEW_WAIT'
                or self.host.windows.current != bound['window']
                or self.host.windows.clock() >= bound['window']['deadline']):
            raise WorkflowError('explicit relay verification requires the current unexpired review window')
        for ref in (bound['notice_ref'], bound['plan_ref'], bound['decision_ref']):
            if ref not in {r for values in state.get('artifact_refs', {}).values() for r in values}:
                raise WorkflowError('caller relay original reference is no longer registered')
            engine.artifacts.read(ref)
        if engine.artifacts.read(self.receipt_ref) != self.receipt_body:
            raise WorkflowError('caller relay verification artifact changed')

    def materials(self, state, activity, materials, *, native=False):
        if native and activity != 'EXECUTOR_IMPLEMENT':
            raise WorkflowError('native relay facts apply only to implementation')
        result = dict(materials)
        result.pop(self.label, None)
        if self.receipt_ref:
            result.pop(self.receipt_ref, None)
        if activity == 'DECISION_MEDIATION':
            # A judgment may concern an earlier activity or invalid evidence.
            # It must remain callable to apply the existing safe disposition.
            if state.get('current_node') != activity:
                raise WorkflowError('caller relay activity differs from the actual current State')
            ref = state.get('decision_handoff_ref')
            if not ref or ref not in state.get('artifact_refs', {}).get('DECISION_HANDOFF', []):
                raise WorkflowError('relay diagnostic requires the actual registered Decision handoff')
            finding = self.host.engine.artifacts.read_json(ref)
            if (finding.get('origin') != 'HOST_INTERNAL_ESCALATION'
                    or finding.get('stage_id') != state.get('stage_id')
                    or finding.get('task_id') != state.get('task_id')
                    or finding.get('origin_activity') != finding.get('resume_node')):
                raise WorkflowError('relay diagnostic Decision finding binding mismatch')
            from loommode.workflow.transitions import Node
            origin = Node(finding['resume_node']).value
            progress_requires_relay = (origin in self.activities - {'DECISION_MEDIATION'}
                                       or state.get('task_id') is not None)
            historical = []
            if self.receipt_ref in state.get('artifact_refs', {}).get(self.label, []):
                # The immutable prior check may be cited as historical evidence,
                # even when its source or current applicability is now invalid.
                body = self.host.engine.artifacts.read(self.receipt_ref)
                if body != self.receipt_body:
                    raise WorkflowError('caller relay historical verification artifact changed')
                result[self.receipt_ref] = body
                historical = [self.receipt_ref]
            result[self.label] = json.dumps({'origin': self.label, **self._identity(),
                'active_task_id': state.get('task_id'), 'context_ref': None,
                'source': 'HOST_RELAY_ADJUDICATION_DIAGNOSTIC_NOT_A_GRANT',
                'finding_ref': ref, 'origin_activity': origin,
                'origin_requires_relay_for_progress': progress_requires_relay,
                'applicability': 'EXECUTION_PREREQUISITE' if progress_requires_relay else 'NOT_REQUIRED_FOR_THIS_JUDGMENT',
                'verification_status': 'PENDING_ACTUAL_CONTEXT_CHECK', 'current_valid': False,
                'verification_ref': None, 'historical_verification_refs': historical,
                'legal_evidence_refs': historical, 'owner_accepted': False}, ensure_ascii=False)
            return result
        if activity in self.activities or state.get('task_id') is not None:
            if state.get('current_node') != activity:
                raise WorkflowError('caller relay activity differs from the actual current State')
            self._check(state)
        if activity not in self.activities and not native:
            return result
        result[self.receipt_ref] = self.receipt_body
        result[self.label] = json.dumps({'origin': self.label, **self._identity(),
            'active_task_id': state.get('task_id'), 'context_ref': None,
            'source': 'DERIVED_HOST_LOCAL_SOURCE_CHECK_NOT_A_NEW_GRANT',
            'verification_status': 'VALID', 'current_valid': True,
            'verification_ref': self.receipt_ref,
            'legal_evidence_refs': [self.receipt_ref], 'owner_accepted': False}, ensure_ascii=False)
        return result

    def bind_context(self, state, activity, materials, context_ref, registry):
        expected = self.materials(state, activity, materials)
        if activity not in self.activities:
            return expected
        if (materials.get(self.label) != expected[self.label]
                or materials.get(self.receipt_ref) != expected.get(self.receipt_ref)):
            raise WorkflowError('caller relay projection is forged or from an old Context')
        from loommode.codex.context import ContextPurpose, FreshnessState
        from loommode.workflow.transitions import Node, TABLE
        record = registry.get(context_ref)
        metadata = record.activity_metadata or {}
        if (record.thread_id != context_ref or record.purpose != ContextPurpose.READ_ONLY_ROLE
                or record.freshness != FreshnessState.READ_ONLY_ROLE or record.tool_profile != 'READ_ONLY_REVIEW'
                or str(Path(record.workspace).resolve()) != self._identity()['workspace']
                or metadata.get('stage') != self._identity()['stage_id']
                or metadata.get('role') != TABLE[Node(activity)][0].value):
            raise WorkflowError('caller relay recipient Context identity/purpose/role mismatch')
        projection = json.loads(expected[self.label])
        projection['context_ref'] = context_ref
        if activity == 'DECISION_MEDIATION':
            try:
                self._check(state)
            except (WorkflowError, OSError, UnicodeError):
                projection['verification_status'] = 'MISSING' if self.receipt_ref is None else 'INVALID'
                projection['limits'] = ('Current relay validity is unestablished. Any supplied prior verification '
                    'is historical evidence only. Decision may adjudicate the actual finding or Owner input '
                    'under existing routes; this diagnostic grants no execution or resumption. '
                    'Task Selection and selected Task activities still require valid relay evidence.')
            else:
                projection.update(verification_status='VALID', current_valid=True,
                                  verification_ref=self.receipt_ref)
        expected[self.label] = json.dumps(projection, ensure_ascii=False)
        return expected
