"""Opt-in native Executor facts at the actual Context/pre-prompt boundary.

The frozen trusted caller owns its existing pool ledger. It reserves once and
publishes pinned snapshots, then seals the completed prompt. This reader never
creates authority, refunds accounting, retries a turn or authenticates chat.
"""
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4

from loommode.codex.context import ContextPurpose, FreshnessState, ResourceState
from loommode.tools.runtime import ToolPhase, ToolProfile
from loommode.workflow.errors import WorkflowError
from .bootstrap import _pinned, CallerVerification


class NativeExecutorAdmission:
    label = 'HOST_NATIVE_EXECUTOR_ADMISSION'

    def __init__(self, host, task_id, caller_id, reserve, seal):
        engine = host.engine
        caller = getattr(engine, 'caller_verification', None)
        relay = getattr(engine, 'caller_relay_verification', None)
        if (engine._busy or engine.state.in_flight_activity
                or engine.state.current_node != 'STAGE_START'
                or getattr(engine.executor, 'native_admission', None) is not None
                or caller is None or relay is None
                or relay.task_id != task_id or relay.caller_id != caller_id
                or caller._input['task_id'] != task_id or caller._input['caller_id'] != caller_id
                or not callable(reserve) or not callable(seal)):
            raise WorkflowError('native admission requires initial trusted Host, current Caller/Relay and callbacks')
        self.host, self.task_id, self.caller_id = host, task_id, caller_id
        self.reserve, self.seal = reserve, seal
        self.working = None
        self.tickets = {}

    @contextmanager
    def activity(self, working):
        if self.working is not None or working.current_node != 'EXECUTOR_IMPLEMENT':
            raise WorkflowError('native admission requires one original implementation activity')
        self.working = working
        try:
            yield
        finally:
            self.working = None

    @staticmethod
    def _read(pin):
        _, raw = _pinned(pin)
        return CallerVerification._json(raw.decode('utf-8-sig'))

    def _publish_private(self, name, value):
        store = self.host.engine.artifacts
        directory = store._guard(store._directory('DECISION') / 'NativeAdmissionPrivate')
        ref = store._publish(directory / name, json.dumps(value, ensure_ascii=False).encode('utf-8'), immutable=True)
        path, digest = ref.rsplit('#sha256=', 1)
        return {'path': path, 'sha256': digest}

    def _context(self, state, context_ref, binding):
        engine, executor = self.host.engine, self.host.engine.executor
        adapter = executor.adapter
        if (self.working is None or not engine._busy or self.host.stop_requested
                or state.get('current_node') != 'EXECUTOR_IMPLEMENT'
                or state.get('task_id') != self.task_id or engine.state.task_id != self.task_id
                or state.get('stage_closed') or executor.main_context != context_ref
                or not adapter.native_workspace_development or not adapter._connected or adapter._closed):
            raise WorkflowError('native admission is not the current live implementation dispatch')
        record = adapter.registry.get(context_ref)
        metadata = record.activity_metadata or {}
        proof = adapter.task_proof(context_ref)
        runtime = proof.runtime
        expected = {'project': state['project'], 'stage_id': state['stage_id'],
                    'task_id': self.task_id, 'intent_ref': state['formal_task_intent_ref'],
                    'final_ref': state['formal_constraint_ref'], 'scope': binding['scope']}
        if (binding != expected or runtime.task_binding != binding
                or proof.backend != 'codex_app_server' or proof.context_ref != context_ref
                or runtime.phase != ToolPhase.IMPLEMENTATION
                or runtime.profile != ToolProfile.BOUNDED_DEVELOPMENT
                or record.thread_id != context_ref or record.owner_id != adapter.owner_id
                or record.purpose != ContextPurpose.DEVELOPMENT
                or record.freshness != FreshnessState.DEVELOPMENT
                or record.tool_profile != ToolProfile.BOUNDED_DEVELOPMENT.value
                or record.resource_state not in {ResourceState.ACTIVE, ResourceState.RETAINED}
                or metadata.get('stage') != state['stage_id'] or metadata.get('role') != 'Executor'
                or Path(record.workspace).resolve() != executor.stage_policy.workspace.resolve()
                or runtime.workspace != executor.stage_policy.workspace.resolve()):
            raise WorkflowError('native recipient Context/purpose/owner/phase/Task binding mismatch')
        for field in ('project', 'stage_id', 'stage_input_ref', 'formal_task_intent_ref', 'formal_constraint_ref'):
            if state[field] != getattr(engine.state, field):
                raise WorkflowError('native admission differs from current original State')
        for ref in (binding['intent_ref'], binding['final_ref']):
            engine.artifacts.read(ref)
        source = engine.caller_verification._pins.get(state['stage_input_ref'])
        _, original = _pinned(source)
        if original.decode('utf-8-sig') != engine.authority.get(state['stage_input_ref']):
            raise WorkflowError('native original Stage authority source changed')
        engine.preflight_task(self.task_id)
        runtime.assert_usable()
        lease = getattr(engine, '_workspace_writer_lease', None)
        if lease is not None and (not lease.held or lease.owner is not engine):
            raise WorkflowError('native admission lost original Writer lease')
        return adapter, runtime

    def _sources(self, state, context_ref, binding, materials):
        adapter, runtime = self._context(state, context_ref, binding)
        engine = self.host.engine
        caller = engine.caller_verification
        result = caller.materials(state, 'EXECUTOR_IMPLEMENT', materials, engine.authority, native=True)
        result = engine.caller_relay_verification.materials(state, 'EXECUTOR_IMPLEMENT', result, native=True)
        for label in ('HOST_CALLER_VERIFICATION', 'HOST_CALLER_RELAY_VERIFICATION'):
            projection = json.loads(result[label])
            projection.update(context_ref=context_ref, purpose='development', phase='IMPLEMENTATION',
                              intent_ref=binding['intent_ref'], final_ref=binding['final_ref'])
            result[label] = json.dumps(projection, ensure_ascii=False)
        return adapter, result

    def _reservation(self, pin, request):
        caller = self.host.engine.caller_verification
        resource, _ = caller._check(self.host.engine.authority)
        value = self._read(pin)
        if (set(value) != {'origin', 'request', 'resource_pin', 'accounting_evidence_pin', 'checks'}
                or value['origin'] != 'CALLER_NATIVE_DISPATCH_RESERVATION' or value['request'] != request
                or value['resource_pin'] != caller._pins[caller._input['resource_ref']]):
            raise WorkflowError('native reservation source/request/original resource mismatch')
        # Accounting algorithms and mutable ledger formats belong to the
        # selected frozen caller. The Host validates this narrow pinned report,
        # its evidence bytes and actual binding; this is not platform attestation.
        _pinned(value['accounting_evidence_pin'])
        checks = value['checks']
        fields = {'reservation_consumed', 'limits_checked', 'chain_ordinal', 'global_ordinal',
                  'checked_at_utc', 'valid_until_utc'}
        if (not isinstance(checks, dict) or set(checks) != fields
                or checks['reservation_consumed'] is not True or checks['limits_checked'] is not True
                or type(checks['chain_ordinal']) is not int
                or not 1 <= checks['chain_ordinal'] <= resource['limits']['max_run_turns']
                or type(checks['global_ordinal']) is not int or checks['global_ordinal'] < 1
                or checks['valid_until_utc'] != resource['valid_until_utc']
                or request['valid_until_utc'] != resource['valid_until_utc']
                or request['deadline_seconds'] != resource['limits']['per_turn_seconds']):
            raise WorkflowError('native caller reservation/limit check is missing or outside approval')
        observed = datetime.fromisoformat(request['observed_at_utc'])
        checked = datetime.fromisoformat(checks['checked_at_utc'])
        if checked.tzinfo is None or not observed <= checked <= datetime.now(timezone.utc):
            raise WorkflowError('native caller reservation report is old or future dated')
        return value, checks, resource

    def prepare(self, state, context_ref, binding, materials, model, effort):
        adapter, result = self._sources(state, context_ref, binding, materials)
        if adapter.runtime_metadata().get('auth_mode') != 'chatgpt':
            raise WorkflowError('native included usage requires original chatgpt Client')
        caller = self.host.engine.caller_verification
        resource, _ = caller._check(self.host.engine.authority)
        request_id = uuid4().hex
        observed_client, observed_owner = adapter.client, adapter.owner_id
        raw = observed_client.request('account/rateLimits/read',
            {'supportsLunaReserve': False, 'excludeResetCreditDetails': True}, timeout=60)
        observed = datetime.now(timezone.utc).isoformat()
        observed_monotonic = time.monotonic()
        quota_pin = self._publish_private(request_id+'-usage.json', {
            'origin': 'ACTUAL_SAME_CLIENT_INCLUDED_USAGE_SNAPSHOT', 'captured_utc': observed,
            'adapter_owner_id': observed_owner, 'context_ref': context_ref, 'actual_response': raw})
        if not isinstance(raw, dict) or raw.get('ordinaryUsageAllowed') is not True:
            raise WorkflowError('current same-Client ordinary included usage is not established')
        if adapter.client is not observed_client or adapter.owner_id != observed_owner:
            raise WorkflowError('native quota observation Client changed while observing usage')
        exact_binding = {**binding, 'workspace': str(adapter.task_proof(context_ref).runtime.workspace),
                         'caller_id': self.caller_id, 'context_ref': context_ref,
                         'adapter_owner_id': adapter.owner_id, 'purpose': 'development', 'phase': 'IMPLEMENTATION'}
        request = {'reservation_id': request_id, 'binding': exact_binding, 'model': model,
                   'reasoning_effort': effort, 'quota_snapshot_pin': quota_pin,
                   'observed_at_utc': observed, 'valid_until_utc': resource['valid_until_utc'],
                   'deadline_seconds': resource['limits']['per_turn_seconds']}
        reservation_pin = self.reserve(copy.deepcopy(request))
        reservation, row, _ = self._reservation(reservation_pin, request)
        # Refresh originals after the trusted callback, not from its output.
        _, result = self._sources(state, context_ref, binding, materials)
        if adapter.client is not observed_client or adapter.owner_id != observed_owner:
            raise WorkflowError('native quota observation Client changed during reservation')
        allowance_refs = state.get('artifact_refs', {}).get('HOST_ALLOWANCE_CONSUMPTION', [])
        allowance = None
        for ref in reversed(allowance_refs):
            value = self.host.engine.artifacts.read_json(ref)
            if (value.get('kind') == 'implementation' and value.get('task_id') == self.task_id
                    and value.get('source') == {'intent_ref': binding['intent_ref'], 'final_ref': binding['final_ref']}
                    and value.get('dispatch_status') == 'RESERVED_BEFORE_CALL'):
                allowance = ref;break
        if allowance is None:
            raise WorkflowError('original protocol implementation allowance is not durably reserved')
        fact = {'origin': self.label, **exact_binding, 'reservation_id': request_id,
                'current_valid': True, 'captured_utc': observed, 'ordinaryUsageAllowed': True,
                'source': 'ACTUAL_SAME_CLIENT_OBSERVATION_AND_TRUSTED_CALLER_ACCOUNTING_REPORT_NOT_A_GRANT',
                'quota_snapshot_sha256_host_only': quota_pin['sha256'],
                'reservation_source_pin': reservation_pin, 'protocol_allowance_ref': allowance,
                'chain_ordinal': row['chain_ordinal'], 'global_ordinal': row['global_ordinal'],
                'deadline_seconds': request['deadline_seconds'], 'valid_until_utc': request['valid_until_utc'],
                'owner_accepted': False, 'actual_currency_cost': 'UNKNOWN',
                'limits': 'As-of Host quota observation and pinned trusted-caller report of its actual durable accounting checks. Host checks source bytes/binding/current approval, not the caller ledger algorithm or platform authentication. Not future quota, Owner approval or a new Grant. Protocol allowance and caller resource accounting are different facts. Prepared failure/UNKNOWN consumes its reservation; prompt is sealed separately after this receipt.'}
        body = json.dumps(fact, ensure_ascii=False)
        reference = self.host.engine.artifacts.save('DECISION', body, task_id=self.task_id)
        # Persist before any prompt/call; keep the Engine's actual working State
        # and its durable in-flight State in agreement, just as allowance does.
        self.host.engine._persist_native_admission(self.working, reference)
        state['artifact_refs'] = copy.deepcopy(self.working.artifact_refs)
        result.update({reference: body, allowance: self.host.engine.artifacts.read(allowance),
                       self.label: json.dumps({**fact, 'verification_ref': reference,
                                              'legal_evidence_refs': [reference, allowance]}, ensure_ascii=False)})
        ticket = {'request': request, 'reservation_pin': copy.deepcopy(reservation_pin),
                  'reference': reference, 'body': body, 'binding': copy.deepcopy(binding),
                  'context_ref': context_ref, 'materials': copy.deepcopy(materials), 'client': observed_client,
                  'prepared_monotonic': observed_monotonic, 'sealed': False, 'dispatch_attempted': False}
        self.tickets[request_id] = ticket
        return ticket, result

    def seal_dispatch(self, ticket, state, prompt):
        request = ticket['request']; request_id = request['reservation_id']
        if self.tickets.get(request_id) is not ticket or ticket['dispatch_attempted']:
            raise WorkflowError('native admission ticket already sealed or not original')
        ticket['dispatch_attempted'] = True  # Even a failed seal is never replayed.
        self._sources(state, ticket['context_ref'], ticket['binding'], ticket['materials'])
        self._reservation(ticket['reservation_pin'], request)
        self._read(request['quota_snapshot_pin'])
        if time.monotonic() - ticket['prepared_monotonic'] > 60:
            raise WorkflowError('native as-of preparation is too old before dispatch')
        expected = {'origin': 'CALLER_NATIVE_DISPATCH_SEAL', 'reservation_pin': ticket['reservation_pin'],
                    'reservation_id': request_id, 'context_ref': ticket['context_ref'],
                    'prompt_sha256': hashlib.sha256(prompt.encode('utf-8')).hexdigest(),
                    'verification_ref': ticket['reference']}
        seal_pin = self.seal(copy.deepcopy(expected))
        sealed = self._read(seal_pin)
        if (set(sealed) != set(expected) | {'accounting_evidence_pin', 'reservation_still_consumed', 'limits_rechecked'}
                or {k: sealed[k] for k in expected} != expected
                or sealed['reservation_still_consumed'] is not True or sealed['limits_rechecked'] is not True):
            raise WorkflowError('native dispatch seal differs from original reservation/actual Prompt')
        _pinned(sealed['accounting_evidence_pin'])
        # Callback side effects cannot revoke a source or change current Context.
        adapter, _ = self._sources(state, ticket['context_ref'], ticket['binding'], ticket['materials'])
        self._reservation(ticket['reservation_pin'], request)
        if self.host.engine.artifacts.read(ticket['reference']) != ticket['body']:
            raise WorkflowError('native admission receipt changed before dispatch')
        if (adapter.client is not ticket['client'] or adapter.owner_id != request['binding']['adapter_owner_id']
                or adapter.runtime_metadata().get('auth_mode') != 'chatgpt'):
            raise WorkflowError('native dispatch no longer uses the observed original Client')
        current = ticket['client'].request('account/rateLimits/read',
            {'supportsLunaReserve': False, 'excludeResetCreditDetails': True}, timeout=60)
        self._publish_private(request_id+'-dispatch-usage.json', {
            'origin': 'ACTUAL_SAME_CLIENT_DISPATCH_RECHECK', 'context_ref': ticket['context_ref'],
            'adapter_owner_id': request['binding']['adapter_owner_id'], 'captured_utc': datetime.now(timezone.utc).isoformat(),
            'actual_response': current})
        if (adapter.client is not ticket['client'] or adapter.owner_id != request['binding']['adapter_owner_id']
                or adapter.runtime_metadata().get('auth_mode') != 'chatgpt'):
            raise WorkflowError('native dispatch Client/owner changed while rechecking included usage')
        if not isinstance(current, dict) or current.get('ordinaryUsageAllowed') is not True:
            raise WorkflowError('included usage revoked before actual native dispatch')
        self._sources(state, ticket['context_ref'], ticket['binding'], ticket['materials'])
        self._reservation(ticket['reservation_pin'], request)
        _pinned(sealed['accounting_evidence_pin'])
        self._read(request['quota_snapshot_pin'])
        if self._read(seal_pin) != sealed:
            raise WorkflowError('native dispatch seal source changed during quota recheck')
        if self.host.engine.artifacts.read(ticket['reference']) != ticket['body']:
            raise WorkflowError('native admission artifact changed during quota recheck')
        if time.monotonic() - ticket['prepared_monotonic'] > 60:
            raise WorkflowError('native as-of observation expired before dispatch')
        ticket['sealed'] = True
        ticket['seal_pin'] = copy.deepcopy(seal_pin)
        return request['deadline_seconds']
