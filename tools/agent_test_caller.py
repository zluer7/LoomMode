"""Finite one-Task caller example, activated only by a reviewed pinned factory.

No authorization or notice attestation is generated here. The later operator
supplies original Owner/resource/preparation pins and the live relay capture.
Append-only accounting never refunds or resumes a failed/unknown reservation.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from threading import RLock
from uuid import uuid4

from loommode.host.bootstrap import _output_path, _pinned
from loommode.workflow.errors import WorkflowError


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def publish(path, value):
    path = Path(path)
    _output_path(path.parent, path)
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


class OneTaskCaller:
    def __init__(self, host, *, config, request_pin, directory):
        self.host, self.config = host, config
        self.request_pin = request_pin
        self.request_raw = _pinned(request_pin)[1]
        self.directory = Path(directory)
        self.lock = RLock()
        self._event_count, self._head, self._identity_pin = 0, None, None
        self.identity = {k: config[k] for k in ('project', 'stage_id', 'workspace')}
        self.task = next(iter(config['task_policies']))
        verification = host.engine.caller_verification
        if verification is None or len(config['task_policies']) != 1:
            raise WorkflowError('one current Task and original Caller verification required')
        self.caller_id = verification._input['caller_id']
        self.identity.update(task_id=self.task, caller_id=self.caller_id)
        self.resource_pin = config['authorities'][verification._input['resource_ref']]
        resource, _ = verification._check(host.engine.authority)
        self.resource = copy.deepcopy(resource)
        remaining = (datetime.fromisoformat(resource['valid_until_utc']) - datetime.now(timezone.utc)).total_seconds()
        self.monotonic_deadline = time.monotonic() + remaining
        self.check()
        _output_path(self.directory.parent, self.directory)
        # Existing spend/unknown state is never silently loaded or reset.
        self.directory.mkdir()
        self._identity_pin = publish(self.directory / 'identity.json', {'origin': 'ONE_TASK_CALLER_ACCOUNTING',
                **self.identity, 'resource_pin': self.resource_pin, 'request_pin': request_pin})

    def check(self):
        if self._identity_pin is not None:
            _pinned(self._identity_pin)
        for reference in self.config['authorities'].values():
            _pinned(reference)
        if _pinned(self.request_pin)[1] != self.request_raw:
            raise WorkflowError('original setup request changed')
        current, _ = self.host.engine.caller_verification._check(self.host.engine.authority)
        if current != self.resource or any(current[k] != v for k, v in self.identity.items()):
            raise WorkflowError('caller original resource binding changed')
        now = datetime.now(timezone.utc)
        start = datetime.fromisoformat(current['authorized_at_utc'])
        expiry = datetime.fromisoformat(current['valid_until_utc'])
        if (not start <= now < expiry or time.monotonic() >= self.monotonic_deadline
                or (now - start).total_seconds() >= current['limits']['total_seconds']
                or current['limits']['max_additional_charge'] != 0):
            raise WorkflowError('caller fixed resource/time/route allowance unavailable')
        self.host.engine.grant()
        if self.host.stop_requested or self.host.engine.state.stage_closed:
            raise WorkflowError('caller cannot dispatch after an actual stop/Stage close')
        lease = getattr(self.host.engine, '_workspace_writer_lease', None)
        if lease is None or not lease.held or lease.owner is not self.host.engine:
            raise WorkflowError('caller lost original Writer ownership')
        return current

    def events(self):
        _output_path(self.directory.parent, self.directory)
        rows = []
        previous = None
        names = sorted(self.directory.glob('event-*.json'))
        for ordinal, path in enumerate(names, 1):
            if path.name != 'event-%06d.json' % ordinal:
                raise WorkflowError('caller accounting sequence missing/conflicting; no replay')
            _output_path(self.directory, path)
            value = json.loads(path.read_text(encoding='utf-8'))
            if value.get('previous') != previous or value.get('sequence') != ordinal:
                raise WorkflowError('caller accounting chain changed; no replay')
            rows.append(value)
            previous = hashlib.sha256(path.read_bytes()).hexdigest()
        if len(rows) != self._event_count or previous != self._head:
            raise WorkflowError('caller accounting head removed/changed; no replay')
        return rows

    def append(self, kind, reservation_id, **fields):
        rows = self.events()
        previous = None if not rows else hashlib.sha256(
            (self.directory / ('event-%06d.json' % len(rows))).read_bytes()).hexdigest()
        value = {'sequence': len(rows) + 1, 'previous': previous, 'kind': kind,
                 'reservation_id': reservation_id, 'at_utc': datetime.now(timezone.utc).isoformat(), **fields}
        pin = publish(self.directory / ('event-%06d.json' % (len(rows) + 1)), value)
        self._event_count += 1
        self._head = pin['sha256']
        return pin

    def reserve(self, reservation_id, **fields):
        resource = self.check()
        rows = self.events()
        if any(row['reservation_id'] == reservation_id for row in rows):
            raise WorkflowError('reservation identity cannot be reused')
        ordinal = sum(row['kind'] == 'reserve' for row in rows) + 1
        if ordinal > resource['limits']['max_run_turns']:
            raise WorkflowError('caller actual finite call allowance exhausted')
        pin = self.append('reserve', reservation_id, ordinal=ordinal, **fields)
        return ordinal, pin

    def context(self, reference):
        adapter = self.host.engine.roles.adapter
        record = adapter.registry.get(reference)
        if (record.owner_id != adapter.owner_id or record.thread_id != reference
                or str(Path(record.workspace).resolve()) != self.identity['workspace']
                or record.resource_state.value not in {'ACTIVE', 'RETAINED'}):
            raise WorkflowError('caller Context/owner/workspace is not current')
        if adapter.runtime_metadata().get('auth_mode') != 'chatgpt':
            raise WorkflowError('caller requires existing ordinary subscription route')
        return adapter

    def reserve_native(self, request):
        with self.lock:
            self.check()
            binding = request['binding']
            if (any(binding.get(k) != v for k, v in self.identity.items())
                    or binding.get('scope') != self.host.engine.caller_verification._input['scope']
                    or binding.get('purpose') != 'development' or binding.get('phase') != 'IMPLEMENTATION'
                    or request['valid_until_utc'] != self.resource['valid_until_utc']
                    or request['deadline_seconds'] != self.resource['limits']['per_turn_seconds']):
                raise WorkflowError('native callback request differs from actual authorization')
            self.context(binding['context_ref'])
            _pinned(request['quota_snapshot_pin'])
            ordinal, accounting = self.reserve(request['reservation_id'], native_request=copy.deepcopy(request))
            value = {'origin': 'CALLER_NATIVE_DISPATCH_RESERVATION', 'request': request,
                     'resource_pin': self.resource_pin, 'accounting_evidence_pin': accounting,
                     'checks': {'reservation_consumed': True, 'limits_checked': True,
                                'chain_ordinal': ordinal, 'global_ordinal': ordinal,
                                'checked_at_utc': datetime.now(timezone.utc).isoformat(),
                                'valid_until_utc': self.resource['valid_until_utc']}}
            return publish(self.directory / (request['reservation_id'] + '-reservation.json'), value)

    def seal_native(self, expected):
        with self.lock:
            self.check()
            reservation = json.loads(_pinned(expected['reservation_pin'])[1])
            request = reservation['request']
            identity = expected['reservation_id']
            rows = [r for r in self.events() if r['reservation_id'] == identity]
            if (len(rows) != 1 or rows[0]['kind'] != 'reserve'
                    or rows[0].get('native_request') != request or request['reservation_id'] != identity
                    or expected['context_ref'] != request['binding']['context_ref']
                    or expected['reservation_pin']['path'] != str(self.directory / (identity + '-reservation.json'))
                    or len(expected['prompt_sha256']) != 64):
                raise WorkflowError('native seal requires one original unclaimed reservation')
            self.context(expected['context_ref'])
            accounting = self.append('seal', identity, expected=copy.deepcopy(expected))
            return publish(self.directory / (identity + '-seal.json'), {**expected,
                'accounting_evidence_pin': accounting, 'reservation_still_consumed': True, 'limits_rechecked': True})

    def relay_pin(self):
        # Operator writes a capture only AFTER actually relaying current original
        # Notice/Plan/Decision. This helper never writes that attestation.
        path = self.directory.parent / 'notice-relay-selection.json'
        if not path.exists():
            return None
        _output_path(self.directory.parent, path)
        pin = json.loads(path.read_text(encoding='utf-8'))
        _pinned(pin)
        return pin

    def run_turn(self, original, **kwargs):
        with self.lock:
            self.check()
            adapter = self.context(kwargs['thread_id'])
            client = adapter.client
            prompt_hash = hashlib.sha256(kwargs['prompt'].encode()).hexdigest()
            native = [r for r in self.events() if r['kind'] == 'seal'
                      and r['expected']['context_ref'] == kwargs['thread_id']
                      and r['expected']['prompt_sha256'] == prompt_hash]
            if native:
                identity = native[-1]['reservation_id']
                if any(r['kind']=='claim' and r['reservation_id']==identity for r in self.events()):
                    raise WorkflowError('sealed dispatch already claimed; no replay')
                # Native preparation already consumed this reservation. Even a
                # final quota/transport failure permanently consumes its claim.
                self.append('claim',identity,context_ref=kwargs['thread_id'],prompt_sha256=prompt_hash)
            else:
                record = adapter.registry.get(kwargs['thread_id'])
                if ('\nACTIVITY: EXECUTOR_IMPLEMENT\n' in kwargs['prompt']
                        and (record.activity_metadata or {}).get('purpose') != 'REPORT_CORRECTION'):
                    raise WorkflowError('native implementation has no original sealed reservation')
                identity = uuid4().hex
            quota = client.request('account/rateLimits/read',
                {'supportsLunaReserve': False, 'excludeResetCreditDetails': True}, timeout=60)
            if (adapter.client is not client or not isinstance(quota, dict)
                    or quota.get('ordinaryUsageAllowed') is not True):
                raise WorkflowError('caller current same-client ordinary usage unavailable')
            if not native:
                self.reserve(identity, context_ref=kwargs['thread_id'], prompt_sha256=prompt_hash)
                self.append('claim', identity, context_ref=kwargs['thread_id'], prompt_sha256=prompt_hash,
                            quota_sha256=digest(quota))
            self.check()  # Failed recheck still consumes the reservation and claim.
            self.context(kwargs['thread_id'])
            if adapter.client is not client:
                raise WorkflowError('caller client changed before dispatch')
            deadline = min(self.resource['limits']['per_turn_seconds'],
                           self.monotonic_deadline - time.monotonic())
            if 'deadline_seconds' in kwargs:
                deadline = min(deadline, kwargs['deadline_seconds'])
            kwargs['deadline_seconds'] = deadline
        # Single Writer/Host serializes activities; no lock held during model call.
        return original(**kwargs)


def install(supervisor, *, config, request_pin):
    host = supervisor.host
    caller = OneTaskCaller(host, config=config, request_pin=request_pin,
                           directory=Path(config['runtime_root']) / 'one-task-accounting')
    host.require_caller_relay(task_id=caller.task, caller_id=caller.caller_id, source_provider=caller.relay_pin)
    host.require_native_executor_admission(task_id=caller.task, caller_id=caller.caller_id,
                                         reserve=caller.reserve_native, seal=caller.seal_native)
    adapter = host.engine.roles.adapter
    original = adapter.run_turn
    adapter.run_turn = lambda **kwargs: caller.run_turn(original, **kwargs)
    return caller
