"""Host-configured, read-only consumption sources; never execution authority."""
import copy
import hashlib
import json
from contextvars import ContextVar
from dataclasses import fields
from pathlib import Path

from .errors import WorkflowError
from .state import WorkflowState, identity, unique_json_object
from .transitions import Node, STOP_NODES


def merge_events(groups, *, reports=(), implementation_units=None, verified_implementation_prefix=0):
    """Union originals; only verified report evidence may cover legacy impl gaps."""
    events, ordinals = {}, {}
    for group in groups:
        for event in group:
            ref = event['reference']
            if ref in events and events[ref] != event:
                raise WorkflowError('allowance history event identity conflict')
            slot = (event['kind'], event['ordinal'])
            if slot in ordinals and ordinals[slot] != ref:
                raise WorkflowError('allowance history same ordinal has different events')
            events[ref], ordinals[slot] = event, ref
    for kind in {kind for kind, _ in ordinals}:
        numbers = sorted(n for k, n in ordinals if k == kind)
        missing = set(range(1, max(numbers) + 1)) - set(numbers)
        report_floor = len(reports) if implementation_units is None else implementation_units
        # Preserve strict standalone legacy validation. Only a prefix obtained
        # from revalidated original HistorySources may cover an inherited gap;
        # every later reservation must still be present, including FAILED calls.
        covered = (kind == 'implementation' and (report_floor >= max(numbers) or
                   verified_implementation_prefix > 0 and all(n <= verified_implementation_prefix for n in missing)))
        if missing and not covered:
            raise WorkflowError('allowance history has missing consumption events')
    return sorted(events.values(), key=lambda e: (e['kind'], e['ordinal']))


def merge_reports(groups):
    reports = {}
    for group in groups:
        for report in group:
            ref = report['reference']
            if ref in reports and reports[ref] != report:
                raise WorkflowError('allowance history report identity conflict')
            reports[ref] = report
    return sorted(reports.values(), key=lambda r: r['reference'])


def report_outputs(state, artifacts):
    """Authenticate Host-authored exact references; prose never selects a source."""
    outputs = {}
    for binding_ref in state.artifact_refs.get('HOST_REPORT_OUTPUT_BINDING', []):
        if binding_ref not in state.artifact_refs.get('DECISION', []):
            raise WorkflowError('report binding lacks Host registration')
        binding = artifacts.read_json(binding_ref)
        owner = binding.get('task_id')
        if (set(binding) != {'origin', 'task_id', 'report_result_ref', 'role_output_ref'}
                or binding['origin'] != 'HOST_REPORT_OUTPUT_BINDING'
                or not isinstance(owner, str) or owner not in state.used_task_ids
                or any(not isinstance(binding[key], str) or not binding[key]
                       for key in ('report_result_ref', 'role_output_ref'))):
            raise WorkflowError('report binding invalid Host identity')
        artifacts.assert_task_reference(binding_ref, 'DECISION', owner)
        if (binding['report_result_ref'] not in state.artifact_refs.get('REPORT_RESULT', [])
                or binding['report_result_ref'] not in state.artifact_refs.get('DECISION', [])
                or binding['role_output_ref'] not in state.artifact_refs.get('ROLE_OUTPUT', [])
                or binding['role_output_ref'] not in state.artifact_refs.get('DECISION', [])):
            raise WorkflowError('report binding endpoint lacks Host registration')
        artifacts.assert_task_reference(binding['report_result_ref'], 'DECISION', owner)
        artifacts.assert_task_reference(binding['role_output_ref'], 'DECISION', owner)
        bound_output = artifacts.read_json(binding['role_output_ref'])
        if (bound_output.get('origin'), bound_output.get('activity'), bound_output.get('task_id')) != (
                'HOST_ROLE_OUTPUT', 'EXECUTOR_IMPLEMENT', owner):
            raise WorkflowError('report binding output identity mismatch')
        if bound_output.get('result') != artifacts.read_json(binding['report_result_ref']):
            raise WorkflowError('report binding output Task/result mismatch')
        report_ref = binding['report_result_ref']
        if report_ref in outputs:
            raise WorkflowError('report requires exactly one original Host output binding')
        outputs[report_ref] = binding['role_output_ref']
    return outputs


def report_unit(state, store, artifacts, report, workspace):
    """Read original Host evidence locally; never serialize it into history receipts.

    Unmanaged/legacy reports remain separate. Managed deduplication requires
    an explicit Host report/output binding and full original receipt/reservation.
    """
    ref, task = report['reference'], report['task_id']
    if (report['store_path'] != str(store.path.resolve())
            or (report['project'], report['stage_id']) != (state.project, state.stage_id)
            or (store.project, store.stage_id) != (state.project, state.stage_id)
            or (artifacts.project, artifacts.stage) != (state.project, state.stage_id)
            or task not in state.used_task_ids
            or ref not in state.artifact_refs.get('REPORT_RESULT', [])
            or ref not in state.artifact_refs.get('DECISION', [])):
        raise WorkflowError('report unit original Host endpoint mismatch')
    artifacts.assert_task_reference(ref, 'DECISION', task)
    result = artifacts.read_json(ref)
    outputs = report_outputs(state, artifacts)
    selected_ref = outputs.get(ref)
    if selected_ref is None:
        raise WorkflowError('report requires exactly one original Host output binding')
    artifacts.assert_task_reference(selected_ref, 'DECISION', task)
    bound_outputs = set(outputs.values())
    units = {}
    attempts, reservations = {}, {}
    missing_managed = False
    for output_ref in state.artifact_refs.get('ROLE_OUTPUT', []):
        if output_ref not in state.artifact_refs.get('DECISION', []):
            raise WorkflowError('report unit output lacks Host registration')
        output = artifacts.read_json(output_ref)
        if output.get('origin') != 'HOST_ROLE_OUTPUT':
            raise WorkflowError('report unit invalid Host output identity')
        if output.get('activity') != 'EXECUTOR_IMPLEMENT':
            continue  # Other genuine role outputs need not have a Task owner.
        # A Task claim alone cannot exclude evidence: authenticate its path and
        # Host identity before isolating another legitimate Task. Managed
        # outputs additionally require their complete receipt provenance.
        owner = output.get('task_id')
        if not isinstance(owner, str) or owner not in state.used_task_ids:
            raise WorkflowError('report unit unknown output owner')
        artifacts.assert_task_reference(output_ref, 'DECISION', owner)
        if output_ref == selected_ref and (owner != task or output.get('result') != result):
            # Equality verifies integrity AFTER selecting the explicit reference;
            # it never discovers or chooses an output, even for identical prose.
            raise WorkflowError('report binding output Task/result mismatch')
        metadata = output.get('invocation')
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise WorkflowError('report unit invalid Host metadata')
        facts = metadata.get('host_fixed_tests')
        if facts is None:
            if owner == task and output_ref in bound_outputs:
                missing_managed = True
            continue
        if not isinstance(facts, dict) or not isinstance(facts.get('implementation_receipt'), dict):
            raise WorkflowError('report unit incomplete managed evidence')
        receipt = facts['implementation_receipt']
        required = {'attempt_id', 'origin', 'request_fingerprint', 'context_ref', 'pid',
            'exit_code', 'stdin_complete', 'truncated', 'cleanup', 'working_files_removed',
            'outcome', 'terminal_status', 'reservation_ref', 'native_authority',
            'production_eligible', 'raw_output_sha256'}
        if (output.get('origin') != 'HOST_ROLE_OUTPUT'
                or output.get('activity') != 'EXECUTOR_IMPLEMENT' or output.get('task_id') != owner
                or facts.get('origin') != 'HOST_MANAGED_FIXED_TESTS'
                or type(facts.get('generation')) is not int or facts['generation'] < 1
                or set(receipt) != required
                or not all(isinstance(receipt.get(k), str) and receipt[k] for k in
                           ('attempt_id', 'origin', 'request_fingerprint', 'context_ref', 'reservation_ref', 'raw_output_sha256'))
                or output.get('context_ref') != facts.get('context_ref')
                or receipt['context_ref'] != facts.get('context_ref')
                or receipt['request_fingerprint'] != facts.get('request_fingerprint')):
            raise WorkflowError('report unit managed identity conflict or incomplete evidence')
        reservation = receipt['reservation_ref']
        if (reservation not in state.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION', [])
                or reservation not in state.artifact_refs.get('DECISION', [])):
            raise WorkflowError('report unit reservation lacks Host registration')
        artifacts.assert_task_reference(reservation, 'DECISION', owner)
        candidate_event = artifacts.read_json(reservation)
        if (candidate_event.get('origin') != 'HOST_ALLOWANCE_CONSUMPTION'
                or candidate_event.get('task_id') != owner or candidate_event.get('kind') != 'implementation'
                or candidate_event.get('dispatch_status') != 'RESERVED_BEFORE_CALL'
                or type(candidate_event.get('ordinal')) is not int or candidate_event['ordinal'] < 1):
            raise WorkflowError('report unit original reservation mismatch')
        implementation = (facts['context_ref'], facts['request_fingerprint'], facts['generation'],
                          json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False))
        for ledger, key, kind in ((attempts, (owner, receipt['attempt_id']), 'attempt'),
                                  (reservations, (owner, reservation), 'reservation')):
            if key in ledger and ledger[key] != implementation:
                raise WorkflowError(f'original implementation {kind} identity conflict')
            ledger[key] = implementation
        if owner != task:
            continue
        event = candidate_event
        units[output_ref] = ((str(store.path.resolve()), state.project, state.stage_id, workspace, task,
                   facts['context_ref'], facts['request_fingerprint'], facts['generation'],
                   json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False)), event)
    selected = units.get(selected_ref)
    if selected:
        unit, event = selected
        # A legacy checkpoint can have a durable ordinal gap predating the
        # reservation protocol. Its reports remain conservative separate units:
        # do not lower that frozen witness merely because two receipts match.
        # Validated imported lower bounds cover predecessors, not local gaps.
        family = event.get('family_task_id')
        ordinals = set()
        for event_ref in state.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION', []):
            item = artifacts.read_json(event_ref)
            if item.get('kind') == 'implementation' and item.get('family_task_id') == family:
                ordinals.add(item['ordinal'])
        floor = 0
        for history_ref in state.artifact_refs.get('HOST_ALLOWANCE_HISTORY', []):
            if history_ref not in state.artifact_refs.get('DECISION', []):
                raise WorkflowError('report unit history lacks Host registration')
            history = artifacts.read_json(history_ref)
            if history.get('family_task_id') == family:
                floor = max(floor, history['source']['used_lower_bounds']['implementation'])
        if missing_managed or any(n > floor and n not in ordinals for n in range(1, max(ordinals, default=0) + 1)):
            # Retain the verified identity even when counting conservatively.
            # Gaps or mixed evidence must never suppress attempt conflict checks.
            return ('legacy-managed-report', ref, unit)
        return unit
    return ('legacy-report', ref)


def count_report_units(reports, resolver):
    units, attempts, reservations = set(), {}, {}
    for report in reports:
        unit = resolver(report)
        managed = unit[2] if unit[0] == 'legacy-managed-report' else unit
        if managed[0] != 'legacy-report':
            receipt = json.loads(managed[-1])
            attempt = (*managed[:5], receipt['attempt_id'])
            if attempt in attempts and attempts[attempt] != managed:
                raise WorkflowError('original implementation attempt identity conflict')
            attempts[attempt] = managed
            reservation = (*managed[:5], receipt['reservation_ref'])
            if reservation in reservations and reservations[reservation] != managed:
                raise WorkflowError('original implementation reservation identity conflict')
            reservations[reservation] = managed
        units.add(unit)
    return len(units)


def evidence_ids(snapshot):
    return {v['reference'] for key in ('events', 'reports') for v in snapshot[key]}


_HISTORY_TRAVERSAL = ContextVar('allowance_history_synchronous_traversal', default=None)


class _HistoryTraversal:
    """One synchronous call only: authenticated snapshots plus exact read set.

    Never retained on an Engine/Source, across dispatch, or for live usage.
    Every first read is authenticated normally; all bytes and bindings are
    re-read before the outer result can escape. No mtime/counter shortcut.
    """
    def __init__(self):
        self.files = {}
        self.bindings = []
        self.snapshots = {}
        self.pending = set()

    def read(self, path):
        path = Path(path)
        raw = path.read_bytes()
        prior = self.files.setdefault(path, raw)
        if prior != raw:raise WorkflowError('history dependency drift during traversal')
        return raw

    def artifacts(self, original):
        store = copy.copy(original)
        read = store.read
        def authenticated(reference):
            path = store._guard(Path(reference.rsplit('#sha256=',1)[0]))
            before = self.read(path)
            value = read(reference)  # Original digest, decoding and namespace checks.
            if self.read(path) != before:raise WorkflowError('history artifact drift during traversal')
            return value
        store.read = authenticated
        return store

    @staticmethod
    def source_identity(source):
        return (source.name, str(source.store.path.resolve()), source.store.project, source.store.stage_id,
            str(source.artifacts.root.resolve()), source.artifacts.project, source.artifacts.stage,
            str(source.path), str(source.root), source.checkpoint_sha256, source.workspace,
            source.source_task_id, source.recipient_task_id, source.recipient_workspace,
            source.recipient_stage_id, source.family_task_id, copy.deepcopy(source.authority),
            tuple((name,id(value)) for name,value in source.sources.items()))

    @staticmethod
    def recipient_identity(engine):
        return (engine.state.project,engine.state.stage_id,str(engine.store.path),
            str(engine.artifacts.root),engine._allowance_workspace(),
            copy.deepcopy(engine.state.active_grant),copy.deepcopy(engine.authority))

    def verify(self):
        for path, raw in self.files.items():
            if path.read_bytes() != raw:raise WorkflowError('history dependency changed before traversal return')
        for source,engine,source_id,recipient_id in self.bindings:
            if self.source_identity(source)!=source_id or self.recipient_identity(engine)!=recipient_id:
                raise WorkflowError('history source/receiver/authority binding drift')
            engine._check_history_endpoint()


class AllowanceHistorySource:
    """Trust anchor selected by Host code from an actual stopped StateStore.

    No caller-supplied counts or digest is accepted. Store bytes are pinned here
    and re-read on every use. Host must protect these handles and original files
    from model writes and bind every required predecessor, using one sequential
    writer. An omitted predecessor or parallel fork cannot be discovered globally.
    """

    def __init__(self, name, store, artifacts, *, workspace: Path, source_task_id,
                 recipient_task_id, recipient_workspace: Path, recipient_stage_id,
                 family_task_id, authority_materials, history_sources=None):
        self.name = identity(name)
        self.store, self.artifacts = store, artifacts
        self.workspace = str(workspace.resolve())
        self.source_task_id = identity(source_task_id)
        self.recipient_task_id = identity(recipient_task_id)
        self.recipient_workspace = str(recipient_workspace.resolve())
        self.recipient_stage_id = identity(recipient_stage_id)
        self.family_task_id = identity(family_task_id)
        self.authority = dict(authority_materials)
        self.sources = dict(history_sources or {})
        self.path = store.path.resolve()
        self.root = artifacts.root.resolve()
        try:
            self.checkpoint_sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()
        except OSError as exc:
            raise WorkflowError('allowance history source checkpoint unavailable') from exc

    def snapshot(self, engine):
        traversal = _HISTORY_TRAVERSAL.get()
        outer = traversal is None
        if outer:traversal = _HistoryTraversal()
        token = _HISTORY_TRAVERSAL.set(traversal)
        try:
            engine._check_history_endpoint()
            source_id = traversal.source_identity(self)
            recipient_id = traversal.recipient_identity(engine)
            key = (id(self), repr(source_id), repr(recipient_id))
            traversal.bindings.append((self,engine,source_id,recipient_id))
            if key in traversal.pending:raise WorkflowError('cyclic original history source')
            if key in traversal.snapshots:
                result = copy.deepcopy(traversal.snapshots[key])
            else:
                traversal.pending.add(key)
                try:result = self._snapshot_authenticated(engine, traversal)
                finally:traversal.pending.remove(key)
                traversal.snapshots[key] = copy.deepcopy(result)
            if outer:traversal.verify()
            return result
        except WorkflowError:
            raise
        except (OSError,ValueError,TypeError,KeyError) as exc:
            raise WorkflowError('invalid original history traversal') from exc
        finally:
            _HISTORY_TRAVERSAL.reset(token)

    def _snapshot_authenticated(self, engine, traversal):
        try:
            # Historical reader uses its own original endpoint. This binding is
            # causal evidence, never a replacement for either endpoint's Grant.
            if (engine.state.stage_id != self.recipient_stage_id
                    or engine._allowance_workspace() != self.recipient_workspace):
                raise WorkflowError('allowance history recipient Stage/workspace mismatch')
            engine._check_history_endpoint()
            if self.store.path.resolve() != self.path or self.artifacts.root.resolve() != self.root:
                raise WorkflowError('allowance history source Store binding changed')
            raw = traversal.read(self.path)
            if hashlib.sha256(raw).hexdigest() != self.checkpoint_sha256:
                raise WorkflowError('allowance history source checkpoint changed')
            payload = json.loads(raw, object_pairs_hook=unique_json_object)
            if not isinstance(payload, dict) or set(payload) != {f.name for f in fields(WorkflowState)}:
                raise WorkflowError('allowance history checkpoint fields missing or unknown')
            state = WorkflowState(**payload)
            state.validate()
            if Node(state.current_node) not in STOP_NODES:
                raise WorkflowError('allowance history requires a stopped immutable source')
            if ((state.project, state.stage_id) != (self.store.project, self.store.stage_id)
                    or (state.project, state.stage_id) != (self.artifacts.project, self.artifacts.stage)
                    or state.project != engine.state.project
                    or not state.active_grant or state.active_grant['workspace'] != self.workspace
                    or self.source_task_id not in state.used_task_ids):
                raise WorkflowError('allowance history source project/workspace/Store identity mismatch')
            # Reuse production family/totals validation without constructing,
            # saving, restarting or importing any old execution State.
            reader = copy.copy(engine)
            reader.state, reader.store, reader.artifacts = state, self.store, traversal.artifacts(self.artifacts)
            reader.authority, reader.history_sources = self.authority, self.sources
            reader._history_workspace = self.workspace
            reader._history_read_only = True
            reader._allowance_write_failed = False
            reader._check_history_endpoint()
            # Formal source inputs are part of this authenticated dependency set.
            for ref in (state.formal_task_intent_ref,state.formal_constraint_ref,state.latest_execution_report_ref):
                if ref:reader.artifacts.read(ref)
            family = reader._allowance_family(state, self.source_task_id)
            if family != self.family_task_id:
                raise WorkflowError('allowance history source family mismatch')
            selected = copy.deepcopy(state)
            selected.task_id = self.source_task_id
            totals = reader._allowance_totals(selected)
            events = reader._allowance_events(selected, family)
            reports = reader._allowance_reports(selected, family)
            # The original ordinal and Host-registered reports establish a lower
            # bound, not a reconstructed event for a missing reservation.
            lower_bounds = {kind: max((e['ordinal'] for e in events if e['kind'] == kind), default=0)
                            for kind in ('implementation', 'repair', 'treatment', 'decision_flow', 'new_basis')}
            lower_bounds['implementation'] = max(lower_bounds['implementation'], reader._allowance_report_count(selected, family, reports))
            for kind in ('implementation', 'repair', 'treatment', 'decision_flow', 'new_basis'):
                if totals[kind] != lower_bounds[kind]:
                    raise WorkflowError('legacy allowance history lacks evidence for used lower bound')
            # Catch source changes during validation as well as on later use.
            if self.path.read_bytes() != raw:
                raise WorkflowError('allowance history source changed during validation')
            return {'name': self.name, 'store_path': str(self.path), 'records_root': str(self.root),
                    'checkpoint_sha256': self.checkpoint_sha256, 'project': state.project,
                    'stage_id': state.stage_id, 'workspace': self.workspace,
                    'source_task_id': self.source_task_id, 'family_task_id': family,
                    'events': events, 'reports': reports, 'used_lower_bounds': lower_bounds}
        except WorkflowError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise WorkflowError('invalid or unavailable original allowance history') from exc

    def report_unit(self, report):
        """Resolve only through configured, pinned original Stores."""
        if report['store_path'] == str(self.path):
            traversal = _HISTORY_TRAVERSAL.get()
            raw = traversal.read(self.path) if traversal is not None else self.path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != self.checkpoint_sha256:
                raise WorkflowError('report unit source checkpoint changed')
            state = WorkflowState(**json.loads(raw, object_pairs_hook=unique_json_object))
            state.validate()
            unit = report_unit(state, self.store, traversal.artifacts(self.artifacts) if traversal is not None else self.artifacts, report, self.workspace)
            if self.path.read_bytes() != raw:
                raise WorkflowError('report unit source changed during validation')
            return unit
        matches = [s for s in self.sources.values() if s.contains_report_store(report['store_path'])]
        if not matches:
            raise WorkflowError('report unit lacks configured original Host source')
        units = {s.report_unit(report) for s in matches}
        if len(units) != 1:
            raise WorkflowError('report unit source conflict')
        return units.pop()

    def contains_report_store(self, path):
        return path == str(self.path) or any(s.contains_report_store(path) for s in self.sources.values())
