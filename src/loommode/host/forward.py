"""Explicit immutable failed-source admission and authenticated successor consumption.

Host-selected pinned files only. No restart, proof import, resource creation or model calls.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object
from .ownership import workspace_identity, _check_namespace, _LEASES


from .private_instance import private_value, require_private_instance

SOURCE_ROOT = Path(__file__).resolve().parents[3]


def source_files():
    """A5 forward-admission identity: rewalk the complete production Python closure.

    Owned by forward admission, independent of historical Native grant/source policy.
    Adding a production module changes the identity; an absent/oversized closure fails.
    """
    paths = tuple(p.relative_to(SOURCE_ROOT).as_posix()
                  for p in sorted((SOURCE_ROOT / 'src/loommode').rglob('*.py')))
    if not paths or len(paths) > 512:
        raise WorkflowError('Forward admission source closure absent/over bound')
    return paths


def digest(path):
    from .materials import material_path
    path=material_path(path)
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pinned(ref):
    if not isinstance(ref,dict) or set(ref)!={'path','sha256'}:
        raise WorkflowError('explicit immutable reference required')
    from .materials import material_path
    path=material_path(ref['path'],ref['sha256'])
    if not path.is_absolute():raise WorkflowError('absolute immutable reference required')
    _check_namespace(path)
    if digest(path)!=ref['sha256']:raise WorkflowError('immutable reference changed')
    return path


def document(ref):
    path=pinned(ref)
    if path.stat().st_size>2_000_000:raise WorkflowError('bounded authority document required')
    return json.loads(path.read_bytes(),object_pairs_hook=unique_json_object)


def stamp(value):
    try:
        if not isinstance(value,str) or not value.endswith('Z'):raise ValueError()
        result=datetime.fromisoformat(value[:-1]+'+00:00')
        if result.isoformat(timespec='seconds').replace('+00:00','Z')!=value:raise ValueError()
        return result
    except ValueError as exc:raise WorkflowError('canonical original UTC seconds required') from exc


class ConsumptionChain:
    """Frozen source segments plus one current authenticated segment, one original pool."""
    def __init__(self,reference):
        self.reference=reference
        self.spec=document(reference)
        if (set(self.spec)!={'purpose','pool_owner','segments','current'} or
                self.spec['purpose']!='AUTHENTICATED_SUCCESSOR_CONSUMPTION_V1'):
            raise WorkflowError('explicit consumption chain schema required')
        owner=document(self.spec['pool_owner'])
        self.pool=owner
        self.original_pool=owner
        self.limits={'roles':35,'native':3,'CORE_roles':18,'CORE_native':2,'EXPORT_roles':13,'EXPORT_native':1}
        if owner.get('purpose') in ('ACTUAL_V005_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V006_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V007_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):
            from .successor import validate_owner
            self.original_pool=validate_owner(self.spec['pool_owner'])[1]
            self.limits.update(roles=48 if owner['purpose'] in ('ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL') else 43 if owner['purpose']=='ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL' else 42,native=4,CORE_native=3)
            expected={'ACTUAL_V007_SINGLE_SUCCESSOR_OWNER_APPROVAL':2,'ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL':3,'ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL':4,'ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL':5,'ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL':6,'ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL':7,'ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL':8,'ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL':9}.get(owner['purpose'],1)
            if len(self.spec['segments'])!=expected:raise WorkflowError('exact immutable predecessor segments required')
        elif owner.get('approved') is not True or owner.get('caps')!={'roles':35,'native':3}:
            raise WorkflowError('original bounded pool Owner required')
        self.workspace=workspace_identity(self.original_pool['scope']['workspace'])

    def _writer(self, lease):
        if lease is None or not lease.held or lease.workspace != self.workspace or _LEASES.get(self.workspace) is not lease:
            raise WorkflowError('original exclusive successor Writer required')

    def _anchor_paths(self):
        native = Path(self.spec['current']['native'])
        return Path(str(native)+'.consumption.jsonl'), Path(str(native)+'.initialized')

    def _source_states(self):
        states = {}
        for key in ('native', 'bindings', 'roles'):
            path = Path(self.spec['current'][key])
            _check_namespace(path)
            raw = path.read_bytes()  # Missing established sources are never zero consumption.
            if len(raw)>2_000_000:raise WorkflowError('bounded successor source required')
            states[key] = {'length':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}
        return states

    def _anchor_identity(self):
        current = self.spec['current']
        return {'chain':self.reference, 'authorities':{
            key:digest(current[key]['path'] if isinstance(current[key],dict) else current[key])
            for key in ('grant','plan','activation')}}

    @staticmethod
    def _durable_line(path, row, mode):
        with path.open(mode) as stream:
            stream.write(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
            stream.flush();os.fsync(stream.fileno())

    def _anchor(self):
        journal, marker = self._anchor_paths()
        try:
            _check_namespace(journal);_check_namespace(marker)
            identity=self._anchor_identity()
            if json.loads(marker.read_bytes(),object_pairs_hook=unique_json_object)!=identity:
                raise WorkflowError('successor initialization identity changed')
            raw=journal.read_bytes()
            if not raw or len(raw)>2_000_000 or not raw.endswith(b'\n'):
                raise WorkflowError('successor monotonic journal incomplete')
            previous=None;last=None
            for index,line in enumerate(raw.splitlines()):
                row=json.loads(line,object_pairs_hook=unique_json_object)
                if set(row)!={'ordinal','previous','identity','sources'} or row['ordinal']!=index or row['previous']!=previous or row['identity']!=identity:
                    raise WorkflowError('successor monotonic journal identity/continuity changed')
                if last:
                    changed=[k for k in ('native','bindings','roles') if row['sources'][k]!=last['sources'][k]]
                    if len(changed)!=1 or row['sources'][changed[0]]['length']<=last['sources'][changed[0]]['length']:
                        raise WorkflowError('successor monotonic journal refunded consumption')
                previous=hashlib.sha256(line).hexdigest();last=row
            if last['sources']!=self._source_states():
                raise WorkflowError('successor source missing/truncated/rolled back or unreserved append')
            return last,previous
        except (OSError,ValueError,KeyError,TypeError) as exc:
            raise WorkflowError('successor durable consumption unknown; no reset') from exc

    def initialize_current(self, *, writer_lease):
        """Explicit one-time fresh initialization, after authenticated authority and Writer admission.

        Never inferred by a reader. A surviving create-only marker forbids reinitializing
        a lost journal. Partial writes/crashes fail closed; no recovery is attempted.
        """
        from .managed_native import _RESERVATIONS
        with _RESERVATIONS:
            self._writer(writer_lease)
            journal,marker=self._anchor_paths()
            if marker.exists() or journal.exists():raise WorkflowError('successor already initialized; no reset')
            # Authenticate Grant/Plan/nonce and require genuinely unspent sources.
            self.snapshot()
            nonce=self._read_current_activation()['nonce']
            if any(document(item['segment']['activation'])['nonce']==nonce for item in self.spec['segments']):raise WorkflowError('reused successor nonce')
            counts,*_=self._segment(self.spec['current'],frozen=False,initializing=True)
            if counts['roles'] or counts['native']:raise WorkflowError('fresh successor must be unspent')
            for key in ('native','bindings','roles'):
                path=Path(self.spec['current'][key]);_check_namespace(path)
                if not path.exists():
                    with path.open('xb') as stream:stream.flush();os.fsync(stream.fileno())
            identity=self._anchor_identity()
            self._durable_line(marker,identity,'xb')
            self._durable_line(journal,{'ordinal':0,'previous':None,'identity':identity,'sources':self._source_states()},'xb')
            self._anchor()

    def append_current(self, source, raw, *, writer_lease):
        """Reserve exact bytes durably BEFORE source append; deletion before first read is fenced.

        All successor writers must use this API; unjournaled appends are rejected.
        Journal-first crashes retain the reservation and fail closed.
        """
        from .managed_native import _RESERVATIONS
        with _RESERVATIONS:
            self._writer(writer_lease)
            if source not in ('native','bindings','roles') or not isinstance(raw,bytes) or not raw.endswith(b'\n') or len(raw.splitlines())!=1:
                raise WorkflowError('one exact successor reservation required')
            last,previous=self._anchor()
            row=json.loads(raw,object_pairs_hook=unique_json_object)
            current=self.spec['current']
            if source=='roles':self.before_role(row['bucket'])
            else:
                grant=document(current['grant']) if isinstance(current['grant'],dict) else json.loads(Path(current['grant']).read_bytes())
                gp=current['grant']['path'] if isinstance(current['grant'],dict) else current['grant']
                if source=='native':
                    from .managed_native import ManagedNativeHost
                    bindings=ManagedNativeHost._task_bindings(grant,digest(gp),Path(current['native']))
                    task=bindings.get(row['request_fingerprint'],{}).get('task_id')
                else:task=row['task_id']
                self.before_native(grant,digest(gp),Path(current['native']),task)
            path=Path(current[source]);existing=path.read_bytes()
            states=dict(last['sources']);states[source]={'length':len(existing)+len(raw),'sha256':hashlib.sha256(existing+raw).hexdigest()}
            journal,_=self._anchor_paths()
            self._durable_line(journal,{'ordinal':last['ordinal']+1,'previous':previous,'identity':last['identity'],'sources':states},'ab')
            with path.open('ab') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            self._segment(current,frozen=False)  # Original exact row identity validators remain authoritative.

    def _read_current_activation(self):
        ref=self.spec['current']['activation']
        return document(ref) if isinstance(ref,dict) else json.loads(Path(ref).read_bytes(),object_pairs_hook=unique_json_object)

    def _initialized_boot_stop(self,segment):
        """Exact ninth initialized preREADY stop. Containment is not business cleanup."""
        from .successor import validate_owner
        if self.pool.get('purpose')!='ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL':raise WorkflowError('exact v014 ninth admission required')
        approved=self.pool['ninth_initialized_boot_stop_history_approved'];refs=approved['original_refs'];proof=segment['closed_unused']
        expected={k:refs[v] for k,v in {'chain':'chain','journal':'journal','marker':'marker','state':'State_identity_only','startup_failure':'startup_failure','owned_child':'owned_child','pre_serve':'pre_serve','resource_close':'resource_close','application_result':'application_result'}.items()}
        if proof!=expected:raise WorkflowError('exact ninth proof identities required')
        for group in ('original_refs','execution_refs','independent_proof_refs'):
            for ref in approved[group].values():
                path=pinned({k:ref[k] for k in ('path','sha256')})
                if 'bytes' in ref and path.stat().st_size!=ref['bytes']:raise WorkflowError('ninth evidence size changed')
        pinned(approved['identity_bundle'])
        for key in ('owner','plan','grant','activation','roles','native','bindings'):
            if segment[key]!=refs[key]:raise WorkflowError('ninth endpoint identity changed')
        prior=ConsumptionChain(refs['chain']);owner,_=validate_owner(refs['owner']);plan=document(refs['plan'])
        if prior.spec['pool_owner']!=refs['owner'] or self.spec['segments'][:8]!=prior.spec['segments']:raise WorkflowError('exact eight predecessor prefix required')
        if len(prior.spec['segments'])!=8 or segment['task_windows']!=prior.spec['current']['task_windows']:raise WorkflowError('ninth original Task windows changed')
        for key in ('grant','activation','plan','roles','native','bindings'):
            if segment[key]['path']!=prior.spec['current'][key]:raise WorkflowError('ninth original current endpoint mismatch')
        if plan['actual_owner']!=refs['owner'] or plan['consumption_chain']!=refs['chain'] or Path(plan['working']).name!=private_value('forward', 'value_24'):raise WorkflowError('ninth Plan binding changed')
        for key in ('grant','activation','native_owner','writer','safety'):
            if plan['authority_paths'][key]!=refs[key]['path']:raise WorkflowError('ninth authority endpoint changed')
        activation=document(refs['activation']);grant=document(refs['grant']);native_owner=document(refs['native_owner'])
        if (activation.get('owner_sha256')!=refs['owner']['sha256'] or activation.get('startup_plan_sha256')!=refs['plan']['sha256'] or activation.get('grant_sha256')!=refs['grant']['sha256'] or activation.get('safety_sha256')!=refs['safety']['sha256'] or activation.get('writer_sha256')!=refs['writer']['sha256'] or native_owner.get('actual_owner')!=refs['owner']):raise WorkflowError('ninth authority binding mismatch')
        for key in ('approved_at','expires_at'):
            if activation.get(key)!=owner[key]:raise WorkflowError('ninth original UTC changed')
        if grant.get('expires_at')!=owner['expires_at']:raise WorkflowError('ninth Grant expiry changed')
        last,_=prior._anchor()
        if last['ordinal']!=0 or any(last['sources'][k]['length']!=0 or pinned(refs[k]).stat().st_size!=0 for k in ('roles','native','bindings')):raise WorkflowError('ninth requires actual initialized zero ledgers')
        state=document(refs['State_identity_only'])
        fields={'project':plan['project'],'stage_id':plan['stage'],'status':'RUNNING','current_node':'STAGE_START','task_id':None,'in_flight_activity':None,'formal_task_intent_ref':None,'formal_constraint_ref':None,'latest_execution_report_ref':None,'used_task_ids':[],'soft_window_events':[],'owner_accepted':False,'artifact_refs':{}}
        if any(state.get(k)!=v for k,v in fields.items()):raise WorkflowError('ninth initialized State projection changed')
        if Path(refs['State_identity_only']['path'])!=Path(plan['working'])/'state/workflow'/plan['project']/plan['stage']/'state.json':raise WorkflowError('ninth State endpoint mismatch')
        app=document(refs['application_result']);failure=document(refs['startup_failure']);resource=document(refs['resource_close']);job=resource['owned_job_receipt']
        if any(app.get(k)!=v for k,v in {'status':'FAILED_OR_CLEANUP_UNPROVED','exit_code':2,'run_id':None,'legal_stop':False,'cleanup_proved':False,'Stage_accepted':False}.items()):raise WorkflowError('ninth application unknown stop changed')
        if failure.get('error_type')!='Empty' or failure.get('run_id') is not None or failure.get('Stage_accepted') is not False:raise WorkflowError('ninth preREADY failure changed')
        if any(resource.get(k)!=v for k,v in {'business_cleanup_proved':False,'cleanup_proved':False,'unknown_business_side_effects':True,'child_exit_code':1,'reader_threads_joined':True,'pipes_closed':True,'process_handle_closed':True,'errors':[],'Stage_accepted':False}.items()) or any(job.get(k) is not True for k in ('root_terminated','tree_terminated_confirmed','job_handle_closed')) or job.get('errors')!=[] or job.get('unknown_side_effect') is not False:raise WorkflowError('ninth containment evidence changed')
        for name,item in approved['absent_evidence'].items():
            if item.get('exists') is not False or ('path' in item and Path(item['path']).exists()):raise WorkflowError('ninth absent START/close evidence changed')
        for group in ('original_refs','execution_refs','independent_proof_refs'):
            for ref in approved[group].values():pinned({k:ref[k] for k in ('path','sha256')})
        return owner

    def _closed_unused(self,segment):
        """Only the two actual closed v006/v007 segments, never report flags."""
        from .successor import V006_OWNER_SHA256,V007_OWNER_SHA256,V008_OWNER_SHA256,V009_OWNER_SHA256,V010_OWNER_SHA256,V011_OWNER_SHA256,V012_OWNER_SHA256,validate_owner
        if segment['owner']['sha256']==private_value('forward', 'value_0'):return self._initialized_boot_stop(segment)
        proof=segment['closed_unused']
        v012=segment['owner']['sha256']==V012_OWNER_SHA256
        v011=segment['owner']['sha256']==V011_OWNER_SHA256
        v010=segment['owner']['sha256']==V010_OWNER_SHA256
        v009=segment['owner']['sha256']==V009_OWNER_SHA256
        v008=segment['owner']['sha256']==V008_OWNER_SHA256
        v007=segment['owner']['sha256']==V007_OWNER_SHA256
        keys={'chain','journal','marker','state','close'}|({'resource_close'} if v007 or v008 or v009 or v010 or v011 or v012 else set())
        if set(proof)!=keys:raise WorkflowError('complete closed unused evidence required')
        anchors={'chain':private_value('forward', 'value_1'),
            'state':private_value('forward', 'value_2'),
            'close':private_value('forward', 'value_3')}
        if v007:
            anchors={'chain':private_value('forward', 'value_4'),
                'state':private_value('forward', 'value_5'),
                'close':private_value('forward', 'value_6'),
                'resource_close':private_value('forward', 'value_7')}
        if v008:
            anchors={'chain':private_value('forward', 'value_8'),
                'state':private_value('forward', 'value_9'),
                'close':private_value('forward', 'value_10'),
                'resource_close':private_value('forward', 'value_11'),
                'journal':private_value('forward', 'value_12'),
                'marker':private_value('forward', 'value_13')}
            if segment['roles']['sha256']!=private_value('forward', 'value_14'):raise WorkflowError('exact v008 role consumption required')
        extra_refs={}
        if v009:
            if self.pool.get('purpose') not in ('ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):raise WorkflowError('exact v010 fifth exception required')
            extra_refs=self.pool['fifth_fixed_history_exception_approved']['original_refs']
            for r in extra_refs.values():pinned(r)
            for key,approved in (('owner','owner'),('plan','plan'),('roles','roles'),('grant','grant_identity_only'),('activation','activation_identity_only')):
                if segment[key]!=extra_refs[approved]:raise WorkflowError('fifth original endpoint/raw identity mismatch')
            for key,approved in (('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close')):
                if proof[key]!=extra_refs[approved]:raise WorkflowError('fifth original proof endpoint/raw identity mismatch')
            anchors={'chain':private_value('forward', 'value_15'),
                'state':private_value('forward', 'value_16'),
                'close':private_value('forward', 'value_17'),
                'resource_close':private_value('forward', 'value_18'),
                'journal':private_value('forward', 'value_19'),
                'marker':private_value('forward', 'value_20')}
        if v010:
            if self.pool.get('purpose') not in ('ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):raise WorkflowError('exact v011 sixth history required')
            extra_refs=self.pool['sixth_normal_closed_history_approved']['original_refs']
            for r in extra_refs.values():pinned(r)
            for key in ('owner','plan','roles','native','bindings','grant','activation'):
                if segment[key]!=extra_refs[key]:raise WorkflowError('sixth original endpoint/raw mismatch')
            for key,approved in (('chain','chain'),('journal','journal'),('marker','marker'),('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close')):
                if proof[key]!=extra_refs[approved]:raise WorkflowError('sixth original proof identity mismatch')
            anchors={k:extra_refs[a]['sha256'] for k,a in (('chain','chain'),('journal','journal'),('marker','marker'),('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close'))}
        if v011:
            if self.pool.get('purpose') not in ('ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):raise WorkflowError('exact v011 seventh history required')
            extra_refs=self.pool['seventh_normal_closed_history_approved']['original_refs']
            for r in extra_refs.values():pinned(r)
            for key in ('owner','plan','roles','native','bindings','grant','activation'):
                if segment[key]!=extra_refs[key]:raise WorkflowError('seventh original endpoint/raw mismatch')
            for key,approved in (('chain','chain'),('journal','journal'),('marker','marker'),('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close')):
                if proof[key]!=extra_refs[approved]:raise WorkflowError('seventh original proof identity mismatch')
            anchors={k:extra_refs[a]['sha256'] for k,a in (('chain','chain'),('journal','journal'),('marker','marker'),('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close'))}
        if v012:
            if self.pool.get('purpose') not in ('ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):raise WorkflowError('exact v011 eighth history required')
            extra_refs=self.pool['eighth_normal_closed_history_approved']['original_refs']
            for r in extra_refs.values():pinned(r)
            for key in ('owner','plan','roles','native','bindings','grant','activation'):
                if segment[key]!=extra_refs[key]:raise WorkflowError('eighth original endpoint/raw mismatch')
            for key,approved in (('chain','chain'),('journal','journal'),('marker','marker'),('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close')):
                if proof[key]!=extra_refs[approved]:raise WorkflowError('eighth original proof identity mismatch')
            anchors={k:extra_refs[a]['sha256'] for k,a in (('chain','chain'),('journal','journal'),('marker','marker'),('state','State_identity_only'),('close','same_run_close'),('resource_close','resource_close'))}
        if any(proof[k]['sha256']!=h for k,h in anchors.items()):raise WorkflowError('exact actual closed v006 evidence required')
        prior=ConsumptionChain(proof['chain'])
        if prior.spec['pool_owner']!=segment['owner'] or segment['owner']['sha256']!=(V012_OWNER_SHA256 if v012 else V011_OWNER_SHA256 if v011 else V010_OWNER_SHA256 if v010 else V009_OWNER_SHA256 if v009 else V008_OWNER_SHA256 if v008 else V007_OWNER_SHA256 if v007 else V006_OWNER_SHA256):
            raise WorkflowError('closed segment original Owner mismatch')
        owner,_=validate_owner(segment['owner'])
        if self.spec['segments'][:len(prior.spec['segments'])]!=prior.spec['segments']:raise WorkflowError('paid predecessor changed or omitted')
        for key in ('grant','activation','plan','native','bindings','roles'):
            if segment[key]['path']!=prior.spec['current'][key]:raise WorkflowError('closed segment endpoint identity mismatch')
            pinned(segment[key])
        if segment['task_windows']!=prior.spec['current']['task_windows']:raise WorkflowError('closed Task windows changed')
        plan=document(segment['plan'])
        if plan['actual_owner']!=segment['owner'] or Path(plan['working']).name!=(private_value('forward', 'value_25') if v012 else private_value('forward', 'value_26') if v011 else private_value('forward', 'value_27') if v010 else private_value('forward', 'value_28') if v009 else private_value('forward', 'value_29') if v008 else private_value('forward', 'value_30') if v007 else private_value('forward', 'value_31')):raise WorkflowError('closed Plan Owner/working mismatch')
        if v009 or v010 or v011 or v012:
            if plan['consumption_chain']!=proof['chain']:raise WorkflowError('fifth original chain mismatch')
            for key in ('grant','activation','native_owner','writer','safety'):
                if plan['authority_paths'][key]!=extra_refs[key if v010 or v011 or v012 else key+'_identity_only']['path']:raise WorkflowError('fifth original authority endpoint mismatch')
        for key,path in zip(('journal','marker'),prior._anchor_paths()):
            if Path(proof[key]['path'])!=path:raise WorkflowError('closed initialization endpoint mismatch')
            pinned(proof[key])
        last,_=prior._anchor()
        if last['ordinal']!=(5 if v012 else 4 if v011 else 1 if v008 or v009 or v010 or v011 or v012 else 0) or any(last['sources'][k]['length']!=(pinned(extra_refs['roles']).stat().st_size if (v011 or v012) and k=='roles' else 238 if (v008 or v009 or v010 or v011 or v012) and k=='roles' else 0) for k in ('roles','native','bindings')):
            raise WorkflowError('closed segment is not initial and unused')
        state=document(proof['state'])
        expected={'project':plan['project'],'stage_id':plan['stage'],'status':'RUNNING','current_node':'STAGE_START',
            'task_id':None,'formal_task_intent_ref':None,'formal_constraint_ref':None,'latest_execution_report_ref':None,
            'in_flight_activity':None,'used_task_ids':[],'soft_window_events':[],'owner_accepted':False}
        if v008 or v009 or v010 or v011 or v012:expected.update(status='FAILED',current_node='FAILED',in_flight_activity='STAGE_REVIEW')
        if v011 or v012:
            expected.update(status='FAILED',current_node='FAILED',in_flight_activity='TASK_SELECTION')
            del expected['soft_window_events']  # exact pinned original State includes its old window; no new-run credit.
            if len(state.get('soft_window_events',[]))!=1:raise WorkflowError('exact closed old window required')
        if v012:expected.update(status='WAITING_HUMAN',current_node='HUMAN_BLOCK',in_flight_activity=None)
        if any(state.get(k)!=v for k,v in expected.items()):raise WorkflowError('closed unused State boundary changed')
        expected_state=Path(plan['working'])/'state/workflow'/plan['project']/plan['stage']/'state.json'
        if Path(proof['state']['path'])!=expected_state:raise WorkflowError('closed original State endpoint mismatch')
        if v007 or v008 or v009 or v010 or v011 or v012:
            close=document(proof['close'])['value'];resources=document(proof['resource_close'])
            expected_close={'status':'SAFE_DIAGNOSTIC','run_id':'M5be48f75ab7a4d4c9f24027b37ac3dd1',
                'node':'STAGE_START','activity_in_flight':False,'worker_alive':False,'supervisor_alive':False,
                'writer_held':False,'workers_started':0,'workers_joined':0,'cleanup_proved':True,
                'business_recovery_authorized':False}
            if v008:expected_close.update(run_id='Mf754f1870c7146d29fdce63bab137733',node='FAILED',activity_in_flight=True,workers_started=2,workers_joined=2)
            if v012:expected_close.update(run_id='M4b635edd088942249f54cdce2d7ca4cf',node='HUMAN_BLOCK',activity_in_flight=False,workers_started=6,workers_joined=6)
            if v011:expected_close.update(run_id='Mc044c686e1d84b808a22a812b21fa919',node='FAILED',activity_in_flight=True,workers_started=5,workers_joined=5)
            if v010:expected_close.update(run_id='Mb28b47a97f394410885ddc0985130825',node='FAILED',activity_in_flight=True,workers_started=2,workers_joined=2)
            if v009:expected_close.update(run_id='M5645398edd054c4fb43b8211b1827dcb',node='FAILED',activity_in_flight=True,workers_started=2,workers_joined=2)
            if v012:
                application=document(extra_refs['application_result'])
                if any(application.get(k)!=v for k,v in {'run_id':'M4b635edd088942249f54cdce2d7ca4cf','status':'FAILED_OR_CLEANUP_UNPROVED','exit_code':2,'legal_stop':False,'cleanup_proved':True,'Stage_accepted':False}.items()):raise WorkflowError('exact eighth closed application fact changed')
            job=resources['owned_job_receipt']
            if (any(close.get(k)!=v for k,v in expected_close.items())
                    or any(resources.get(k) is not True for k in ('business_cleanup_proved','reader_threads_joined','pipes_closed','process_handle_closed','cleanup_proved'))
                    or resources.get('unknown_business_side_effects') is not False or resources.get('errors')!=[]
                    or resources.get('child_exit_code')!=0
                    or any(job.get(k) is not True for k in ('root_terminated','tree_terminated_confirmed','job_handle_closed'))
                    or job.get('unknown_side_effect') is not False or job.get('errors')!=[]):
                raise WorkflowError('actual v007 same-run safety/owned resource close unproved')
            directory=Path(segment['plan']['path']).parent/'run-v001'
            if (Path(proof['close']['path'])!=directory/'actual-close-response.json'
                    or Path(proof['resource_close']['path'])!=directory/'actual-resource-close.json'):
                raise WorkflowError('closed v007 same-run close endpoint mismatch')
        else:
            close=document(proof['close']);health=close['resource_health']
            if (close.get('run_id')!='M64d1bb20bbc54c91ac17bab0c90e0a78' or close.get('phase')!='CLOSED'
                    or health.get('status')!='RELEASED' or health.get('reasons')!=[]
                    or any(health.get(k)!=0 for k in ('writer_count','worker_count','supervisor_count','started_workers','joined_workers'))
                    or not health.get('adapters') or not health.get('managed_backends')):
                raise WorkflowError('actual closed Host resources unproved')
            for a in health['adapters']:
                if (a.get('status')!='RELEASED' or a.get('closed') is not True or a.get('connected') is not False
                        or any(a.get(k)!=0 for k in ('live_contexts','owned_process_count','alive_process_count','live_tool_runtimes'))):
                    raise WorkflowError('closed adapter resources unproved')
                for r in a['process_receipts']:
                    t=r['termination']
                    if (r.get('released') is not True or r.get('process_handle_closed') is not True
                            or any(t.get(k) is not True for k in ('root_terminated','tree_terminated_confirmed','job_handle_closed'))
                            or t.get('unknown_side_effect') is not False or t.get('errors')!=[]
                            or not all(r['pipes_closed']) or r.get('readers_alive')!=0 or r.get('writers_alive')!=0):
                        raise WorkflowError('closed owned process receipt unproved')
            for b in health['managed_backends']:
                if b.get('closed') is not True or b.get('running') is not False or b.get('owned_resources')!=0 or b.get('last_receipt') is not None:raise WorkflowError('closed Native resources unproved')
        for ref in [segment[k] for k in ('owner','grant','activation','plan','native','bindings','roles')]+list(proof.values()):pinned(ref)
        for r in extra_refs.values():pinned(r)
        return owner

    def _segment(self,segment,*,frozen,initializing=False):
        from .managed_native import ManagedNativeHost
        keys={'grant','activation','plan','native','bindings','roles','task_windows'}
        closed=frozen and 'closed_unused' in segment
        if closed:
            keys|={'owner','closed_unused'}
            if self.pool.get('purpose') not in ('ACTUAL_V007_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):raise WorkflowError('closed segment requires exact v007')
        if set(segment)!=keys:raise WorkflowError('complete consumption segment required')
        closed_owner=self._closed_unused(segment) if closed else None
        if frozen:
            grant=document(segment['grant']);plan=document(segment['plan']);activation=document(segment['activation'])
            native=pinned(segment['native']);roles=pinned(segment['roles']);bound=pinned(segment['bindings'])
            if bound!=Path(str(native)+'.tasks.jsonl'):raise WorkflowError('Task binding source endpoint mismatch')
            grant_sha=segment['grant']['sha256'];plan_sha=segment['plan']['sha256']
        else:
            if not initializing:self._anchor()
            read_live=lambda ref:document(ref) if isinstance(ref,dict) else json.loads(Path(ref).read_bytes(),object_pairs_hook=unique_json_object)
            grant=read_live(segment['grant']);activation=read_live(segment['activation']);plan=read_live(segment['plan'])
            native=Path(segment['native']);roles=Path(segment['roles'])
            if segment['bindings']!=str(native)+'.tasks.jsonl':raise WorkflowError('current binding endpoint mismatch')
            grant_path=segment['grant']['path'] if isinstance(segment['grant'],dict) else segment['grant']
            plan_path=segment['plan']['path'] if isinstance(segment['plan'],dict) else segment['plan']
            grant_sha=digest(grant_path);plan_sha=digest(plan_path)
        if (workspace_identity(grant['workspace'])!=self.workspace or
                activation.get('grant_sha256')!=grant_sha or activation.get('startup_plan_sha256')!=plan_sha or
                set(segment['task_windows'])!=set(grant['requests']) or
                any(w not in ('CORE','EXPORT') for w in segment['task_windows'].values()) or
                plan.get('workspace')!=grant['workspace'] or
                plan.get('templates')!=grant['requests'] or
                grant.get('dispatch_limit')!=3 or grant.get('cost_units_limit')!=3 or
                grant.get('cost_units_per_dispatch')!=1):
            raise WorkflowError('segment Grant/Plan/Activation/window identity mismatch')
        pool=closed_owner or (self.original_pool if frozen else self.pool)
        if (activation.get('approved_at')!=pool['approved_at'] or activation.get('expires_at')!=pool['expires_at']
                or grant.get('expires_at')!=pool['expires_at']):
            raise WorkflowError('segment original window changed')
        bindings=ManagedNativeHost._task_bindings(grant,grant_sha,native)
        _,entries=ManagedNativeHost._budget_entries(grant,grant_sha,native,bindings)
        if len(entries)>3 or len(entries)*grant['cost_units_per_dispatch']>grant['cost_units_limit']:
            raise WorkflowError('source native pool already exceeded')
        counts={'roles':0,'native':len(entries),'CORE_roles':0,'CORE_native':0,'EXPORT_roles':0,'EXPORT_native':0}
        attempts=[]
        for row in entries:
            task=bindings[row['request_fingerprint']]['task_id']
            counts[segment['task_windows'][task]+'_native']+=1
            if not isinstance(row.get('attempt'),str) or not row['attempt']:raise WorkflowError('native attempt identity absent')
            attempts.append(row['attempt'])
        nonce=activation.get('nonce')
        if not isinstance(nonce,str) or len(nonce)!=64 or set(nonce)-set('0123456789abcdef'):
            raise WorkflowError('actual activation nonce required')
        nonce_sha=hashlib.sha256(nonce.encode()).hexdigest()
        fifth=closed and closed_owner.get('purpose')=='ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL'
        rows=[json.loads(line,object_pairs_hook=unique_json_object) for line in roles.read_bytes().splitlines()] if roles.exists() else []
        for index,row in enumerate(rows):
            if (set(row)!={'ordinal','bucket','plan_sha256','nonce_sha256','activity','synthetic'}
                    or type(row['ordinal']) is not int or row['ordinal']!=index+1+(1 if fifth else 0)
                    or row['plan_sha256']!=plan_sha or row['nonce_sha256']!=nonce_sha or row['synthetic'] is not False
                    or row['bucket'] not in {'STAGE',*segment['task_windows']}):
                raise WorkflowError('role consumption Plan/nonce/ordinal identity mismatch')
            counts['roles']+=1
            if row['bucket']!='STAGE':counts[segment['task_windows'][row['bucket']]+'_roles']+=1
        if closed:
            expected_counts=dict.fromkeys(counts,0)
            if closed_owner.get('purpose') in ('ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL'):
                expected_counts['roles']=1
                if len(rows)!=1 or rows[0]['bucket']!='STAGE' or rows[0]['activity']!='STAGE_REVIEW':raise WorkflowError('exact v008 stage consumption required')
            if closed_owner.get('purpose')=='ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL':
                expected_counts.update(roles=4,CORE_roles=1)
                if [(r['bucket'],r['activity']) for r in rows]!=[('STAGE','STAGE_REVIEW'),('STAGE','STAGE_PLANNING'),('STAGE','STAGE_PLAN_DECISION'),(private_value('forward', 'value_21'),'TASK_SELECTION')]:raise WorkflowError('exact seventh activity/bucket consumption required')
            if closed_owner.get('purpose')=='ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL':
                expected_counts.update(roles=5,CORE_roles=2)
                if [(r['bucket'],r['activity']) for r in rows]!=[('STAGE','STAGE_REVIEW'),('STAGE','STAGE_PLANNING'),('STAGE','STAGE_PLAN_DECISION'),(private_value('forward', 'value_22'),'TASK_SELECTION'),(private_value('forward', 'value_23'),'DECISION_MEDIATION')]:raise WorkflowError('exact eighth activity/bucket consumption required')
            if counts!=expected_counts:raise WorkflowError('closed exact segment consumption changed')
        return counts,attempts,grant_sha,str(native.resolve()),str(roles.resolve())

    def snapshot(self,*,include_current=False):
        if document(self.reference)!=self.spec:raise WorkflowError('consumption chain changed during session')
        if document(self.spec['pool_owner'])!=self.pool:raise WorkflowError('consumption pool Owner changed during session')
        if not isinstance(self.spec['segments'],list) or not self.spec['segments']:
            raise WorkflowError('required failed predecessor consumption absent')
        totals=dict.fromkeys(('roles','native','CORE_roles','CORE_native','EXPORT_roles','EXPORT_native'),0)
        seen=set();previous=None;attempts=set();nonces=set()
        for ordinal,item in enumerate(self.spec['segments'],1):
            if set(item)!={'ordinal','previous_sha256','segment'} or item['ordinal']!=ordinal or item['previous_sha256']!=previous:
                raise WorkflowError('missing/noncontinuous consumption predecessor')
            if self.pool.get('purpose') in ('ACTUAL_V007_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):
                if ('closed_unused' in item['segment'])!=(ordinal>=2):raise WorkflowError('exact paid then closed-unused order required')
                if ordinal>=2:
                    from .successor import V006_OWNER_SHA256,V007_OWNER_SHA256,V008_OWNER_SHA256,V009_OWNER_SHA256,V010_OWNER_SHA256,V011_OWNER_SHA256,V012_OWNER_SHA256,V013_OWNER_SHA256
                    if item['segment']['owner']['sha256']!={2:V006_OWNER_SHA256,3:V007_OWNER_SHA256,4:V008_OWNER_SHA256,5:V009_OWNER_SHA256,6:V010_OWNER_SHA256,7:V011_OWNER_SHA256,8:V012_OWNER_SHA256,9:V013_OWNER_SHA256}[ordinal]:
                        raise WorkflowError('exact v006 then v007 closed order required')
            counts,ids,grant,native,roles=self._segment(item['segment'],frozen=True)
            nonce=document(item['segment']['activation'])['nonce']
            if nonce in nonces:raise WorkflowError('duplicate activation nonce')
            nonces.add(nonce)
            for identity in (grant,native,roles):
                if identity in seen:raise WorkflowError('duplicate consumption source')
                seen.add(identity)
            for identity in ids:
                if identity in attempts:raise WorkflowError('duplicate Native attempt')
                attempts.add(identity)
            for key in totals:totals[key]+=counts[key]
            previous=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        current=self.spec['current']
        # Successor endpoints may not alias an immutable source, even before files exist.
        for key in ('native','roles'):
            if str(Path(current[key]).resolve()) in seen:raise WorkflowError('successor reuses frozen endpoint')
        if include_current:
            counts,ids,grant,native,roles=self._segment(current,frozen=False)
            if self._read_current_activation()['nonce'] in nonces:raise WorkflowError('reused successor activation nonce')
            if grant in seen or attempts.intersection(ids):raise WorkflowError('reused successor Grant/attempt')
            for key in totals:totals[key]+=counts[key]
        limits=self.limits
        if any(totals[k]>limit for k,limit in limits.items()):raise WorkflowError('cumulative original pool/window exceeded')
        return totals

    def before_native(self,grant,grant_sha256,ledger,task):
        current=self.spec['current']
        grant_path=current['grant']['path'] if isinstance(current['grant'],dict) else current['grant']
        if (digest(grant_path)!=grant_sha256 or json.loads(Path(grant_path).read_bytes(),object_pairs_hook=unique_json_object)!=grant or
                Path(current['native']).resolve()!=Path(ledger).resolve() or task not in current['task_windows']):
            raise WorkflowError('new Grant is not authenticated successor')
        used=self.snapshot(include_current=True);window=current['task_windows'][task]
        if used['native']>=self.limits['native'] or used[window+'_native']>=self.limits[window+'_native']:
            raise WorkflowError('cumulative Native/window exhausted before resource')

    def current_role_count(self):
        """Authenticated segment-local count, independent of frozen pool totals."""
        self.snapshot(include_current=True)
        return self._segment(self.spec['current'],frozen=False)[0]['roles']

    def before_role(self,task):
        used=self.snapshot(include_current=True)
        window='STAGE' if task=='STAGE' else self.spec['current']['task_windows'].get(task)
        if window is None or used['roles']>=self.limits['roles'] or window!='STAGE' and used[window+'_roles']>=self.limits[window+'_roles']:
            raise WorkflowError('cumulative role/window exhausted before call')
        return used


def git_identity(workspace):
    def run(*args):
        result=subprocess.run(['git','-C',str(workspace),*args],capture_output=True,check=True,timeout=15)
        return result.stdout
    return {'head':run('rev-parse','HEAD').decode().strip(),
            'index_sha256':hashlib.sha256(run('ls-files','--stage','-z')).hexdigest(),
            'staged_diff_sha256':hashlib.sha256(run('diff','--cached','--binary')).hexdigest(),
            'worktree_status_sha256':hashlib.sha256(run('status','--porcelain=v1','-z','--untracked-files=all')).hexdigest()}


class ForwardBasis:
    """Pinned read-only gate. Success is necessary, never Owner/Safety/Writer/Grant creation."""
    def __init__(self,reference):
        self.reference=reference;self.spec=document(reference)

    def readiness(self,*,now=None,writer_lease=None,history_source=None,history_consumer=None):
        s=document(self.reference)
        if s!=self.spec or s.get('purpose')!='EXPLICIT_FAILED_SOURCE_FORWARD_BASIS_V1':
            raise WorkflowError('explicit immutable forward basis required')
        original=document(s['original_owner']);approval=document(s['repair_owner'])
        if (original.get('approved') is not True or approval.get('approved') is not True
                or approval.get('purpose')!='ACTUAL_OWNER_APPROVED_MINIMAL_FORWARD_FAILURE_RECOVERY_CONTRACT'
                or approval.get('original_owner')!=s['original_owner']
                or approval.get('original_window')!={k:original[k] for k in ('approved_at','expires_at')}
                or approval.get('additional_product_budget') is not False or approval.get('new_time_window') is not False
                or approval.get('restore_closed_proof') is not False or original.get('caps')!={'roles':35,'native':3}):
            raise WorkflowError('explicit repair scope and original fixed authority mismatch')
        pinned(approval['approved_scope_report']);pinned(s['final'])
        workspace=workspace_identity(s['workspace']);root=Path(s['root']).resolve(strict=True)
        if (workspace!=workspace_identity(original['scope']['workspace']) or Path(workspace).parent!=root
                or Path(s['working']).parent.resolve()!=root or Path(s['working']).resolve()==Path(s['failed_working']).resolve()
                or Path(s['working']).exists()):
            raise WorkflowError('new explicit sibling working required; no old State reuse')
        failed=document(s['failed_state'])
        if (failed.get('current_node')!='FAILED' or failed.get('task_id')!=s['failed_task']
                or failed.get('in_flight_activity')!='EXECUTOR_IMPLEMENT' or failed.get('latest_execution_report_ref') is not None):
            raise WorkflowError('actual immutable failed source mismatch')
        cleanup=cleanup_projection(pinned(s['close_receipt']),s['failed_run'])
        if cleanup!=document(s['cleanup']):raise WorkflowError('cleanup projection differs from original receipt')
        if cleanup!={'run_id':s['failed_run'],'closed':True,'workers_started':9,'workers_joined':9,
                     'writer_count':0,'worker_count':0,'supervisor_count':0,'lease_released':True,
                     'endpoint_removed':True,'native_cleanup_proved':True,'usage':'UNKNOWN'}:
            raise WorkflowError('complete trusted failure cleanup evidence required')
        # Cleanup evidence must be pinned to the actual original close receipt, never a caller flag.
        pinned(s['close_receipt']);pinned(s['effects_audit'])
        expected_sources={str((SOURCE_ROOT/rel).resolve()) for rel in source_files()}
        if {str(Path(row['path']).resolve()) for row in s['source_pins']}!=expected_sources or len(s['source_pins'])!=len(expected_sources):
            raise WorkflowError('complete exact current production source closure required')
        for row in s['source_pins']:pinned(row)
        if not s.get('protected_inputs'):raise WorkflowError('protected policy/test/role/route inputs required')
        for row in s['protected_inputs']:pinned(row)
        for rel,expected in s['effects'].items():
            path=Path(workspace)/rel
            if path.resolve().parent!= (Path(workspace)/'ledger').resolve() or digest(path)!=expected:
                raise WorkflowError('actual source side effects drifted')
        if git_identity(workspace)!=s['git']:raise WorkflowError('workspace HEAD/index drifted')
        _check_namespace(Path(s['working']))
        retained=_LEASES.get(workspace)
        if retained is not None and retained is not writer_lease:raise WorkflowError('concurrent Writer blocks forward basis')
        if writer_lease is not None and (retained is not writer_lease or not writer_lease.held or writer_lease.workspace!=workspace):
            raise WorkflowError('original retained canonical Writer required')
        chain=ConsumptionChain(s['consumption_chain'])
        if chain.spec['pool_owner']!=s['original_owner']:raise WorkflowError('consumption chain belongs to different pool')
        used=chain.snapshot()
        if used!={'roles':7,'native':1,'CORE_roles':4,'CORE_native':1,'EXPORT_roles':0,'EXPORT_native':0}:
            raise WorkflowError('exact failed predecessor consumption must be retained')
        tasks=s['task_windows']
        if chain.spec['current']['task_windows']!=tasks or sorted(tasks.values())!=['CORE','EXPORT']:
            raise WorkflowError('explicit successor logical windows required')
        if 'independent_minimum_count' in s:
            minimum=document(s['independent_minimum_count'])
            if minimum.get('minimum_count')!={'entry_roles':3,'CORE_roles':7,'EXPORT_roles':7,'stage_tail_roles':12,'roles':29,'Native':2}:
                raise WorkflowError('original full chain count mismatch')
        estimate=s['estimate']
        expected_keys={'roles','native','role_seconds','native_timeout_seconds','tests_git_stage_seconds','work_floor_seconds','review_seconds','acceptance_seconds'}
        if (set(estimate)!=expected_keys or any(type(v) is not int or v<0 for v in estimate.values())
                or estimate['native_timeout_seconds']!=900 or estimate['role_seconds']<120
                or estimate['work_floor_seconds']<7200 or estimate['review_seconds']!=1800
                or estimate['acceptance_seconds']!=3600 or estimate['tests_git_stage_seconds']<2100):
            raise WorkflowError('complete 900s forward time estimate required')
        # Original normal route: Stage entry3 + CORE7 + EXPORT7 + Stage tail12
        # (including final selection and all four separate memory calls) =29.
        if estimate['roles']<29 or estimate['native']<2:raise WorkflowError('full normal chain minimum omitted')
        approved,expires=stamp(original['approved_at']),stamp(original['expires_at'])
        if (expires-approved).total_seconds()!=21600:raise WorkflowError('original six-hour pair changed')
        now=now or datetime.now(timezone.utc)
        if not isinstance(now,datetime) or now.tzinfo is None:raise WorkflowError('aware current UTC required')
        work=max(estimate['work_floor_seconds'],estimate['roles']*estimate['role_seconds']+
                 estimate['native']*900+estimate['tests_git_stage_seconds'])
        required=work+1800+3600
        if not approved<=now<expires or (expires-now).total_seconds()<required:
            raise WorkflowError('INSUFFICIENT_FULL_CHAIN_TIME')
        if estimate['roles']>35-used['roles'] or estimate['native']>3-used['native']:
            raise WorkflowError('INSUFFICIENT_FULL_CHAIN_BUDGET')
        # Host supplies an actual configured AllowanceHistorySource consumer, not numeric caller claims.
        from loommode.workflow.allowance_history import AllowanceHistorySource
        if type(history_source) is not AllowanceHistorySource or history_consumer is None:
            raise WorkflowError('verified typed history consumer required')
        snapshot=history_source.snapshot(history_consumer)
        floor=snapshot['used_lower_bounds']
        typed={k:floor[k] for k in ('implementation','repair','decision_flow')}
        typed['next_implementation_ordinal']=floor['implementation']+1
        if typed!={'implementation':5,'repair':1,'decision_flow':0,'next_implementation_ordinal':6}:
            raise WorkflowError('actual stopped typed history mismatch')
        return {'status':'READ_ONLY_BASIS_VERIFIED_NOT_ACTIVATED','used':used,'required_seconds':required,
                'typed':typed,'native_timeout_seconds':900,'usage':'UNKNOWN'}

def cleanup_projection(path,run_id):
    """Local whitelist consumer of original close evidence; never returns receipt/body/proof."""
    rows=[json.loads(line,object_pairs_hook=unique_json_object) for line in Path(path).read_bytes().splitlines()]
    matches=[row for row in rows if row.get('status')=='ORIGINAL_CLOSE_RETURNED' and row.get('run_id')==run_id]
    if len(matches)!=1:raise WorkflowError('unique actual close receipt required')
    row=matches[0];resources=row['resources'];backends=row['backends']
    native=bool(backends)
    for backend in backends:
        health=backend['health'];receipt=backend['receipt'];cleanup=receipt['cleanup']
        native=native and health.get('closed') is True and health.get('running') is False and receipt.get('working_files_removed') is True
        native=native and all(cleanup.get(k) is True for k in ('root_terminated','tree_terminated_confirmed','job_handle_closed','io_threads_joined','pipes_closed','process_handle_closed'))
        native=native and cleanup.get('unknown_side_effect') is False and cleanup.get('errors')==[]
    return {'run_id':run_id,'closed':row.get('phase')=='CLOSED',
            'workers_started':resources.get('started_workers'),'workers_joined':resources.get('joined_workers'),
            'writer_count':resources.get('writer_count'),'worker_count':resources.get('worker_count'),
            'supervisor_count':resources.get('supervisor_count'),
            'lease_released':row.get('canonical_lease')=='RELEASED' and row.get('workspace_lease',{}).get('held') is False,
            'endpoint_removed':row.get('endpoint_exists') is False,'native_cleanup_proved':bool(native),'usage':'UNKNOWN'}