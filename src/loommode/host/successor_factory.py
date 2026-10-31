"""A6 normal canonical/Engine/role/Native assembly and explicit A-side activation."""
from pathlib import Path
from datetime import datetime,timezone
from dataclasses import asdict
import hashlib,json,os,secrets
from .successor import (wire,hashed,reference,validate_owner,readiness,runtime_authorities,history_sources,
    history_probe,apply_typed_capacity,SuccessorNativeHost,LiveWindowBudget)
from .forward import document,pinned,digest,ConsumptionChain
from .managed_native import task_template_sha256,runtime_plan_sha256
from loommode.workflow.errors import WorkflowError


from .private_instance import private_value, require_private_instance

def policy(plan,task=None,*,stage=False):
    from loommode.tools.runtime import ToolPolicy,ToolProfile
    from loommode.tools.test_runner import TestSpec
    row=plan['policies']['STAGE' if stage else task]
    tests=tuple(TestSpec(**{**x,'argv':tuple(x['argv'])}) for x in row['tests'])
    return ToolPolicy(Path(plan['workspace']),ToolProfile.BOUNDED_DEVELOPMENT,tuple(row['readable_paths']),tuple(row['writable_paths']),tuple(row['stageable_paths']),tests,tuple(row['commit_messages']))


def templates(plan):
    from loommode.workflow.implementation import ImplementationConfig,ImplementationRequest
    config=ImplementationConfig.from_mapping(plan['implementation'])
    values={}
    for task in plan['tasks']:
        request=ImplementationRequest.create(config,policy(plan,task),{'project':plan['project'],'stage_id':plan['stage'],'task_id':task,'intent_ref':'NOT_YET_ROLE_GENERATED','final_ref':'NOT_YET_ROLE_GENERATED','scope':list(policy(plan,task).writable_paths)},'TEMPLATE ONLY: original normal Promoter Intent required.','TEMPLATE ONLY: original normal Constraint Final must bind native_timeout_seconds=900.')
        values[task]={'template_sha256':task_template_sha256(request),'predecessor_task_id':None if task==plan['tasks'][0] else plan['tasks'][0]}
    return values


def capability_plans(plan):
    """HEAD-compatible pure launch capability identity; no historical helper required."""
    from loommode.workflow.implementation import ImplementationConfig,ImplementationRequest
    from loommode.workflow.managed_cli import native_launch_plan
    config=ImplementationConfig.from_mapping(plan['implementation']);work=Path(plan['working']);result={}
    for task in plan['tasks']:
        pol=policy(plan,task)
        request=ImplementationRequest.create(config,pol,{'project':plan['project'],'stage_id':plan['stage'],'task_id':task,'intent_ref':'NOT_YET_ROLE_GENERATED','final_ref':'NOT_YET_ROLE_GENERATED','scope':list(pol.writable_paths)},'TEMPLATE ONLY','TEMPLATE ONLY')
        launch=native_launch_plan(request,work/'ATTEMPT/schema.json',work/'ATTEMPT/result.json')
        result[task]=hashed({'template_sha256':task_template_sha256(request),'working_root':str(work),'argv':launch.argv,'environment':launch.environment})
    return result


def scope(plan):
    return {'origin':'OWNER_SCOPE_GRANT','scope':'EXPLICIT_BOUNDED_SCOPE','scope_id':private_value('successor_factory', 'value_0'),'project':plan['project'],'workspace':plan['workspace'],'major_phase':private_value('successor_factory', 'value_1'),'stage_ids':[plan['stage']],'series_ids':[],'task_ids':plan['tasks'],'relationships':{}}


def role_bucket(engine,plan):
    from loommode.workflow.transitions import Node,TASK_REQUIRED_NODES
    node=Node(engine.state.current_node);core,export=plan['tasks']
    if node==Node.DECISION_MEDIATION:
        if not engine.state.decision_handoff_ref:raise WorkflowError('actual typed mediation source absent')
        node=Node(engine.artifacts.read_json(engine.state.decision_handoff_ref)['origin_activity'])
    if node==Node.TASK_SELECTION:return 'STAGE' if export in engine.state.task_checkpoint_refs else export if core in engine.state.task_checkpoint_refs else core
    if node in TASK_REQUIRED_NODES:
        if engine.state.task_id not in plan['tasks']:raise WorkflowError('role Task outside exact successor')
        return engine.state.task_id
    return 'STAGE'


def reserve_role(engine,plan,chain,lease):
    bucket=role_bucket(engine,plan);used=chain.before_role(bucket)
    activation=document(reference(Path(plan['authority_paths']['activation'])))
    current=chain.spec['current'];row={'ordinal':chain.current_role_count()+1,'bucket':bucket,'plan_sha256':digest(current['plan'] if isinstance(current['plan'],str) else current['plan']['path']),
        'nonce_sha256':hashlib.sha256(activation['nonce'].encode()).hexdigest(),'activity':engine.state.current_node,'synthetic':False}
    chain.append_current('roles',(wire(row)+'\n').encode(),writer_lease=lease)
    return row


def install_guards(engine,adapter,native,plan_ref,lease,*,guard=None):
    p=document(plan_ref);chain=ConsumptionChain(p['consumption_chain'])
    if guard is None and (type(native.live_budget) is not LiveWindowBudget or native.live_budget.engine is not engine):raise WorkflowError('same live Engine Timer required for all guards')
    check=guard if guard is not None else lambda:runtime_authorities(plan_ref,writer_lease=lease,live=True,live_budget=native.live_budget)
    original=adapter.run_turn
    def role_turn(*args,**kwargs):
        check();reserve_role(engine,p,chain,lease)
        return original(*args,**kwargs)
    adapter.run_turn=role_turn
    step=engine.step
    def advance(**kwargs):
        check();core,export=p['tasks'];used=chain.snapshot(include_current=True)
        if (engine.state.task_id==export and engine.state.current_node=='EXECUTOR_IMPLEMENT') or (engine.state.current_node=='TASK_SELECTION' and core in engine.state.task_checkpoint_refs and export not in engine.state.task_checkpoint_refs):
            if core not in engine.state.task_checkpoint_refs:raise WorkflowError('EXPORT requires original same-live CORE checkpoint')
            if chain.limits['roles']-used['roles']<19 and engine.state.current_node=='TASK_SELECTION':raise WorkflowError('EXPORT complete seven+tail12 budget unavailable')
        if engine.state.current_node=='EXECUTOR_IMPLEMENT':
            if 'native_timeout_seconds=900' not in engine.artifacts.read(engine.state.formal_constraint_ref):raise WorkflowError('actual new Constraint Final must explicitly bind native_timeout_seconds=900')
            if engine.state.task_id==core:apply_typed_capacity(engine,p)
            elif engine.state.task_id!=export:raise WorkflowError('unknown successor implementation Task')
            native.bind_actual_task(engine)
        return step(**kwargs)
    engine.step=advance


def objective_review_materials(executor,state,materials,*,allowed=()):
    """Actual live proof ownership and final-generation tests; only allowed fresh inputs."""
    task=state['task_id'] if isinstance(state,dict) else state.task_id
    if not executor.managed_task(task):return materials
    session=executor._managed_session
    if not session or task not in session.tasks:raise WorkflowError('fresh review needs original live managed proof')
    request,proof=session.tasks[task]
    if executor.task_requests.get(task)!=request or executor._managed_proofs.get(proof.context_ref) is not proof:raise WorkflowError('fresh managed proof ownership mismatch')
    facts=executor.managed_test_evidence(task)
    proof.verify_managed_tests(request,session.generations[task],session.implementation_receipts.get(task),facts,require_passed=False)
    if not facts or 'next-boundary' not in facts['required_test_ids']:raise WorkflowError('actual final-generation fixed Boundary required')
    keys=set(allowed)
    keys.update(state[k] for k in ('formal_task_intent_ref','formal_constraint_ref') if state.get(k))
    safe={k:v for k,v in materials.items() if k in keys}
    tests={name:{'result':{k:row['result'].get(k) for k in ('passed','exit_code','timed_out','truncated','termination')}} for name,row in facts['tests'].items()}
    safe['HOST_MANAGED_FIXED_TESTS']=wire({k:facts[k] for k in ('origin','generation','request_fingerprint','required_test_ids','source_before','source_after')}|{'tests':tests})
    return safe



def _bind_candidate_roles(roles,project_root):
    """Trusted factory wiring: recheck the same candidate before every prompt path."""
    from .materials import candidate_role_inputs
    from loommode.workflow.transitions import Role
    invoke,correct,explain=roles.invoke,roles.correct_report,roles.explain_status
    def merge(role,materials):
        bound=candidate_role_inputs(role.value,project_root)
        if bound is None:raise WorkflowError('candidate role binding disappeared')
        fixed=bound['materials']
        if any(k in materials and materials[k]!=v for k,v in fixed.items()):
            raise WorkflowError('bound role material collision')
        return {**materials,**fixed}
    def bound_invoke(role,node,state,materials,override=None):
        return invoke(role,node,state,merge(role,materials),override)
    def bound_correct(role,node,state,materials,override=None):
        return correct(role,node,state,merge(role,materials),override)
    def bound_explain(*,question,projection,materials):
        return explain(question=question,projection=projection,materials=merge(Role.DECISION,materials))
    roles.invoke,roles.correct_report,roles.explain_status=bound_invoke,bound_correct,bound_explain


def assemble_authority(plan,plan_ref=None):
    """Pure trusted assembly, before any work directory, chain or Adapter exists."""
    from .materials import LocalMaterials,SIX_FORMALS
    owner,_=validate_owner(plan['actual_owner'])
    if owner.get('purpose') not in ('ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL'):
        return {'owner':pinned(plan['actual_owner']).read_text(encoding='utf8'),'bounded-scope':wire(scope(plan)),
            'a6-runtime-contract':wire({'original_owner':plan['actual_owner'],'plan':plan_ref,plan['tasks'][0]:'normal original Intent/Final required; actual Final must include native_timeout_seconds=900',plan['tasks'][1]:'same live accepted/checkpointed '+plan['tasks'][0]+' Report dependency; all Stage windows and Owner Gate required'}),
            **{r['key']:pinned({'path':r['path'],'sha256':r['sha256']}).read_text(encoding='utf-8-sig') for r in plan['governance']}}
    if owner['six_formal_material_contract_approved']['entries']!=SIX_FORMALS:raise WorkflowError('exact approved six formal identities required')
    rows=plan['governance'];keys=[r['key'] for r in rows]
    if len(set(keys))!=len(keys):raise WorkflowError('duplicate governance key')
    local=LocalMaterials(plan['root'],plan['material_mapping'],allowed_mapping_sha256=plan['material_mapping']['sha256'])
    values={};provenance=[]
    for entry in SIX_FORMALS:
        key=entry['governance_opaque_key'];ref={'path':entry['path'],'sha256':entry['raw_sha256']}
        expected={'key':key,**ref,'classification':entry['classification'],'actual_original_formal_ref':entry['actual_original_formal_ref'],'expected_Engine_text_domain':entry['expected_Engine_text_domain']}
        if [r for r in rows if r['key']==key]!=[expected]:raise WorkflowError('complete exact governance formal row required')
        if plan['protected_inputs'].count(ref)!=1 or plan['additional_controls'].count({**ref,'kind':'control'})!=1:raise WorkflowError('exact protected/additional formal identity required')
        if key in plan.get('fresh_material_keys',()):raise WorkflowError('historical procedural body cannot widen objective fresh inputs')
        target=local.resolve(ref['path'],ref['sha256']);raw=target.read_bytes()
        # The source-map remains the original identity even when a trusted local control supplies bytes.
        if len(raw)!=entry['raw_bytes'] or hashlib.sha256(raw).hexdigest()!=entry['raw_sha256']:raise WorkflowError('full original formal raw identity required')
        text=target.read_text(encoding='utf-8-sig');domain=entry['expected_Engine_text_domain']
        if hashlib.sha256(text.encode('utf8')).hexdigest()!=domain['utf8_sha256'] or len(text.encode('utf8'))!=domain['utf8_bytes'] or len(text)!=domain['chars']:raise WorkflowError('full original Engine text identity required')
        if target.read_bytes()!=raw:raise WorkflowError('formal changed during assembly')
        values[key]=text;provenance.append({'key':key,'classification':entry['classification'],'actual_original_formal_ref':entry['actual_original_formal_ref'],'usage':'HISTORICAL_EVIDENCE_ONLY','not_current_authority':True})
    authority={'owner':pinned(plan['actual_owner']).read_text(encoding='utf8'),'bounded-scope':wire(scope(plan)),
        'a6-runtime-contract':wire({'original_owner':plan['actual_owner'],'plan':plan_ref,plan['tasks'][0]:'normal original Intent/Final required; actual Final must include native_timeout_seconds=900',plan['tasks'][1]:'same live accepted/checkpointed '+plan['tasks'][0]+' Report dependency; all Stage windows and Owner Gate required'})}
    for r in rows:
        key=r['key']
        if (key in authority and key!='a6-runtime-contract') or key=='historical-formal-source-map':raise WorkflowError('governance authority collision')
        authority[key]=values[key] if key in values else pinned({'path':r['path'],'sha256':r['sha256']}).read_text(encoding='utf-8-sig')
    authority['historical-formal-source-map']=wire(provenance)
    if 'historical-formal-source-map' in plan.get('fresh_material_keys',()):raise WorkflowError('historical metadata cannot widen objective inputs')
    return authority


def create_host(plan_ref,*,canonical_context,dependencies=None):
    """Normal factory, no unconditional rejection and no historical Native locations."""
    preflight_plan=document(plan_ref)
    authority=assemble_authority(preflight_plan,plan_ref)
    p,a,_=runtime_authorities(plan_ref,writer_lease=canonical_context.writer_lease)
    if p!=preflight_plan:raise WorkflowError('Plan changed after material preflight')
    if p['templates']!=templates(p) or p['capability_plans']!=capability_plans(p):raise WorkflowError('actual template/capability closure mismatch')
    if dependencies is None:
        from loommode.codex.adapter import ThinCodexAdapter,AdapterConfig
        from loommode.codex.app_server import BinaryPolicy
        deps={'adapter':lambda:ThinCodexAdapter.from_binary(binary_policy=BinaryPolicy(Path(p['role_route']['binary']),('0.160.1',)),process_cwd=Path(p['workspace']),allowed_workspace_roots=(Path(p['workspace']),),config=AdapterConfig(default_turn_deadline_seconds=120))}
    else:
        # Not selectable by Plan/CLI. Only isolated tests provide no-model constructors.
        deps=dependencies
        if not deps.get('isolated_fixture_root') or not Path(p['working']).resolve().is_relative_to(Path(deps['isolated_fixture_root']).resolve()):raise WorkflowError('injected dependencies require explicit isolated fixture boundary')
    from loommode.workflow.state import StateStore,WorkflowState
    from loommode.workflow.artifacts import ArtifactStore
    from loommode.workflow.engine import WorkflowEngine
    from loommode.workflow.executor import ExecutorRuntime
    from loommode.workflow.implementation import ImplementationConfig
    from loommode.workflow.managed_cli import CliLimits
    from loommode.roles.runtime import RoleRuntime,current_verified_profiles
    from loommode.workflow.transitions import Role
    from loommode.tools.runtime import ToolPolicy,ToolProfile
    from loommode.host import DecisionEntry,DecisionHost,StateProjection,SupervisorHost
    from loommode.host.implementation import ManagedHostPreflight,HostAuthorityProof
    workspace=Path(p['workspace']);work=Path(p['working']);lease=canonical_context.writer_lease
    # Resource-free admission above; retained Writer is checked again before mutation.
    work.mkdir()  # Exactly one fresh directory, no exist_ok/restart.
    chain=ConsumptionChain(p['consumption_chain']);chain.initialize_current(writer_lease=lease)
    adapter=None
    try:
        adapter=deps['adapter']()
        if hasattr(adapter,'client'):
            adapter.client.command=(p['role_route']['binary'],*p['role_route']['arguments'],'app-server','--stdio')
            adapter.client.environment={k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA') if k in os.environ}
        stage_policy=policy(p,stage=True);profiles=current_verified_profiles()
        executor=ExecutorRuntime(adapter,stage_policy,{t:policy(p,t) for t in p['tasks']},profiles,objective_review_materials=lambda executor,state,materials:objective_review_materials(executor,state,materials,allowed=p.get('fresh_material_keys',())))
        review=ToolPolicy(workspace,ToolProfile.READ_ONLY_REVIEW,stage_policy.readable_paths)
        from .materials import candidate_role_inputs
        bound=candidate_role_inputs('Decision',p['root'])
        role_files={Role(r['role']):pinned({'path':r['path'],'sha256':r['sha256']}) for r in p['roles']}
        if bound is not None and any(role_files[Role(name)].resolve()!=path.resolve() for name,path in bound['role_files'].items()):
            raise WorkflowError('candidate Plan roles must match payload official role identities')
        roles=RoleRuntime(adapter,role_files,review,profiles,p['stage'])
        if bound is not None:_bind_candidate_roles(roles,p['root'])
        # Reuse the exact verified complete bodies from resource-free admission.
        if bound is not None:
            authority.update({k:v for k,v in bound['materials'].items() if k.startswith('official-policy:') or k.startswith('project-overlay:authority:') or k.startswith('project-overlay:mapping:')})
        sources=history_sources(p)
        engine=WorkflowEngine(WorkflowState(p['project'],p['stage']),StateStore(work/'state',p['project'],p['stage']),ArtifactStore(work/'artifacts',p['project'],p['stage']),roles,executor,authority,stage_authorization_ref='owner',scope_grant_refs=('bounded-scope',),local_commit_authorized=True,allowance_history_sources=sources)
        history_probe(p,sources,authority['owner'])
        entry=DecisionEntry(StateProjection(project=p['project'],stage_id=p['stage'],workspace=workspace,artifacts=engine.artifacts,registry=adapter.registry,state_provider=lambda:engine.state,source_ref='A6 explicit new single successor',authority_materials=authority,is_busy=lambda:engine._busy),roles)
        host=canonical_context.register_host(SupervisorHost(DecisionHost(entry,engine,allow_progress=True,allow_owner_events=True)))
        native=SuccessorNativeHost(lease,plan_ref,live_budget=LiveWindowBudget(host.host))
        limits=CliLimits(**p['limits'])
        def lookup(request,capability):
            admission=native.check(request,work,limits);used=chain.snapshot(include_current=True)
            return HostAuthorityProof(capability,request.fingerprint,'A6_GRANT#'+admission.grant_sha256,datetime.fromisoformat(a['grant']['expires_at'].replace('Z','+00:00')),4-used['native'],4-used['native'],'OWNER_APPROVED_DISPATCH_UNIT',900)
        def typed_reserve(request,attempt):
            for r in reversed(engine.state.artifact_refs.get('HOST_ALLOWANCE_CONSUMPTION',[])):
                row=engine.artifacts.read_json(r)
                if row.get('kind')=='implementation' and row.get('task_id')==request.binding['task_id'] and row.get('source')=={'intent_ref':request.binding['intent_ref'],'final_ref':request.binding['final_ref']}:return r
            raise WorkflowError('durable real Engine implementation ordinal required before Native')
        executor.implementation_config=ImplementationConfig.from_mapping(p['implementation'])
        executor.managed_backend.host_preflight=ManagedHostPreflight(lookup,native._writer)
        executor.bind_managed_cli(work,typed_reserve,limits=limits,native_host=native)
        host.host._managed_native=native
        install_guards(engine,adapter,native,plan_ref,lease)
        adapter.connect()
        return host
    except BaseException:
        if canonical_context.host is None and adapter is not None:adapter.close()
        raise


def activation_payloads(plan_ref,*,writer_lease=None):
    """A calls after actual independent Safety/Writer records; pure technical derivation."""
    from loommode.workflow.implementation import ImplementationConfig
    from loommode.workflow.managed_cli import PARENT_HTTP_ROUTE
    p=document(plan_ref);readiness(plan_ref,writer_lease=writer_lease);owner,_=validate_owner(p['actual_owner'])
    safety=document(reference(Path(p['authority_paths']['safety'])));writer=document(reference(Path(p['authority_paths']['writer'])))
    if safety.get('verdict')!='BOUNDED_VALIDATION_ALLOWED' or safety.get('plan_sha256')!=plan_ref['sha256'] or safety.get('owner_sha256')!=p['actual_owner']['sha256'] or safety.get('sources')!=p['sources'] or not safety.get('independent_context_ref') or safety.get('reviewer_role')!='Decision' or safety.get('purpose')!='A6_INDEPENDENT_SUCCESSOR_SAFETY' or safety.get('native_timeout_seconds')!=900 or safety.get('capability_plans')!=p['capability_plans']:raise WorkflowError('actual independent Safety required before activation derivation')
    for key in ('code_review','tool_probe'):pinned(safety[key])
    if writer.get('purpose')!='A6_TRUSTED_FRESH_WRITER_ADMISSION' or writer.get('plan_sha256')!=plan_ref['sha256'] or writer.get('owner_sha256')!=p['actual_owner']['sha256'] or writer.get('safety_sha256')!=digest(p['authority_paths']['safety']) or writer.get('workspace')!=p['workspace'] or writer.get('working')!=p['working'] or writer.get('released') is not True or writer.get('fresh_store') is not True:raise WorkflowError('actual fresh Writer admission required')
    config=ImplementationConfig.from_mapping(p['implementation']).managed
    grant={'purpose':'A6_BOUNDED_SUCCESSOR_NATIVE_RUN','owner_authorized':True,'requests':p['templates'],'request_binding_mode':'ENGINE_SAVED_TASK_V1','endpoint':config.endpoint,'credential_file':config.credential_file,'credential_env':config.credential_env,'expires_at':owner['expires_at'],'workspace':p['workspace'],'working_root':p['working'],'source_sha256':p['sources'],'binary_sha256':p['native_binary_sha256'],'dispatch_limit':3,'cost_units_per_dispatch':1,'cost_units_limit':3,'currency':'OWNER_APPROVED_DISPATCH_UNIT','timeout_seconds':900,'cleanup_seconds':p['limits']['cleanup_seconds'],'io_limits':{k:p['limits'][k] for k in ('stdin_bytes','stream_bytes','result_bytes')},'parent_http_route':PARENT_HTTP_ROUTE,'safety_sha256':digest(p['authority_paths']['safety']),'host_configuration_sha256':plan_ref['sha256'],'accepted_native_sha256':digest(p['authority_paths']['safety'])}
    native_owner={'purpose':'A6_DERIVED_NATIVE_OWNER_AUTHORIZATION','actual_owner':p['actual_owner'],'runtime_plan_sha256':runtime_plan_sha256(grant),'capabilities':['model_api','credential_read','mxc_exec','provider_budget']}
    owner_hash=hashlib.sha256((wire(native_owner)+'\n').encode()).hexdigest()
    grant['runtime_authorities']={k:{'file':p['authority_paths']['native_owner'],'sha256':owner_hash} for k in native_owner['capabilities']}
    activation={'nonce':secrets.token_hex(32),'startup_plan_sha256':plan_ref['sha256'],'owner_sha256':p['actual_owner']['sha256'],'safety_sha256':digest(p['authority_paths']['safety']),'writer_sha256':digest(p['authority_paths']['writer']),'grant_sha256':hashlib.sha256((wire(grant)+'\n').encode()).hexdigest(),'approved_at':owner['approved_at'],'expires_at':owner['expires_at']}
    return {'native_owner':native_owner,'grant':grant,'activation':activation}


def activate(plan_ref):
    """Explicit normal A-side command; never invoked by source Task/test outside fixtures."""
    from .ownership import WorkspaceLease
    p=document(plan_ref);lease=WorkspaceLease(p['workspace'])
    if not lease.acquire():raise WorkflowError('parallel Writer blocks activation')
    try:
        # Static readiness knows this exact retained Writer; no business working is created.
        readiness(plan_ref,writer_lease=lease)
        # activation_payloads uses the same protected source checks without acquiring resources.
        # Its readiness must admit this existing lease, rather than ignore concurrency.
        payload=activation_payloads(plan_ref,writer_lease=lease)
        if any(Path(p['authority_paths'][k]).exists() for k in payload):raise WorkflowError('one create-only activation; never overwrite/retry')
        for k,value in payload.items():
            with Path(p['authority_paths'][k]).open('xb') as f:f.write((wire(value)+'\n').encode());f.flush();os.fsync(f.fileno())
        runtime_authorities(plan_ref,writer_lease=lease)
        return {'status':'ACTUAL_A_AUTHORITY_ACTIVATED_NOT_LAUNCHED','product_calls':0}
    finally:lease.release()
