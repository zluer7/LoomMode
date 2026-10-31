"""A6 explicit single successor. New eligibility, never old proof recovery."""
import hashlib
import importlib.util
import json
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
from dataclasses import asdict
from .forward import document,pinned,digest,stamp,ConsumptionChain,source_files,SOURCE_ROOT,git_identity,cleanup_projection
from .materials import material_path
from .ownership import workspace_identity,_LEASES,_check_namespace
from .managed_native import ManagedNativeHost,_Admission,task_template_sha256,control_sha256,runtime_plan_sha256,_RESERVATIONS,BINARY_SHA256
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object


from .private_instance import private_value, require_private_instance

def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def hashed(value):return hashlib.sha256(wire(value).encode()).hexdigest()
def reference(path):return {'path':str(path),'sha256':digest(path)}

V014_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V014_QUOTE = None  # Requires explicit pinned private bootstrap.
V013_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V012_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V011_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V010_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V009_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V008_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V007_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V006_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.
V005_OWNER_SHA256 = None  # Requires explicit pinned private bootstrap.


def validate_owner(ref):
    owner=document(ref)
    if owner.get('purpose')=='ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v014_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v013_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v012_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v011_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v010_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v009_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v008_owner(ref,owner)
    if owner.get('purpose')=='ACTUAL_V007_SINGLE_SUCCESSOR_OWNER_APPROVAL':return _validate_v007_owner(ref,owner)
    if owner.get('purpose')!='ACTUAL_V006_SINGLE_SUCCESSOR_OWNER_APPROVAL':
        return _validate_v005_owner(ref)
    # Narrow support for this exact real approval, never a caller-created pool.
    if ref['sha256']!=V006_OWNER_SHA256:raise WorkflowError('exact actual v006 Owner required')
    previous,original=_validate_v005_owner(owner['previous_actual_owner'])
    for key,expected in (('approved_request',private_value('successor', 'value_22')),
                         ('approved_proposal',private_value('successor', 'value_23'))):
        if owner[key]['sha256']!=expected:raise WorkflowError('exact v006 request/proposal required')
        pinned(owner[key])
    if (owner.get('approved') is not True
            or owner['previous_actual_owner']['sha256']!=V005_OWNER_SHA256
            or owner['original_owner']!=previous['original_owner']
            or owner.get('previous_UTC_preserved')!=[previous['approved_at'],previous['expires_at']]
            or owner.get('original_UTC_preserved')!=[original['approved_at'],original['expires_at']]
            or [owner.get(k) for k in ('approved_at','expires_at')]!=[private_value('successor', 'value_98'),private_value('successor', 'value_99')]
            or owner.get('actual_owner_quote')!='产品额度净增 0，未用 35 roles／3 Native 仅承接至唯一后继；新共享六小时；组织净增 2 次，加原未用 1 次，共最多 3 次、每次最多 900 秒'
            or owner.get('net_new')!={'roles':0,'native':0}
            or owner.get('previous_v005_net_new_relative_v004')!=previous['net_new']
            or owner.get('v005_segment_product_used')!={'roles':0,'native':0}
            or owner.get('carry_unspent_to_only_successor')!=previous['future_available']
            or owner.get('no_parallel_prior_pool') is not True
            or owner.get('v006_typed_net_delta')!={'implementation':0,'repair':0}
            or owner.get('typed')!=previous['typed']
            or any(owner.get(k)!=previous[k] for k in ('caps','future_available','original_used_preserved',
                'CORE_cumulative_cap','CORE_used_preserved','EXPORT_cumulative_cap','new_working_name'))):
        raise WorkflowError('v006 lineage/net-zero/single successor mismatch')
    return owner,original



def _validate_v014_owner(ref,owner):
    if ref['sha256']!=V014_OWNER_SHA256:raise WorkflowError('exact actual v014 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_24')),('approved_proposal',private_value('successor', 'value_25')),('independent_request_check',private_value('successor', 'value_26'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact v014 approved inputs required')
        pinned(owner[key])
    proposal=document(owner['approved_proposal'])
    expected={'approved':True,'actual_owner_quote':V014_QUOTE,'approved_at':private_value('successor', 'value_51'),'expires_at':private_value('successor', 'value_52'),'new_working_name':private_value('successor', 'value_53'),'net_new':{'roles':0,'native':0},'carry_unspent_to_only_successor':{'roles':29,'native':3},'closed_v013_segment_product_used':[0,0],'required_initial_full_chain_seconds':13980,'required_before_organization_start_seconds':15150,'typed':{**previous['typed'],'v014_net_delta':[0,0]},'approved_source_task':private_value('successor', 'value_11'),'approved_intent_draft':proposal['intent_draft'],'preserve_closed_working_names':[*previous['preserve_closed_working_names'],private_value('successor', 'value_80')],'previous_windows_preserved':{**previous['previous_windows_preserved'],'v013':[previous['approved_at'],previous['expires_at']]},'ninth_initialized_boot_stop_history_approved':{**proposal['ninth_initialized_boot_stop_history'],'purpose':'FROZEN_REFERENCE_SET_NOT_AN_ENGINE_CONSUMPTION_CHAIN','ordinal_requested':9},'startup_budget_approved':{'READY_seconds':330,'original_READY_seconds':30,'explicit_added_seconds':300,'initial_required_seconds':13980,'before_B18_required_seconds':15150,'prior13680_floor_preserved':True,'overhead2100_review1800_acceptance3600_unchanged':True,'success_guaranteed':False,'old_inner_cause':'UNKNOWN'}}
    common=('caps','preserved_used','future_available','CORE_used_preserved','CORE_cumulative_cap','EXPORT_cumulative_cap','EXPORT_used_preserved','fees','no_parallel_prior_pool','fifth_fixed_history_exception_approved','sixth_normal_closed_history_approved','seventh_normal_closed_history_approved','eighth_normal_closed_history_approved','six_formal_material_contract_approved','approved_business_wording_clarification','all_history_preserved','all_history_max','C2_history_preserved','C2_max','older_frozen_unused_not_released')
    org={**previous['organization_CLI'],'previous_cap':17,'previous_consumed':17,'future_ordinals':[18],'lineage_cumulative_max_launches':18,'no_ordinal19':True};org.pop('no_ordinal18')
    if owner['previous_actual_owner']['sha256']!=V013_OWNER_SHA256 or any(owner.get(k)!=v for k,v in expected.items()) or any(owner.get(k)!=previous[k] for k in common) or owner.get('organization_CLI')!=org:raise WorkflowError('v014 exact successor contract mismatch')
    pinned(owner['approved_intent_draft']);pinned(owner['approved_business_wording_clarification'])
    return owner,original


def require_full_chain_time(owner,required,*,now=None):
    now=now or datetime.now(timezone.utc)
    if now.tzinfo is None or not stamp(owner['approved_at'])<=now<stamp(owner['expires_at']) or (stamp(owner['expires_at'])-now).total_seconds()<required:
        raise WorkflowError('INSUFFICIENT_SUCCESSOR_FULL_CHAIN_TIME')


def startup_budget(owner):
    # Metadata only: no stdout, no READY frame, no old-cause inference.
    if owner.get('purpose')=='ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL':
        return {'READY_seconds':330,'added_initial_seconds':300,'initial_seconds':13980,'before_organization_seconds':15150,'old_inner_cause':'UNKNOWN'}
    return {'READY_seconds':30,'added_initial_seconds':0,'initial_seconds':13680,'before_organization_seconds':14850,'old_inner_cause':'UNKNOWN'}

def _validate_v013_owner(ref,owner):
    if ref['sha256']!=V013_OWNER_SHA256:raise WorkflowError('exact actual v013 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_27')),('approved_proposal',private_value('successor', 'value_28')),('independent_request_check',private_value('successor', 'value_29'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact v013 request/proposal/check required')
        pinned(owner[key])
    proposal=document(owner['approved_proposal'])
    expected={'approved':True,'actual_owner_quote':private_value('successor', 'value_54'),'approved_at':private_value('successor', 'value_55'),'expires_at':private_value('successor', 'value_56'),'new_working_name':private_value('successor', 'value_57'),
        'preserved_used':{'roles':19,'native':1},'future_available':{'roles':29,'native':3},'net_new':{'roles':5,'native':0},'caps':{'roles':48,'native':4},'CORE_used_preserved':[7,1],'carry_unspent_to_only_successor':{'roles':24,'native':3},'closed_v012_segment_product_used':[5,0],
        'preserve_closed_working_names':[*previous['preserve_closed_working_names'],private_value('successor', 'value_81')],
        'required_initial_full_chain_seconds':13680,'required_before_organization_start_seconds':14850,
        'typed':{**previous['typed'],'v013_net_delta':[0,0]},'fifth_fixed_history_exception_approved':previous['fifth_fixed_history_exception_approved'],
        'sixth_normal_closed_history_approved':previous['sixth_normal_closed_history_approved'],'seventh_normal_closed_history_approved':previous['seventh_normal_closed_history_approved'],'eighth_normal_closed_history_approved':proposal['eighth_frozen_history'],'six_formal_material_contract_approved':proposal['six_formal_material_contract'],'approved_source_task':private_value('successor', 'value_12'),'approved_intent_draft':{'path':private_value('successor', 'value_82'),'sha256':private_value('successor', 'value_30')},'approved_business_wording_clarification':{'path':private_value('successor', 'value_83'),'sha256':private_value('successor', 'value_31')},
        'previous_windows_preserved':{**previous['previous_windows_preserved'],'v012':[previous['approved_at'],previous['expires_at']]}}
    org={'previous_cap':16,'previous_consumed':16,'unused_carried':0,'net_new_launches':1,'future_max_launches':1,'future_ordinals':[17],'lineage_cumulative_max_launches':17,'max_seconds_each':900,'durable_reserve_before_launch':True,'failed_timeout_reportonly_consumed_no_refund':True,'same_shared_window':True,'separate_from_product_pool':True,'no_ordinal18':True}
    common=('no_parallel_prior_pool','v005_segment_product_used','closed_v006_segment_product_used','closed_v007_segment_product_used','closed_v008_segment_product_used','closed_v009_segment_product_used','CORE_cumulative_cap','EXPORT_cumulative_cap','EXPORT_used_preserved','fees','real_paid_dispatch_eligible_now')
    if (owner['previous_actual_owner']['sha256']!=V012_OWNER_SHA256 or previous['purpose']!='ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL' or any(owner.get(k)!=v for k,v in expected.items()) or any(owner.get(k)!=previous[k] for k in common) or owner.get('organization_CLI')!=org):raise WorkflowError('v013 exact lineage/window/quote/net/typed/single successor mismatch')
    pinned(owner['approved_intent_draft']);pinned(owner['approved_business_wording_clarification'])
    return owner,original


def _validate_v012_owner(ref,owner):
    if ref['sha256']!=V012_OWNER_SHA256:raise WorkflowError('exact actual v012 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_32')),('approved_proposal',private_value('successor', 'value_33')),('independent_request_check',private_value('successor', 'value_34'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact v012 request/proposal/check required')
        pinned(owner[key])
    proposal=document(owner['approved_proposal'])
    expected={'approved':True,'actual_owner_quote':private_value('successor', 'value_58'),'approved_at':private_value('successor', 'value_59'),'expires_at':private_value('successor', 'value_60'),'new_working_name':private_value('successor', 'value_61'),
        'preserved_used':{'roles':14,'native':1},'future_available':{'roles':29,'native':3},'net_new':{'roles':1,'native':0},'caps':{'roles':43,'native':4},'CORE_used_preserved':[5,1],'carry_unspent_to_only_successor':{'roles':28,'native':3},'closed_v011_segment_product_used':[4,0],
        'preserve_closed_working_names':[*previous['preserve_closed_working_names'],private_value('successor', 'value_84')],
        'required_initial_full_chain_seconds':13680,'required_before_organization_start_seconds':14850,
        'typed':{**previous['typed'],'v012_net_delta':[0,0]},'fifth_fixed_history_exception_approved':previous['fifth_fixed_history_exception_approved'],
        'sixth_normal_closed_history_approved':previous['sixth_normal_closed_history_approved'],'seventh_normal_closed_history_approved':proposal['seventh_frozen_history'],
        'previous_windows_preserved':{**previous['previous_windows_preserved'],'v011':[previous['approved_at'],previous['expires_at']]}}
    org={'previous_cap':15,'previous_consumed':15,'unused_carried':0,'net_new_launches':1,'future_max_launches':1,'future_ordinals':[16],'lineage_cumulative_max_launches':16,'max_seconds_each':900,'durable_reserve_before_launch':True,'failed_timeout_reportonly_consumed_no_refund':True,'same_shared_window':True,'separate_from_product_pool':True,'no_ordinal17':True}
    common=('no_parallel_prior_pool','v005_segment_product_used','closed_v006_segment_product_used','closed_v007_segment_product_used','closed_v008_segment_product_used','closed_v009_segment_product_used','CORE_cumulative_cap','EXPORT_cumulative_cap','EXPORT_used_preserved','fees','real_paid_dispatch_eligible_now')
    if (owner['previous_actual_owner']['sha256']!=V011_OWNER_SHA256 or previous['purpose']!='ACTUAL_V011_SINGLE_SUCCESSOR_OWNER_APPROVAL' or any(owner.get(k)!=v for k,v in expected.items()) or any(owner.get(k)!=previous[k] for k in common) or owner.get('organization_CLI')!=org):raise WorkflowError('v012 exact lineage/window/quote/net/typed/single successor mismatch')
    return owner,original


def _validate_v011_owner(ref,owner):
    if ref['sha256']!=V011_OWNER_SHA256:raise WorkflowError('exact actual v011 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_35')),('approved_proposal',private_value('successor', 'value_36')),('independent_request_check',private_value('successor', 'value_37'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact v011 request/proposal/check required')
        pinned(owner[key])
    proposal=document(owner['approved_proposal'])
    expected={'approved':True,'actual_owner_quote':private_value('successor', 'value_62'),'approved_at':private_value('successor', 'value_63'),'expires_at':private_value('successor', 'value_64'),'new_working_name':private_value('successor', 'value_65'),
        'preserved_used':{'roles':10,'native':1},'future_available':{'roles':32,'native':3},'carry_unspent_to_only_successor':{'roles':32,'native':3},'closed_v010_segment_product_used':[1,0],
        'preserve_closed_working_names':[*previous['preserve_closed_working_names'],private_value('successor', 'value_85')],
        'required_initial_full_chain_seconds':14040,'required_before_organization_start_seconds':15210,
        'typed':{**previous['typed'],'v011_net_delta':[0,0]},'fifth_fixed_history_exception_approved':previous['fifth_fixed_history_exception_approved'],
        'sixth_normal_closed_history_approved':proposal['sixth_frozen_history'],
        'previous_windows_preserved':{**previous['previous_windows_preserved'],'v010':[previous['approved_at'],previous['expires_at']]}}
    org={'previous_cap':14,'previous_consumed':14,'unused_carried':0,'net_new_launches':1,'future_max_launches':1,'future_ordinals':[15],'lineage_cumulative_max_launches':15,'max_seconds_each':900,'durable_reserve_before_launch':True,'failed_timeout_reportonly_consumed_no_refund':True,'same_shared_window':True,'separate_from_product_pool':True,'no_ordinal16':True}
    common=('net_new','caps','no_parallel_prior_pool','v005_segment_product_used','closed_v006_segment_product_used','closed_v007_segment_product_used','closed_v008_segment_product_used','closed_v009_segment_product_used','CORE_cumulative_cap','CORE_used_preserved','EXPORT_cumulative_cap','EXPORT_used_preserved','fees','real_paid_dispatch_eligible_now')
    if (owner['previous_actual_owner']['sha256']!=V010_OWNER_SHA256 or previous['purpose']!='ACTUAL_V010_SINGLE_SUCCESSOR_OWNER_APPROVAL' or any(owner.get(k)!=v for k,v in expected.items()) or any(owner.get(k)!=previous[k] for k in common) or owner.get('organization_CLI')!=org):raise WorkflowError('v011 exact lineage/window/quote/net/typed/single successor mismatch')
    return owner,original


def _validate_v010_owner(ref,owner):
    if ref['sha256']!=V010_OWNER_SHA256:raise WorkflowError('exact actual v010 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_38')),
                  ('approved_proposal',private_value('successor', 'value_39')),
                  ('independent_request_check',private_value('successor', 'value_40'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact v010 request/proposal/check required')
        pinned(owner[key])
    proposal=document(owner['approved_proposal'])
    expected={'approved':True,'actual_owner_quote':private_value('successor', 'value_66'),'approved_at':private_value('successor', 'value_67'),
        'expires_at':private_value('successor', 'value_68'),'new_working_name':private_value('successor', 'value_69'),
        'preserved_used':{'roles':9,'native':1},'future_available':{'roles':33,'native':3},
        'carry_unspent_to_only_successor':{'roles':33,'native':3},'closed_v009_segment_product_used':[1,0],
        'preserve_closed_working_names':[private_value('successor', 'value_86'),private_value('successor', 'value_87'),private_value('successor', 'value_88'),private_value('successor', 'value_89')],
        'required_initial_full_chain_seconds':14160,'typed':{**previous['typed'],'v010_net_delta':[0,0]},
        'fees':previous['fees'],'conservative_accounting_current_old_consumer_authenticates':False,
        'previous_windows_preserved':{**previous['previous_windows_preserved'],'v009':[previous['approved_at'],previous['expires_at']]},
        'fifth_fixed_history_exception_approved':{**proposal['fifth_frozen_history'],
            'only_one_spent_reservation':True,'original_raw_must_not_change':True,
            'arbitrary_bad_history_allowed':False,'new_current_validation_unchanged':True}}
    common=('net_new','caps','no_parallel_prior_pool','v005_segment_product_used','closed_v006_segment_product_used',
        'closed_v007_segment_product_used','closed_v008_segment_product_used','CORE_cumulative_cap','CORE_used_preserved',
        'EXPORT_cumulative_cap','EXPORT_used_preserved','real_paid_dispatch_eligible_now')
    org=owner.get('organization_CLI',{})
    if (owner['previous_actual_owner']['sha256']!=V009_OWNER_SHA256
            or previous.get('purpose')!='ACTUAL_V009_SINGLE_SUCCESSOR_OWNER_APPROVAL'
            or any(owner.get(k)!=v for k,v in expected.items()) or any(owner.get(k)!=previous[k] for k in common)
            or org!={'previous_cap':13,'previous_consumed':13,'unused_carried':0,'net_new_launches':1,
                'future_max_launches':1,'future_ordinals':[14],'lineage_cumulative_max_launches':14,'max_seconds_each':900,
                'durable_reserve_before_launch':True,'failed_timeout_reportonly_consumed_no_refund':True,
                'same_shared_window':True,'separate_from_product_pool':True,'no_ordinal15':True}):
        raise WorkflowError('v010 exact identity/lineage/window/net-zero/typed/single replacement mismatch')
    return owner,original


def _validate_v009_owner(ref,owner):
    if ref['sha256']!=V009_OWNER_SHA256:raise WorkflowError('exact actual v009 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_41')),
                  ('approved_proposal',private_value('successor', 'value_42')),
                  ('independent_request_check',private_value('successor', 'value_43'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact approved v009 request/proposal/check required')
        pinned(owner[key])
    expected={'approved':True,'actual_owner_quote':'批准','approved_at':private_value('successor', 'value_70'),
        'expires_at':private_value('successor', 'value_71'),'new_working_name':private_value('successor', 'value_72'),
        'preserved_used':{'roles':8,'native':1},'future_available':{'roles':34,'native':3},
        'carry_unspent_to_only_successor':{'roles':34,'native':3},'closed_v008_segment_product_used':[1,0],
        'preserve_closed_working_names':[private_value('successor', 'value_90'),private_value('successor', 'value_91'),private_value('successor', 'value_92')],
        'required_initial_full_chain_seconds':14280,
        'typed':{**previous['typed'],'v009_net_delta':[0,0]},
        'previous_windows_preserved':{**previous['previous_windows_preserved'],'v008':[previous['approved_at'],previous['expires_at']]}}
    common=('net_new','caps','no_parallel_prior_pool','v005_segment_product_used',
        'closed_v006_segment_product_used','closed_v007_segment_product_used','CORE_cumulative_cap',
        'CORE_used_preserved','EXPORT_cumulative_cap','EXPORT_used_preserved','real_paid_dispatch_eligible_now')
    if (owner['previous_actual_owner']['sha256']!=V008_OWNER_SHA256
            or previous.get('purpose')!='ACTUAL_V008_SINGLE_SUCCESSOR_OWNER_APPROVAL'
            or any(owner.get(k)!=v for k,v in expected.items())
            or any(owner.get(k)!=previous[k] for k in common)):
        raise WorkflowError('v009 exact identity/lineage/window/net-zero/single replacement mismatch')
    return owner,original


def _validate_v008_owner(ref,owner):
    if ref['sha256']!=V008_OWNER_SHA256:raise WorkflowError('exact actual v008 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_44')),
                  ('approved_proposal',private_value('successor', 'value_45')),
                  ('independent_request_check',private_value('successor', 'value_46'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact approved v008 request/proposal/check required')
        pinned(owner[key])
    typed={k:v for k,v in previous['typed'].items() if k!='v007_net_delta'}
    typed['v008_net_delta']=[0,0]
    windows={**previous['previous_windows_preserved'],'v007':[previous['approved_at'],previous['expires_at']]}
    expected={'approved':True,'approved_at':private_value('successor', 'value_73'),'expires_at':private_value('successor', 'value_74'),
        'actual_owner_quote':'产品与组织净增均 0，承接未用 35 roles／3 Native、唯一剩余组织调用（≤900 秒），批准唯一替换后继及新共享六小时',
        'new_working_name':private_value('successor', 'value_75'),'preserve_closed_working_names':[private_value('successor', 'value_93'),private_value('successor', 'value_94')],
        'closed_v007_segment_product_used':[0,0],'typed':typed,'previous_windows_preserved':windows}
    common=('net_new','caps','preserved_used','future_available','carry_unspent_to_only_successor',
        'no_parallel_prior_pool','v005_segment_product_used','closed_v006_segment_product_used',
        'CORE_cumulative_cap','CORE_used_preserved','EXPORT_cumulative_cap','EXPORT_used_preserved',
        'required_initial_full_chain_seconds','real_paid_dispatch_eligible_now')
    if (owner['previous_actual_owner']['sha256']!=V007_OWNER_SHA256
            or previous.get('purpose')!='ACTUAL_V007_SINGLE_SUCCESSOR_OWNER_APPROVAL'
            or any(owner.get(k)!=v for k,v in expected.items())
            or any(owner.get(k)!=previous[k] for k in common)):
        raise WorkflowError('v008 exact identity/lineage/window/net-zero/single replacement mismatch')
    return owner,original


def _validate_v007_owner(ref,owner):
    if ref['sha256']!=V007_OWNER_SHA256:raise WorkflowError('exact actual v007 Owner required')
    previous,original=validate_owner(owner['previous_actual_owner'])
    for key,h in (('approved_request',private_value('successor', 'value_47')),
                  ('approved_proposal',private_value('successor', 'value_48'))):
        if owner[key]['sha256']!=h:raise WorkflowError('exact approved v007 request/proposal required')
        pinned(owner[key])
    expected={'approved':True,'approved_at':private_value('successor', 'value_76'),'expires_at':private_value('successor', 'value_77'),
        'actual_owner_quote':private_value('successor', 'value_13'),
        'net_new':{'roles':0,'native':0},'caps':{'roles':42,'native':4},'preserved_used':{'roles':7,'native':1},
        'future_available':{'roles':35,'native':3},'carry_unspent_to_only_successor':{'roles':35,'native':3},
        'no_parallel_prior_pool':True,'v005_segment_product_used':[0,0],'closed_v006_segment_product_used':[0,0],
        'CORE_cumulative_cap':[18,3],'CORE_used_preserved':[4,1],'EXPORT_cumulative_cap':[13,1],
        'EXPORT_used_preserved':[0,0],'new_working_name':private_value('successor', 'value_78'),'preserve_closed_working_name':private_value('successor', 'value_79'),
        'required_initial_full_chain_seconds':14400,'real_paid_dispatch_eligible_now':False}
    typed={'family':private_value('successor', 'value_14'),'preserved_used':[5,1,0],'target_cumulative_capacity':[7,2],
        'v007_net_delta':[0,0],'v005_original_net_delta_counted_once':[1,0],
        'new_recipient_baseline_capacity':[3,1],'one_time_local_derived_additional_capacity':[4,1],
        'next_real_implementation_ordinal':6}
    windows={'v004':[original['approved_at'],original['expires_at']],
        'v005':[private_value('successor', 'value_95'),private_value('successor', 'value_96')],
        'v006':[previous['approved_at'],previous['expires_at']]}
    if (owner['previous_actual_owner']['sha256']!=V006_OWNER_SHA256
            or previous.get('purpose')!='ACTUAL_V006_SINGLE_SUCCESSOR_OWNER_APPROVAL'
            or owner.get('previous_windows_preserved')!=windows or owner.get('typed')!=typed
            or any(owner.get(k)!=v for k,v in expected.items())):
        raise WorkflowError('v007 exact lineage/window/net-zero/typed/single successor mismatch')
    return owner,original


def _validate_v005_owner(ref):
    owner=document(ref)
    original=document(owner['original_owner'])
    for key in ('approved_request','approved_proposal'):pinned(owner[key])
    if (owner.get('purpose')!='ACTUAL_V005_SINGLE_SUCCESSOR_OWNER_APPROVAL' or owner.get('approved') is not True
        or owner.get('actual_owner_quote')!='\u6279\u51c6\u63a5\u7eed\u7533\u8bf7 v005 \u5168\u90e8\u8303\u56f4\u3001\u8d39\u7528\u9014\u5f84\u4e0e\u65b0\u540e\u7ee7\u5171\u4eab\u516d\u5c0f\u65f6\u3002'
        or owner.get('caps')!={'roles':42,'native':4} or owner.get('net_new')!={'roles':7,'native':1}
        or owner.get('future_available')!={'roles':35,'native':3}
        or owner.get('original_used_preserved')!={'roles':7,'native':1}
        or owner.get('carry_original_unspent_to_only_successor')!={'roles':28,'native':2}
        or owner.get('CORE_cumulative_cap')!={'roles':18,'native':3}
        or owner.get('CORE_used_preserved')!={'roles':4,'native':1}
        or owner.get('EXPORT_cumulative_cap')!={'roles':13,'native':1}
        or owner.get('original_UTC_preserved')!=[original['approved_at'],original['expires_at']]
        or original.get('approved') is not True or original.get('caps')!={'roles':35,'native':3}
        or owner.get('new_working_name')!=private_value('successor', 'value_97')
        or [owner.get(k) for k in ('approved_at','expires_at')]!=[private_value('successor', 'value_100'),private_value('successor', 'value_101')]):
        raise WorkflowError('explicit v005 net/cumulative/single successor authority mismatch')
    typed=owner['typed']
    required={'family':private_value('successor', 'value_15'),'preserved_used':[5,1,0],'preserved_capacity':[6,2],
        'net_new_implementation':1,'net_new_repair':0,'target_cumulative_capacity':[7,2],
        'new_recipient_baseline_capacity':[3,1],'one_time_local_derived_additional_capacity':[4,1],
        'no_double_import_of_old_capacity':True,'next_real_implementation_ordinal':6}
    if typed!=required:raise WorkflowError('explicit typed net/cumulative derivation mismatch')
    return owner,original


def history_factory(plan):
    """Use only pinned old pure functions, never execute a legacy bootstrap.

    Frozen v014/v003 top-level bootstraps import unaccepted Native locations
    and prepend dirty Dev. Their exact history/policy bodies need neither.
    """
    import ast
    from loommode.workflow.allowance_history import AllowanceHistorySource
    from loommode.workflow.state import StateStore
    from loommode.workflow.artifacts import ArtifactStore
    from loommode.tools.runtime import ToolPolicy,ToolProfile
    from loommode.tools.test_runner import TestSpec
    from .managed_native import _regular
    refs=plan['history_inputs']
    files={key:pinned(ref) for key,ref in refs.items()}
    original=ast.parse(files['factory'].read_bytes())
    literals={}
    for node in original.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in {'INPUTS','MODULES'}:
            literals[node.targets[0].id]=ast.literal_eval(node.value)
    if set(literals)!={'INPUTS','MODULES'}:raise WorkflowError('frozen history policy literals missing')
    root=Path(plan['root']);workspace=Path(plan['workspace']);w=pinned(plan['history_factory']).parent
    def selected(tree,names,namespace,path):
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
        if {n.name for n in nodes}!=set(names):raise WorkflowError('frozen pure history functions missing')
        class AuthorityRead(ast.NodeTransformer):
            def visit_Call(self,node):
                self.generic_visit(node)
                if (isinstance(node.func,ast.Attribute) and node.func.attr=='read_text'
                        and isinstance(node.func.value,ast.Call) and isinstance(node.func.value.func,ast.Name)
                        and node.func.value.func.id=='Path' and len(node.func.value.args)==1
                        and isinstance(node.func.value.args[0],ast.Subscript)
                        and isinstance(node.func.value.args[0].slice,ast.Constant)
                        and node.func.value.args[0].slice.value=='authority_path'):
                    node.func.value=ast.Call(func=ast.Name(id='_authority_material',ctx=ast.Load()),args=node.func.value.args,keywords=[])
                return node
        namespace['_authority_material']=material_path
        tree=ast.fix_missing_locations(AuthorityRead().visit(ast.Module(body=nodes,type_ignores=[])))
        exec(compile(tree,str(path),'exec'),namespace)
    old={'Path':Path,'json':json,'unique_json_object':unique_json_object,'_regular':_regular,
        'PROJECT':plan['project'],'STAGE':plan['stage'],'WORKSPACE':workspace,
        'CORE':private_value('successor', 'value_16'),'EXPORT':private_value('successor', 'value_17'),'APPROVAL':files['owner'],**literals}
    selected(original,('data','scope'),old,files['factory'])
    ns={'Path':Path,'json':json,'WorkflowError':WorkflowError,'AllowanceHistorySource':AllowanceHistorySource,
        'StateStore':StateStore,'ArtifactStore':ArtifactStore,'ToolPolicy':ToolPolicy,'ToolProfile':ToolProfile,'TestSpec':TestSpec,
        'ROOT':root,'WORKSPACE':workspace,'W':w,'PROJECT':plan['project'],'STAGE':plan['stage'],
        'CORE':private_value('successor', 'value_18'),'EXPORT':private_value('successor', 'value_19'),'FAMILY':private_value('successor', 'value_20'),
        'HISTORY_PLAN':files['plan'],'OLD':SimpleNamespace(**old)}
    selected(ast.parse(pinned(plan['history_factory']).read_bytes()),
        ('history_sources','scope','capacity_authority','fixed_specs','policy'),ns,pinned(plan['history_factory']))
    return SimpleNamespace(**ns)


def history_sources(plan):
    """Actual HistorySource handles; original state/proofs never escape this consumer."""
    from loommode.workflow.allowance_history import AllowanceHistorySource
    from loommode.workflow.state import StateStore
    from loommode.workflow.artifacts import ArtifactStore
    old=history_factory(plan)
    prior=old.history_sources()
    # Only needed authority identity fields are consumed locally, not returned.
    state=document(plan['failed_state'])
    grant=SimpleNamespace(**state['active_grant'])
    authority={'owner':pinned(plan['old_runtime_owner']).read_text(encoding='utf-8-sig'),
        'bounded-scope':wire(old.scope()),'new-capacity':old.capacity_authority(SimpleNamespace(grant=lambda:grant))}
    authority.update({r['key']:pinned({'path':r['path'],'sha256':r['sha256']}).read_text(encoding='utf-8-sig') for r in document(plan['old_plan'])['governance']})
    failed=Path(plan['failed_working']);project=plan['project'];stage=plan['stage']
    source=AllowanceHistorySource('a6-original-failed-core2',StateStore(failed/'state',project,stage),
        ArtifactStore(failed/'artifacts',project,stage),workspace=Path(plan['workspace']),source_task_id=private_value('successor', 'value_49'),
        recipient_task_id=plan['tasks'][0],recipient_workspace=Path(plan['workspace']),recipient_stage_id=stage,
        family_task_id=private_value('successor', 'value_50'),authority_materials=authority,history_sources={s.name:s for s in prior})
    if source.checkpoint_sha256!=plan['failed_state']['sha256']:raise WorkflowError('failed typed source changed')
    return (source,)


def history_probe(plan,sources,owner_text):
    """An unsaved real Engine reader, no constructor/Store writes or execution state import."""
    from loommode.workflow.engine import WorkflowEngine
    from loommode.workflow.state import StateStore,WorkflowState
    from loommode.workflow.artifacts import ArtifactStore
    from loommode.workflow.governance import ScopeGrant,digest as text_digest
    engine=WorkflowEngine.__new__(WorkflowEngine)
    engine.state=WorkflowState(plan['project'],plan['stage'])
    engine.authority={'owner':owner_text};engine.state.stage_input_ref='owner'
    engine.executor=SimpleNamespace(stage_policy=SimpleNamespace(workspace=Path(plan['workspace'])))
    engine.scope_grants={}
    engine.stage_grant=ScopeGrant('STAGE',plan['stage'],'owner',text_digest(owner_text),plan['project'],plan['workspace'],private_value('successor', 'value_21'),(plan['stage'],))
    engine.state.active_grant=engine.stage_grant.as_dict()
    engine._history_read_only=True;engine._history_workspace=plan['workspace'];engine._allowance_write_failed=False
    engine.history_sources={s.name:s for s in sources}
    engine.store=StateStore(Path(plan['working'])/'state',plan['project'],plan['stage'])
    engine.artifacts=ArtifactStore(Path(plan['working'])/'artifacts',plan['project'],plan['stage'])
    snapshots=[s.snapshot(engine) for s in sources]
    if len(snapshots)!=1 or {k:snapshots[0]['used_lower_bounds'][k] for k in ('implementation','repair','decision_flow')}!={'implementation':5,'repair':1,'decision_flow':0}:
        raise WorkflowError('actual FAILED typed history must preserve5/1/0')
    return {'implementation':5,'repair':1,'decision_flow':0,'next_implementation_ordinal':6}


class LiveWindowBudget:
    """Bound once to the new live Host; credit only its own Timer observations.

    No persisted restart/import or caller elapsed value can create credit. The
    original SoftWindows still owns scheduling, quiescence and durable expiry.
    """
    def __init__(self, host):
        from .driver import DecisionHost
        from .windows import SoftWindows
        from loommode.workflow.engine import WorkflowEngine
        import copy
        if (type(host) is not DecisionHost or type(host.windows) is not SoftWindows
                or type(host.engine) is not WorkflowEngine or host.windows.host is not host
                or host.windows.durations != (1800.0, 3600.0)
                or host.engine.state.soft_window_events or host.windows.applied
                or host.windows.current is not None):
            raise WorkflowError('fresh original production Host Timer required')
        self.host, self.engine, self.windows = host, host.engine, host.windows
        self.stage, self.run, self.epoch = self.engine.state.stage_id, self.windows.run_id, self.windows.epoch
        self._clock = self.windows.clock
        self._armed = None
        self._completed = {}
        arm, consume = self.windows.arm, self.windows.consume
        def observe_arm():
            if self.windows.current is not None and self.windows.current != self._armed:
                raise WorkflowError('unobserved live Timer arm')
            arm()
            event = self.windows.current
            if event is not None:
                if self._armed is not None and self._armed != event:
                    # A new notice must not reuse credit for the prior notice.
                    self._armed = None
                self._armed = copy.deepcopy(event)
        def observe_consume():
            event = copy.deepcopy(self._armed)
            changed = consume()
            if changed:
                if (event is None or event['window_id'] not in self.windows.applied
                        or self._clock() < event['deadline']):
                    raise WorkflowError('unobserved live Timer expiry')
                self._completed[event['window_id']] = {**event,
                    'outcome':'NO_OBJECTION_OBSERVED','owner_accepted':False}
                self._armed = None
            return changed
        self.windows.arm, self.windows.consume = observe_arm, observe_consume

    def remaining(self):
        import math
        from loommode.workflow.transitions import Node
        w, e = self.windows, self.engine
        if (self.host.engine is not e or self.host.windows is not w or w.host is not self.host
                or w.run_id != self.run or w.epoch != self.epoch or e.state.stage_id != self.stage
                or w.durations != (1800.0,3600.0)):
            raise WorkflowError('foreign or obsolete live Timer binding')
        state = e.state
        # Read only this new live Engine checkpoint. Never invoke restart/load.
        saved = json.loads(e.store.path.read_text(encoding='utf-8-sig'),object_pairs_hook=unique_json_object)
        events = state.soft_window_events
        if (saved.get('stage_id') != self.stage or saved.get('soft_window_events') != events
                or len(events) != len(self._completed)
                or any(self._completed.get(x.get('window_id')) != x for x in events)):
            raise WorkflowError('unobserved or unsaved live Timer completion')
        remaining = {'SOFT_REVIEW_WAIT':1800.0,'SOFT_ACCEPTANCE_WAIT':3600.0}
        current_time = self._clock()
        if not math.isfinite(current_time):raise WorkflowError('invalid live Timer clock')
        for event in events:
            node=event['node'];ref=state.stage_notice_ref if node=='SOFT_REVIEW_WAIT' else state.stage_closeout_ref
            if (node not in remaining or event['notice_ref']!=ref or event['run_id']!=self.run
                    or event['stage_epoch']!=self.epoch or event['stage_id']!=self.stage
                    or event['window_id'] not in w.applied or current_time<event['deadline']
                    or event['duration_seconds']!=remaining[node]):
                raise WorkflowError('obsolete or premature live Timer completion')
            e.artifacts.read(ref)
            remaining[node]=0.0
        if w.current is not None:
            event=w.current;node=event['node']
            ref=state.stage_notice_ref if node=='SOFT_REVIEW_WAIT' else state.stage_closeout_ref
            if (self._armed!=event or node!=state.current_node or node not in remaining
                    or event['run_id']!=self.run or event['stage_epoch']!=self.epoch
                    or event['stage_id']!=self.stage or event['notice_ref']!=ref
                    or event['duration_seconds']!=remaining[node]):
                raise WorkflowError('unobserved or obsolete live Timer window')
            e.artifacts.read(ref)
            remaining[node]=max(0.0,min(remaining[node],event['deadline']-current_time))
        return sum(remaining.values())


def readiness(plan_ref,*,now=None,writer_lease=None,live=False,check_typed=True,live_budget=None):
    p=document(plan_ref);owner,original=validate_owner(p['actual_owner'])
    if Path(p.get('source_root','')).resolve()!=SOURCE_ROOT.resolve():raise WorkflowError('exact reviewed runtime source root required')
    workspace=workspace_identity(p['workspace']);work=Path(p['working'])
    if p['purpose']!='A6_SINGLE_ELIGIBLE_SUCCESSOR_PLAN_V1' or workspace!=workspace_identity(original['scope']['workspace']) or work.name!=owner['new_working_name'] or work.parent.resolve()!=Path(workspace).parent:
        raise WorkflowError('single original Root/workspace successor required')
    if not live and work.exists():raise WorkflowError('new successor only; no resume/replay')
    if not live and git_identity(workspace)!=p['git']:raise WorkflowError('initial actual Git four-field identity changed')
    if not live and 'initial_raw_index' in p:pinned(p['initial_raw_index'])
    if not live:
        for rel,h in p['effects'].items():
            if digest(Path(workspace)/rel)!=h:raise WorkflowError('retained business source effect changed')
    if set(p['sources'])!=set(source_files()):raise WorkflowError('complete A6 dynamic source closure required')
    for rel,h in p['sources'].items():
        if digest(SOURCE_ROOT/rel)!=h:raise WorkflowError('A6 source identity changed')
    for row in p['protected_inputs']:pinned(row)
    for row in (p['failed_state'],p['old_plan'],p['old_runtime_owner'],p['history_factory']):pinned(row)
    failed=document(p['failed_state'])
    if failed.get('current_node')!='FAILED' or failed.get('in_flight_activity')!='EXECUTOR_IMPLEMENT' or failed.get('latest_execution_report_ref') is not None:raise WorkflowError('immutable original failed boundary mismatch')
    cleanup=cleanup_projection(pinned(p['close_receipt']),p['failed_run'])
    if cleanup!=document(p['cleanup']) or not cleanup['closed'] or not cleanup['native_cleanup_proved'] or not cleanup['lease_released']:raise WorkflowError('original close cleanup unproved')
    retained=_LEASES.get(workspace)
    if retained is not None and retained is not writer_lease:raise WorkflowError('parallel original/successor Writer refused')
    if writer_lease is not None and (retained is not writer_lease or not writer_lease.held):raise WorkflowError('retained actual Writer required')
    chain=ConsumptionChain(p['consumption_chain'])
    if chain.spec['pool_owner']!=p['actual_owner']:raise WorkflowError('wrong successor pool owner')
    old=chain.snapshot()
    if old!={'roles':owner.get('preserved_used',owner.get('original_used_preserved'))['roles'],'native':1,'CORE_roles':(7 if owner.get('purpose') in ('ACTUAL_V013_SINGLE_SUCCESSOR_OWNER_APPROVAL','ACTUAL_V014_SINGLE_SUCCESSOR_OWNER_APPROVAL') else 5 if owner.get('purpose')=='ACTUAL_V012_SINGLE_SUCCESSOR_OWNER_APPROVAL' else 4),'CORE_native':1,'EXPORT_roles':0,'EXPORT_native':0}:raise WorkflowError('exact original cumulative consumption must be preserved')
    used=chain.snapshot(include_current=True) if live else old
    roles=owner['caps']['roles']-used['roles'];native=3-(used['native']-1)
    if roles<0 or native<0:raise WorkflowError('successor pool exhausted')
    if live_budget is not None and (not live or type(live_budget) is not LiveWindowBudget):raise WorkflowError('original live Timer budget required')
    if live_budget is not None:
        e=live_budget.engine
        if (e.state.project!=p['project'] or e.state.stage_id!=p['stage']
                or workspace_identity(e.executor.stage_policy.workspace)!=workspace
                or e.store.path.resolve()!=(work/'state'/'workflow'/p['project']/p['stage']/'state.json').resolve()):
            raise WorkflowError('foreign live Engine/working Timer budget')
    windows=live_budget.remaining() if live_budget is not None else 5400
    required=roles*120+native*900+2100+windows+startup_budget(owner)['added_initial_seconds']
    require_full_chain_time(owner,required,now=now)
    if p['limits']['timeout_seconds']!=900 or p['templates'].keys()!=chain.spec['current']['task_windows'].keys():raise WorkflowError('new900/Task templates required')
    typed=history_probe(p,history_sources(p),pinned(p['actual_owner']).read_text(encoding='utf8')) if check_typed else None
    return {'status':'READ_ONLY_ELIGIBLE_BASIS_PENDING_FRESH_AUTHORITIES','used':used,'future_remaining':{'roles':roles,'native':native},'required_seconds':required,'typed':typed,'usage':'UNKNOWN'}


def runtime_authorities(plan_ref,*,now=None,writer_lease=None,live=False,live_budget=None):
    p=document(plan_ref);basis=readiness(plan_ref,now=now,writer_lease=writer_lease,live=live,live_budget=live_budget)
    a={k:document(reference(Path(path))) for k,path in p['authority_paths'].items()}
    owner,_=validate_owner(p['actual_owner']);owner_sha=p['actual_owner']['sha256'];plan_sha=plan_ref['sha256']
    safety=a['safety'];writer=a['writer'];grant=a['grant'];activation=a['activation'];native_owner=a['native_owner']
    for key in ('code_review','tool_probe'):pinned(safety[key])
    if (safety.get('purpose')!='A6_INDEPENDENT_SUCCESSOR_SAFETY' or safety.get('verdict')!='BOUNDED_VALIDATION_ALLOWED' or not safety.get('independent_context_ref') or safety.get('reviewer_role')!='Decision' or safety.get('plan_sha256')!=plan_sha or safety.get('owner_sha256')!=owner_sha or safety.get('sources')!=p['sources'] or safety.get('native_timeout_seconds')!=900 or safety.get('capability_plans')!=p['capability_plans']):raise WorkflowError('fresh exact independent Safety required')
    if (writer.get('purpose')!='A6_TRUSTED_FRESH_WRITER_ADMISSION' or writer.get('plan_sha256')!=plan_sha or writer.get('owner_sha256')!=owner_sha or writer.get('safety_sha256')!=digest(p['authority_paths']['safety']) or writer.get('workspace')!=p['workspace'] or writer.get('working')!=p['working'] or writer.get('released') is not True or writer.get('fresh_store') is not True):raise WorkflowError('fresh Writer admission required')
    if (activation.get('startup_plan_sha256')!=plan_sha or activation.get('grant_sha256')!=digest(p['authority_paths']['grant']) or activation.get('owner_sha256')!=owner_sha or activation.get('safety_sha256')!=digest(p['authority_paths']['safety']) or activation.get('writer_sha256')!=digest(p['authority_paths']['writer']) or any(activation.get(k)!=owner[k] for k in ('approved_at','expires_at')) or not isinstance(activation.get('nonce'),str) or len(activation['nonce'])!=64 or set(activation['nonce'])-set('0123456789abcdef')):raise WorkflowError('fresh exact nonce/UTC/Activation required')
    if (grant.get('purpose')!='A6_BOUNDED_SUCCESSOR_NATIVE_RUN' or grant.get('owner_authorized') is not True or grant.get('requests')!=p['templates'] or grant.get('source_sha256')!=p['sources'] or grant.get('workspace')!=p['workspace'] or grant.get('working_root')!=p['working'] or grant.get('expires_at')!=owner['expires_at'] or 'approved_at' in grant or grant.get('dispatch_limit')!=3 or grant.get('cost_units_limit')!=3 or grant.get('cost_units_per_dispatch')!=1 or grant.get('timeout_seconds')!=900 or grant.get('request_binding_mode')!='ENGINE_SAVED_TASK_V1' or grant.get('safety_sha256')!=digest(p['authority_paths']['safety']) or grant.get('host_configuration_sha256')!=plan_sha or grant.get('accepted_native_sha256')!=digest(p['authority_paths']['safety'])):raise WorkflowError('new exact single-segment3 Native Grant required')
    capabilities={'model_api','credential_read','mxc_exec','provider_budget'}
    if native_owner.get('purpose')!='A6_DERIVED_NATIVE_OWNER_AUTHORIZATION' or native_owner.get('actual_owner')!=p['actual_owner'] or native_owner.get('runtime_plan_sha256')!=runtime_plan_sha256(grant) or set(native_owner.get('capabilities',[]))!=capabilities or grant.get('runtime_authorities')!={k:{'file':p['authority_paths']['native_owner'],'sha256':digest(p['authority_paths']['native_owner'])} for k in capabilities}:raise WorkflowError('actual new Owner technical runtime derivation required')
    return p,a,basis


class SuccessorNativeHost(ManagedNativeHost):
    """New A6 exact type; no dependency on unaccepted NativeHostLocations policy."""
    def __init__(self,writer_lease,plan_ref,*,live_budget=None):
        super().__init__(writer_lease);self.plan_ref=plan_ref;self.live_budget=live_budget
        self.plan,self.authorities,_=runtime_authorities(plan_ref,writer_lease=writer_lease,live=True,live_budget=self.live_budget)
    @property
    def records_root(self):return Path(self.plan['records_root'])
    def _configuration(self):return {'consumption_chain':self.plan['consumption_chain']}
    def _paths(self):
        p=self.plan
        return Path(p['authority_paths']['grant']),Path(p['authority_paths']['native_owner']),Path(p['native_ledger']),self._configuration()
    def _check(self,request,working_root,limits,*,binding_engine=None):
        p,a,_=runtime_authorities(self.plan_ref,writer_lease=self.writer_lease,live=True,live_budget=self.live_budget)
        grant=a['grant'];config=request.config.managed;self._writer(request)
        from loommode.workflow.managed_cli import PARENT_HTTP_ROUTE,native_launch_plan
        if (request.config.backend!='managed_codex_cli' or str(request.policy.workspace.resolve())!=p['workspace'] or str(Path(working_root).resolve())!=p['working'] or asdict(limits)!=p['limits'] or request.binding['task_id'] not in p['templates'] or task_template_sha256(request)!=p['templates'][request.binding['task_id']]['template_sha256'] or grant.get('endpoint')!=config.endpoint or grant.get('credential_file')!=config.credential_file or grant.get('credential_env')!=config.credential_env or config.cli_version!='0.162.1' or config.windows_sandbox!='mxc' or config.approval_policy!='never' or config.unattended is not True or config.credential_env!='DEEPSEEK_API_KEY' or grant.get('parent_http_route')!=PARENT_HTTP_ROUTE or digest(config.cli_path)!=BINARY_SHA256 or grant.get('binary_sha256')!=BINARY_SHA256 or grant.get('currency')!='OWNER_APPROVED_DISPATCH_UNIT' or grant.get('cleanup_seconds')!=limits.cleanup_seconds or grant.get('io_limits')!={k:getattr(limits,k) for k in ('stdin_bytes','stream_bytes','result_bytes')}):raise WorkflowError('A6 exact Native request/route/binary/limits changed')
        workspace=Path(p['workspace']).resolve();home=Path(config.codex_home).resolve(strict=True);work=Path(p['working']).resolve()
        if any(x==y or x.is_relative_to(y) or y.is_relative_to(x) for x,y in ((workspace,home),(workspace,work),(home,work),(workspace,self.records_root),(home,self.records_root),(work,self.records_root))):raise WorkflowError('independent home/workspace/Records required')
        credential=Path(config.credential_file).resolve(strict=False)
        if credential.is_relative_to(workspace) or credential.is_relative_to(work) or credential==home or credential==Path(config.cli_path).resolve():raise WorkflowError('credential scope mismatch')
        for path in (Path('C:/ProgramData/OpenAI/Codex/requirements.toml'),Path('C:/ProgramData/OpenAI/Codex/config.toml'),home/'managed_config.toml',home/'.env',home/'auth.json'):
            if path.exists():raise WorkflowError('ambient managed/auth inputs require fresh review')
        native_launch_plan(request,work/'ATTEMPT/schema.json',work/'ATTEMPT/result.json')
        sha=digest(p['authority_paths']['grant']);bindings=self._task_bindings(grant,sha,Path(p['native_ledger']));selected=bindings.get(request.fingerprint)
        if not selected and binding_engine is None:raise WorkflowError('actual saved Task binding required')
        if selected and (selected['task_id']!=request.binding['task_id'] or selected['control_sha256']!=control_sha256(request,work)):raise WorkflowError('actual Native binding changed')
        self._runtime_budget(grant,sha,Path(p['native_ledger']),bindings,task=request.binding['task_id'])
        return _Admission(sha,grant,'NATIVE_MXC_V4_BOUNDED_VALIDATION',False,selected['binding_sha256'] if selected else None)


def apply_typed_capacity(engine,plan):
    owner,_=validate_owner(plan['actual_owner']);task=plan['tasks'][0]
    if engine.state.task_id!=task:raise WorkflowError('typed addition only exact CORE3 recipient')
    totals=engine._allowance_totals(engine.state)
    if (totals['implementation'],totals['repair'],totals['decision_flow'])!=(5,1,0) and not any(engine.artifacts.read_json(r)['authorization_id']=='A6-V005-NET-ONE' for r in engine.state.artifact_refs.get('HOST_ALLOWANCE_GRANT',[])):raise WorkflowError('actual inherited typed5/1/0 required before one-time addition')
    grant=engine.grant()
    capacity={'origin':'OWNER_ALLOWANCE_AUTHORIZATION','authorization_id':'A6-V005-NET-ONE','project':engine.state.project,'stage_id':engine.state.stage_id,'workspace':plan['workspace'],'family_task_id':owner['typed']['family'],'recipient_task_id':task,'scope_authority_ref':grant.authority_ref,'scope_authority_sha256':grant.authority_sha256,'additional_capacity':{'implementation':4,'repair':1,'treatment':0,'decision_flow':0},'reason':'Actual v005: old6/2 + net1/0 =7/2; new3/1 + derived4/1; old capacity never imported.'}
    engine.authority['a6-derived-capacity']=wire(capacity)
    result=engine.apply_owner_allowance('a6-derived-capacity')
    totals=engine._allowance_totals(engine.state)
    if totals['capacity']['implementation']!=7 or totals['capacity']['repair']!=2:raise WorkflowError('derived typed7/2 mismatch')
    return result
