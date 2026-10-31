"""Generate pinned one-Task configuration only; inert unless explicitly activated.

Original Owner Stage/resource/supplement files are supplied independently.
This tool never writes Owner authorization, relay attestation or business files.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from loommode.host.bootstrap import _pinned, _regular, _directory, _output_path, inspect_config
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object


def pin(path):
    original = _regular(Path(path))  # Inspect original spelling before resolve.
    return {'path': str(original.resolve(strict=True)),
            'sha256': hashlib.sha256(original.read_bytes()).hexdigest()}


def put(path, value):
    raw = value if isinstance(value, str) else json.dumps(value, indent=2)
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(raw + '\n')
    return pin(path)


def prepare(request_path, target, *, activate=False, owner_source_sha256=None):
    request_pin = pin(request_path)
    request = json.loads(_pinned(request_pin)[1], object_pairs_hook=unique_json_object)
    fields = {'project','stage_id','task_id','caller_id','workspace','records_root','runtime_root',
              'records_tuple','owner_source','stage_authority','resource_authorization','resource_supplement',
              'codex','policy'}
    if not isinstance(request, dict) or set(request) != fields:
        raise WorkflowError('explicit one-Task setup request schema required')
    originals = {key: _pinned(request[key])[1] for key in
                 ('owner_source','stage_authority','resource_authorization','resource_supplement')}
    if any(not body.strip() for body in originals.values()):
        raise WorkflowError('nonempty independently supplied original authority required')
    if activate and owner_source_sha256 != request['owner_source']['sha256']:
        raise WorkflowError('explicit current Owner-source pin required for activation')
    resource = json.loads(originals['resource_authorization'], object_pairs_hook=unique_json_object)
    identity = {k: request[k] for k in ('project','stage_id','task_id','workspace','caller_id')}
    if any(resource.get(k) != v for k,v in identity.items()):
        raise WorkflowError('actual Owner resource identity differs from requested setup')
    # Source originals refer to these fixed local names, never to mutable spend.
    expected = {'owner_source_ref':'owner-original','supplement_ref':'resource-supplement',
                'preparation_ref':'prepared-inputs'}
    if any(resource.get(k) != v for k,v in expected.items()):
        raise WorkflowError('resource original must select exact distinct immutable sources')
    limits = resource['limits']
    if (not 1 <= limits['max_run_turns'] <= 100 or not 1 <= limits['per_turn_seconds'] <= 600
            or not 1800 < limits['total_seconds'] <= 86400 or limits['max_additional_charge'] != 0):
        raise WorkflowError('finite one-Task subscription-only limits required, including normal review window')
    for key in ('workspace','records_root','runtime_root'):
        _directory(request[key])
    target = Path(target).absolute()
    _output_path(target.parent, target)
    if target.exists() or target.is_relative_to(ROOT):
        raise WorkflowError('new external management input directory required')
    for key in ('workspace','records_root','runtime_root'):
        root = Path(request[key])
        if target.is_relative_to(root) or root.is_relative_to(target):
            raise WorkflowError('management inputs must be disjoint from live stores/workspace')
    target.mkdir(parents=True)
    scope = copy.deepcopy(request['policy']['writable'])
    prep = {'origin':'CALLER_PREPARATION_MANIFEST', **identity, 'scope':scope,
            'pins':{'setup-request':request_pin,'caller-helper':pin(ROOT/'tools/agent_test_caller.py'),
                    'setup-helper':pin(Path(__file__))}}
    authorities = {'owner-original':request['owner_source'],'owner-stage':request['stage_authority'],
                   'approved-resources':request['resource_authorization'],
                   'resource-supplement':request['resource_supplement'],
                   'prepared-inputs':put(target/'prepared-inputs.json', prep)}
    caller = {'origin':'CALLER_VERIFICATION_INPUT', **identity,
              'resource_ref':'approved-resources', 'approved_limits':limits, 'scope':scope, **expected}
    authorities['caller-input'] = put(target/'caller-input.json', caller)
    config = {'schema_version':1, **{k:request[k] for k in ('project','stage_id','workspace','records_root','runtime_root','records_tuple')},
              'stage_authorization_ref':'owner-stage', 'authorities':authorities,
              'roles':{role:pin(ROOT/'config/roles'/(role+'.md')) for role in ('Promoter','Constraint','Discussant','Decision')},
              'codex':{**request['codex'],'connect_on_assembly':bool(activate)},
              'policy':request['policy'], 'task_policies':{request['task_id']:request['policy']},
              'grants':{'allow_progress':bool(activate),'allow_owner_events':bool(activate),'local_commit_authorized':False},
              'caller_verification_ref':'caller-input'}
    config_pin = put(target/'bootstrap.json', config)
    # Full original validation before the factory is ever imported. A failed
    # generation is left as evidence and cannot overwrite or activate old output.
    inspect_config(config_pin['path'], expected_sha256=config_pin['sha256'])
    helper_pin = pin(ROOT/'tools/agent_test_caller.py')
    factory = '''"""Generated reviewed first-use factory; not an authorization source."""
import hashlib
import importlib.util
import json
from pathlib import Path
from loommode.host.bootstrap import create_host as assemble
CANONICAL_FACTORY_API = 1
CONFIG = %r
REQUEST = %r
CALLER = %r
ACTIVE = %r
def create_host(*, canonical_context):
    supervisor = assemble(CONFIG['path'], expected_sha256=CONFIG['sha256'], canonical_context=canonical_context)
    if ACTIVE:
        if hashlib.sha256(Path(CALLER['path']).read_bytes()).hexdigest() != CALLER['sha256']:
            raise ValueError('caller helper source drift')
        spec = importlib.util.spec_from_file_location('loommode_one_task_caller', CALLER['path'])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        config = json.loads(Path(CONFIG['path']).read_text(encoding='utf-8'))
        supervisor._agent_test_caller = module.install(supervisor, config=config, request_pin=REQUEST)
    return supervisor
''' % (config_pin, request_pin, helper_pin, bool(activate))
    factory_pin = put(target/'factory.py', factory)
    normalized_authority = originals['stage_authority'].decode('utf-8-sig')
    binding = {'schema_version':1,'project':request['project'],'stage_id':request['stage_id'],
               'workspace':request['workspace'],'stage_authorization_ref':'owner-stage',
               'stage_authorization_sha256':hashlib.sha256(normalized_authority.encode()).hexdigest(),
               'decision_role':'Decision','grants':config['grants'],
               'runtime':{'kind':'development','source_root':str(ROOT/'src'),
                          'approval_ref':'owner-original'},'factory':factory_pin}
    put(target/'canonical-binding.json', binding)
    result={'origin':'ONE_TASK_SETUP_CONFIGURATION_ONLY','active':bool(activate),
            'authority_authenticated':False,'request_pin':request_pin,'config':config_pin,
            'factory':factory_pin,'new_inputs':str(target),'model_calls':0,
            'limits':'Pins and activation flags do not authenticate or create Owner permission. Actual later Owner authorization is required. No relay attestation/accounting/State/model launch was generated.'}
    put(target/'SETUP.json', result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--activate',action='store_true',help='Only after actual later Owner authorization; never for offline installation')
    parser.add_argument('--owner-source-sha256')
    args=parser.parse_args(argv)
    print(json.dumps(prepare(args.request,args.target,activate=args.activate,
                             owner_source_sha256=args.owner_source_sha256),indent=2))


if __name__=='__main__':
    main()
