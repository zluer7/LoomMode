"""Create one fresh handoff bound to exact verified candidate bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

sys.dont_write_bytecode=True
# -I removes the script directory from sys.path. Admit only this verified
# adjacent tools directory; never fall back to a development checkout or cwd.
sys.path.insert(0,str(Path(__file__).resolve().parent))

try:
    from .agent_test_integrity import unlinked,verify_directory,safe_name
except ImportError:
    from agent_test_integrity import unlinked,verify_directory,safe_name


def build_handoff(candidate,archive,target):
    candidate,archive,target=map(lambda p:Path(p).absolute(),(candidate,archive,target))
    for path in (candidate,archive,target):unlinked(path)
    if target.exists() or target.is_relative_to(candidate) or candidate.is_relative_to(target):
        raise ValueError('new disjoint handoff target required')
    manifest=verify_directory(candidate)
    version=manifest['version']
    if version not in ('2.0.0-rc.3','2.0.0') or archive.name!='LoomMode-'+version+'-Agent-Test.zip':
        raise ValueError('exact supported candidate version/name required')
    outer=target.parent/('LoomMode-'+version+('-Release-Candidate-Handoff.zip' if version=='2.0.0' else '-Retest-Handoff.zip'))
    unlinked(outer)
    if outer.exists() or outer.with_suffix('.zip.sha256').exists():
        raise ValueError('new handoff archive and sidecar required')
    current={p.relative_to(candidate).as_posix():p.read_bytes() for p in candidate.rglob('*') if p.is_file()}
    with zipfile.ZipFile(archive) as stream:
        names=stream.namelist()
        if len(names)!=len(set(n.casefold() for n in names)):raise ValueError('duplicate archive target')
        zipped={safe_name(n):stream.read(n) for n in names}
    if zipped!=current:raise ValueError('archive differs from exact verified candidate')
    raw=archive.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if archive.with_suffix('.zip.sha256').read_text().split()[0]!=digest:raise ValueError('core sidecar differs')
    files={archive.name:raw,archive.name+'.sha256':(digest+'  '+archive.name+'\n').encode()}
    for name in ('START_HERE.md','KNOWN_ISSUES.md','TEST_REPORT_TEMPLATE.md','ISSUES_TEMPLATE.md'):
        files[name]=current[name]
    identity={'kind':'LOOMMODE_RELEASE_CANDIDATE_HANDOFF' if version=='2.0.0' else 'LOOMMODE_RC3_RETEST_HANDOFF','version':version,'candidate_archive':archive.name,
        'candidate_sha256':digest,'candidate_bytes':len(raw),'manifest_sha256':hashlib.sha256(current['MANIFEST.json']).hexdigest(),
        'selected_source_sha256':manifest['source_selected_sha256'],'license':'Apache-2.0',
        'real_run_authorized':False,'prior_UNKNOWN_reset_or_refund':False,
        'files':{n:hashlib.sha256(v).hexdigest() for n,v in files.items()}}
    files['HANDOFF.json']=(json.dumps(identity,indent=2)+'\n').encode()
    files['HANDOFF_SHA256SUMS']=''.join(hashlib.sha256(v).hexdigest()+'  '+n+'\n' for n,v in sorted(files.items())).encode()
    target.mkdir(parents=True)
    for name,value in files.items():
        with (target/name).open('xb') as stream:stream.write(value)
    with zipfile.ZipFile(outer,'x',compression=zipfile.ZIP_DEFLATED) as stream:
        for name,value in sorted(files.items()):stream.writestr(name,value)
    outer_sha=hashlib.sha256(outer.read_bytes()).hexdigest()
    with outer.with_suffix('.zip.sha256').open('x',encoding='utf-8') as stream:stream.write(outer_sha+'  '+outer.name+'\n')
    return {'handoff_directory':str(target),'handoff_zip':str(outer),'handoff_sha256':outer_sha,
            'core_zip':str(archive),'core_sha256':digest,'version':version,'files':len(files)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('candidate','archive','target'):parser.add_argument('--'+name,type=Path,required=True)
    print(json.dumps(build_handoff(**vars(parser.parse_args())),indent=2))
