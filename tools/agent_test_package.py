"""Build an allowlisted Apache-2.0 candidate, offline wheel, manifest and ZIP.

No Git mutation or release.json. Source is copied, not installed in place.
The target must be absent or the explicitly approved empty directory.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

sys.dont_write_bytecode=True
try:
    from .agent_test_integrity import safe_name, unlinked, verify_directory
except ImportError:
    from agent_test_integrity import safe_name, unlinked, verify_directory


def sha(raw):return hashlib.sha256(raw).hexdigest()


def prepare(source,specification):
    source=Path(source).absolute()
    unlinked(source)
    specification=Path(specification).absolute()
    unlinked(specification)
    spec=json.loads(specification.read_text(encoding='utf-8'))
    if set(spec)!={'format','files'} or spec['format']!='LOOMMODE_AGENT_TEST_CANDIDATE_V1':
        raise ValueError('explicit candidate allowlist required')
    selected={};folded=set()
    # Validate the entire destination namespace before opening any source. This
    # also makes malformed allowlists fail consistently before partial work.
    for row in spec['files']:
        if set(row)!={'source','target'}:raise ValueError('exact source/target rows required')
        safe_name(row['source']);target=safe_name(row['target'])
        if target.casefold() in folded or target.casefold() in {'manifest.json','sha256sums','release.json'}:
            raise ValueError('duplicate/casefold/reserved target refused')
        folded.add(target.casefold())
    for row in spec['files']:
        if set(row)!={'source','target'}:raise ValueError('exact source/target rows required')
        origin,target=safe_name(row['source']),safe_name(row['target'])
        path=source/origin
        unlinked(path)
        if not path.resolve(strict=True).is_relative_to(source.resolve()):raise ValueError('source escape')
        raw=path.read_bytes()
        if len(raw)>2_000_000:raise ValueError('bounded source required')
        text=raw.decode('utf-8-sig')
        secret=re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{20,}')
        private=re.compile(r'(?i)\b(?:[a-z]:[/\\]+users[/\\]+[^/\\\s]+|[a-z]:[/\\]+loommode[/\\])')
        if secret.search(text):raise ValueError('key signature in selected source: '+origin)
        # Exact intentionally synthetic negative-test sentinel, not a private path.
        sentinel='/'.join(('C:','Users','synthetic_private','secret'))
        scan=text.replace(sentinel,'SYNTHETIC_NEGATIVE_TEST_SENTINEL') if origin=='tests/test_public_bootstrap.py' else text
        if private.search(scan):raise ValueError('developer path in selected source: '+origin)
        if origin.endswith('.py'):ast.parse(text,filename=origin)
        selected[target]=(raw,origin)
    actual={p.relative_to(source).as_posix() for p in (source/'src').rglob('*.py')}
    declared={origin for raw,origin in selected.values() if origin.startswith('src/') and origin.endswith('.py')}
    if actual!=declared or len(actual)!=65:raise ValueError('complete reviewed 65-file production closure required')
    return selected


def build(source,specification,target,evidence,archive,baseline=None,source_date_epoch=None):
    source,target,evidence,archive=map(lambda p:Path(p).absolute(),(source,target,evidence,archive))
    for path in (target,evidence,archive):unlinked(path)
    if (target==source or target.is_relative_to(source) or source.is_relative_to(target)
            or evidence.is_relative_to(source) or source.is_relative_to(evidence)
            or evidence.is_relative_to(target) or target.is_relative_to(evidence)
            or archive.is_relative_to(source) or archive.is_relative_to(target)):
        raise ValueError('disjoint source/candidate/evidence required')
    if (evidence.exists() or archive.exists() or archive.with_suffix(archive.suffix+'.sha256').exists()
            or target.exists() and any(target.iterdir())):
        raise ValueError('fresh evidence/archive and absent or approved empty target required')
    files=prepare(source,specification)
    version=ast.literal_eval(next(node.value for node in ast.parse(files['src/loommode/version.py'][0].decode('utf-8')).body
                                 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in node.targets)))
    match=re.fullmatch(r'(\d+\.\d+\.\d+)(?:-rc\.(\d+))?',version)
    if not match:raise ValueError('numeric release or explicit rc source version required')
    pep440=match[1]+('rc'+match[2] if match[2] else '')
    epoch=None if source_date_epoch is None else int(source_date_epoch)
    if epoch is not None and not 315532800<=epoch<=4354819199:
        raise ValueError('SOURCE_DATE_EPOCH outside portable ZIP dates')
    stamp=datetime.now(timezone.utc) if epoch is None else datetime.fromtimestamp(epoch,timezone.utc)
    evidence.mkdir(parents=True)
    temporary=evidence/'build temporary';temporary.mkdir()
    stage=evidence/'wheel source';stage.mkdir()
    for name,(raw,origin) in files.items():
        if name.startswith('src/') or name in {'pyproject.toml','LICENSE'}:
            output=stage/name;output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(raw)
    wheels=evidence/'built wheels';wheels.mkdir()
    command=[sys.executable,'-B','-m','pip','wheel','--no-index','--no-deps','--no-build-isolation','--wheel-dir',str(wheels),str(stage)]
    env={**os.environ,'TEMP':str(temporary),'TMP':str(temporary),'PYTHONDONTWRITEBYTECODE':'1','PIP_NO_INDEX':'1','PIP_DISABLE_PIP_VERSION_CHECK':'1'}
    if epoch is not None:env['SOURCE_DATE_EPOCH']=str(epoch)
    run=subprocess.run(command,cwd=evidence,env=env,capture_output=True,text=True,encoding='utf-8')
    (evidence/'wheel-build.stdout.log').write_text(run.stdout,encoding='utf-8')
    (evidence/'wheel-build.stderr.log').write_text(run.stderr,encoding='utf-8')
    if run.returncode:raise RuntimeError('offline wheel build failed; preserve evidence')
    built=list(wheels.glob('*.whl'))
    if len(built)!=1 or built[0].name!='loommode-'+pep440+'-py3-none-any.whl':raise ValueError('candidate wheel version mismatch')
    official_license=files['LICENSE'][0]
    if len(official_license)!=11358 or sha(official_license)!='cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30':
        raise ValueError('exact unmodified official Apache text required')
    with zipfile.ZipFile(built[0]) as wheel:
        licenses=[name for name in wheel.namelist() if '.dist-info/' in name and name.endswith('/LICENSE')]
        metadata=[name for name in wheel.namelist() if name.endswith('.dist-info/METADATA')]
        if len(licenses)!=1 or wheel.read(licenses[0])!=official_license or len(metadata)!=1:
            raise ValueError('wheel must retain exact official LICENSE bytes')
        metadata_text=wheel.read(metadata[0]).decode('utf-8')
        if 'License :: OSI Approved :: Apache Software License' not in metadata_text or 'Apache License' not in metadata_text:
            raise ValueError('wheel Apache metadata missing')
    source_digest=sha(json.dumps({origin:sha(raw) for raw,origin in files.values()},sort_keys=True,separators=(',',':')).encode())
    wheelname='wheels/'+built[0].name
    files[wheelname]=(built[0].read_bytes(),None)
    old={};baseline_sha=None
    if baseline:
        baseline=Path(baseline);unlinked(baseline)
        old=json.loads(baseline.read_text()).get('source_files',{})
        baseline_sha=sha(baseline.read_bytes())
    manifest={'kind':'LOOMMODE_AGENT_TEST_CANDIDATE_V1','version':version,'installed_pep440':pep440,
              'rights':'Apache-2.0','license':'Apache-2.0',
              'license_sha256':sha(official_license),'wheel_license_sha256':sha(official_license),
              'notice':'No included upstream NOTICE or identified selected third-party attribution obligation; no redundant NOTICE created.',
              'release':False,'runtime_acceptance':False,'created_utc':stamp.isoformat(),
              'source':'LoomMode_Dev explicitly selected working-tree bytes, not HEAD archive',
              'source_selected_sha256':source_digest,'c5_selected_baseline_sha256':baseline_sha,
              'hash_scheme':'Manifest excludes itself; SHA256SUMS covers payload+manifest and excludes itself; external ZIP.sha256 covers ZIP.',
              'provenance_limit':'Owner confirms independent personal development and selected Apache-2.0; public developer/copyright name: 争流儿. This records the Owner declaration, not an independent legal-title audit.',
              'files':{name:{'sha256':sha(raw),'bytes':len(raw),'source':origin,
                              'transformation':'IDENTITY' if origin else 'OFFLINE_WHEEL_FROM_SELECTED_PRODUCTION_AND_PYPROJECT',
                              'c5_identity':'UNCHANGED' if origin in old and old[origin]==sha(raw) else 'CHANGED' if origin in old else 'NEW_SELECTED_ASSET'}
                       for name,(raw,origin) in sorted(files.items())}}
    rawmanifest=(json.dumps(manifest,indent=2)+'\n').encode()
    allfiles={name:raw for name,(raw,origin) in files.items()}
    allfiles['MANIFEST.json']=rawmanifest
    allfiles['SHA256SUMS']=(''.join(sha(raw)+'  '+name+'\n' for name,raw in sorted(allfiles.items()))).encode()
    target.mkdir(parents=True,exist_ok=True)
    for name,raw in sorted(allfiles.items()):
        output=target/name;unlinked(output);output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('xb') as stream:stream.write(raw)
    verify_directory(target)
    archive.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as stream:
        for name,raw in sorted(allfiles.items()):
            if epoch is None:stream.writestr(name,raw)
            else:
                info=zipfile.ZipInfo(name,stamp.timetuple()[:6]);info.compress_type=zipfile.ZIP_DEFLATED
                info.create_system=3;info.external_attr=0o100644<<16
                stream.writestr(info,raw)
    archive_digest=sha(archive.read_bytes())
    with archive.with_suffix(archive.suffix+'.sha256').open('x',encoding='utf-8') as stream:
        stream.write(archive_digest+'  '+archive.name+'\n')
    result={'source_selected_sha256':source_digest,'version':version,'target':str(target),'archive':str(archive),
            'zip_sha256':archive_digest,'manifest_sha256':sha(rawmanifest),'payload_files':len(files),'directory_files':len(allfiles),
            'production_files':65,'source_date_epoch':epoch,'wheel_command':command,'wheel_exit_status':run.returncode,
            'rights':'Apache-2.0','status':'BUILT_NOT_YET_ACCEPTED'}
    (evidence/'build-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','specification','target','evidence','archive'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--baseline',type=Path)
    parser.add_argument('--source-date-epoch',type=int,help='Pinned build timestamp for repeatable wheel/manifest/ZIP bytes')
    args=parser.parse_args()
    print(json.dumps(build(**vars(args)),indent=2))


if __name__=='__main__':main()
