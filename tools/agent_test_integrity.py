"""Verify exact candidate directory or safely extract a new verified ZIP."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


def safe_name(name):
    parts=PurePosixPath(name).parts
    reserved={'con','prn','aux','nul',*[f'com{i}' for i in range(1,10)],*[f'lpt{i}' for i in range(1,10)]}
    if (not name or '\\' in name or ':' in name or name.startswith('/') or '..' in parts
            or name != '/'.join(parts) or any(p in {'.',''} or p.endswith((' ','.'))
                or p.casefold()=='.git' or p.split('.')[0].casefold() in reserved for p in parts)):
        raise ValueError('unsafe candidate member')
    return name


def unlinked(path):
    path=Path(path).absolute()
    for item in (path,*path.parents):
        try: info=item.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('linked candidate namespace refused')
        if stat.S_ISREG(info.st_mode) and info.st_nlink!=1:
            raise ValueError('hardlinked candidate file refused')


def verify_bytes(files):
    folded=set()
    for name in files:
        safe_name(name)
        if name.casefold() in folded:raise ValueError('casefold-colliding candidate members')
        folded.add(name.casefold())
    manifest=json.loads(files['MANIFEST.json'])
    if manifest.get('kind')!='LOOMMODE_AGENT_TEST_CANDIDATE_V1':
        raise ValueError('candidate manifest kind required')
    names=set(manifest['files'])
    if set(files)!=names|{'MANIFEST.json','SHA256SUMS'}:
        raise ValueError('missing or extra candidate members')
    for name,row in manifest['files'].items():
        if len(files[name])!=row['bytes'] or hashlib.sha256(files[name]).hexdigest()!=row['sha256']:
            raise ValueError('candidate payload hash mismatch: '+name)
    checks={}
    for line in files['SHA256SUMS'].decode('utf-8').splitlines():
        digest,name=line.split('  ',1)
        safe_name(name)
        if name in checks or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('invalid checksum inventory')
        checks[name]=digest
    if set(checks)!=names|{'MANIFEST.json'}:raise ValueError('checksum coverage mismatch')
    for name,digest in checks.items():
        if hashlib.sha256(files[name]).hexdigest()!=digest:raise ValueError('checksum mismatch: '+name)
    return manifest


def verify_directory(root):
    root=Path(root).absolute()
    unlinked(root)
    files={}
    for path in root.rglob('*'):
        unlinked(path)
        if path.is_file():files[path.relative_to(root).as_posix()]=path.read_bytes()
    return verify_bytes(files)


def extract(archive,target,expected_sha256):
    archive,target=Path(archive).absolute(),Path(target).absolute()
    unlinked(archive);unlinked(target)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected_sha256:raise ValueError('ZIP hash mismatch')
    if target.exists():raise ValueError('new absent extraction directory required')
    files={}
    with zipfile.ZipFile(archive) as stream:
        for row in stream.infolist():
            safe_name(row.filename)
            if row.is_dir() or row.filename in files or stat.S_ISLNK(row.external_attr>>16):
                raise ValueError('duplicate/directory/linked ZIP member refused')
            if row.file_size>10_000_000 or len(files)>=300:raise ValueError('bounded ZIP required')
            files[row.filename]=stream.read(row)
    verify_bytes(files)  # Validate all members before any extraction write.
    target.mkdir(parents=True)
    for name,raw in files.items():
        path=target/name
        unlinked(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
    return verify_directory(target)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path)
    parser.add_argument('--archive',type=Path)
    parser.add_argument('--extract-to',type=Path)
    parser.add_argument('--sha256')
    args=parser.parse_args()
    if args.directory and not any((args.archive,args.extract_to,args.sha256)):
        result=verify_directory(args.directory)
    elif not args.directory and all((args.archive,args.extract_to,args.sha256)):
        result=extract(args.archive,args.extract_to,args.sha256)
    else:parser.error('directory verification OR archive/extract-to/sha256 required')
    print(json.dumps({'status':'INTEGRITY_VERIFIED','version':result['version'],
                      'payload_files':len(result['files']),'license':result.get('license')}))


if __name__=='__main__':main()
