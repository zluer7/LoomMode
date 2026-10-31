"""Copy an explicit NON_RELEASE development work set; never creates a release.

The inventory is local test evidence, not a release Manifest or license grant.
Existing distribution and Binding compatibility checks remain independent.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True


def _unlinked(path):
    for item in (path, *path.parents):
        if not item.exists():
            continue
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('linked work-package namespace refused')


def prepare(source, specification):
    source = Path(source).resolve(strict=True)
    spec = json.loads(Path(specification).read_text(encoding='utf-8'))
    if set(spec) != {'format', 'files'} or spec['format'] != 'LOOMMODE_NON_RELEASE_WORK_SET_V1':
        raise ValueError('explicit non-release work set required')
    files = {}
    for row in spec['files']:
        if set(row) != {'source', 'target'}:
            raise ValueError('explicit source and destination required')
        origin, target = Path(row['source']), Path(row['target'])
        if any(p.is_absolute() or '..' in p.parts or ':' in str(p) for p in (origin, target)):
            raise ValueError('relative contained work-set paths required')
        if target.as_posix().casefold() in {'release.json', '.git', 'instance.json'} or target.as_posix() in files:
            raise ValueError('release/private/duplicate destination refused')
        _unlinked(source / origin)
        path = (source / origin).resolve(strict=True)
        if not path.is_relative_to(source) or path.is_symlink() or not path.is_file():
            raise ValueError('work-set source escapes or is not a file')
        raw = path.read_bytes()
        if len(raw) > 2_000_000:
            raise ValueError('bounded source file required')
        files[target.as_posix()] = raw
    actual = {p.relative_to(source).as_posix() for p in (source / 'src/loommode').rglob('*.py')}
    declared = {p for p in files if p.startswith('src/loommode/') and p.endswith('.py')}
    if not actual or declared != actual or 'src/loommode_binding.py' not in files:
        raise ValueError('work set must exactly cover production Python closure and neutral Binding')
    forbidden = re.compile(r'(?:[a-z]:[/\\]+users[/\\]+[^/\\\s]+|[a-z]:[/\\]+loommode(?:[/\\]|$)|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{20,})', re.I)
    for path, raw in files.items():
        text = raw.decode('utf-8-sig')
        if forbidden.search(text):
            raise ValueError('private path/key signature in selected public payload: ' + path)
        if path.endswith('.py'):
            ast.parse(text, filename=path)
    return files


def build(source, specification, target):
    files = prepare(source, specification)
    target = Path(target).absolute()
    _unlinked(target)
    target.mkdir()  # Never overwrite an earlier test package or user directory.
    inventory = {}
    for name, raw in sorted(files.items()):
        output = target / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('xb') as stream:
            stream.write(raw)
        inventory[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    evidence = {'kind': 'NON_RELEASE_OFFLINE_WORK_PACKAGE', 'release': False,
                'compatibility_validated': False, 'license_granted': False,
                'privacy_scan': 'ALL_SELECTED_UTF8_FILES_PATH_AND_KEY_SIGNATURES_WITH_SOURCE_REVIEW',
                'privacy_scan_limit': 'Signature checks do not prove absence of every possible secret.',
                'files': inventory}
    with (target / 'NON_RELEASE_INVENTORY.json').open('x', encoding='utf-8') as stream:
        json.dump(evidence, stream, indent=2)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--specification', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    facts = build(args.source, args.specification, args.target)
    print(json.dumps({'kind': facts['kind'], 'files': len(facts['files']), 'release': False}))


if __name__ == '__main__':
    main()
