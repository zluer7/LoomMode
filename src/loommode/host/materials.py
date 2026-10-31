"""Explicit Host-owned local control-material resolution; no filesystem monkeypatch."""
from pathlib import Path
import hashlib,json,stat
from threading import RLock
from loommode.workflow.errors import WorkflowError

from .private_instance import private_value, require_private_instance

_INTERNAL = ()  # No developer-instance defaults.
_ACTIVE=None
_LOCK=RLock()

def internal(path):
    name=Path(path).as_posix().casefold()
    return any(name==p or name.startswith(p+'/') for p in _INTERNAL)

SIX_FORMALS = ()  # No developer-instance defaults.

def exact_formal(path,expected=None):
    key=Path(path).as_posix().casefold()
    for entry in SIX_FORMALS:
        if key==Path(entry['path']).as_posix().casefold() and (expected is None or expected==entry['raw_sha256']):return entry
    return None

class LocalMaterials:
    """Construct only in the trusted candidate Host, using a pinned mapping overlay.

    Input records stay unchanged. History Store/Artifact paths are never mapped.
    """
    def __init__(self,project_root,mapping_ref,*,allowed_mapping_sha256):
        self.root=Path(project_root).absolute();self._regular(self.root,directory=True)
        path=Path(mapping_ref['path'])
        self._regular(path)
        if not path.resolve().is_relative_to(self.root.resolve()):raise WorkflowError('mapping must be project-local')
        raw=path.read_bytes()
        if mapping_ref['sha256']!=allowed_mapping_sha256 or hashlib.sha256(raw).hexdigest()!=allowed_mapping_sha256:raise WorkflowError('trusted mapping pin required')
        value=json.loads(raw);self.rows={};local=set()
        if set(value)!={'purpose','entries'} or value['purpose']!='HOST_LOCAL_CONTROL_MATERIALS_V1':raise WorkflowError('explicit control mapping schema required')
        for row in value['entries']:
            if set(row)!={'logical_path','sha256','local_path','kind'} or row['kind'] not in ('control','helper','official','policy','role-experience'):raise WorkflowError('non-control material mapping refused')
            logical=Path(row['logical_path']);key=logical.as_posix().casefold()
            if (not internal(logical) and not (row['kind']=='control' and exact_formal(logical,row['sha256']))) or key in self.rows or any(x.casefold() in ('state','proof','credentials','.git') for x in logical.parts) or 'transcript' in logical.name.casefold():raise WorkflowError('unknown/private/duplicate logical material')
            rel=Path(row['local_path'])
            if rel.is_absolute() or '..' in rel.parts:raise WorkflowError('relative project material required')
            target=self.root/rel;self._regular(target)
            canonical=target.resolve()
            if not canonical.is_relative_to(self.root.resolve()) or canonical in local:raise WorkflowError('material containment/alias refused')
            local.add(canonical);self.rows[key]=(target,row['sha256'])
            resolved=self.resolve(logical,row['sha256'])
            formal=exact_formal(logical)
            if formal and (row['sha256']!=formal['raw_sha256'] or row['kind']!='control' or resolved.stat().st_size!=formal['raw_bytes']):raise WorkflowError('exact formal kind/size required')
        self.mapping=path;self.mapping_raw=raw

    @staticmethod
    def _regular(path,*,directory=False):
        for p in (path,*path.parents):
            info=p.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise WorkflowError('linked material namespace refused')
        info=path.stat()
        if directory:
            if not stat.S_ISDIR(info.st_mode):raise WorkflowError('material root must be directory')
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>2_000_000:raise WorkflowError('bounded unique regular material required')

    def resolve(self,path,expected=None):
        if hasattr(self,'mapping'):
            self._regular(self.mapping)
            if self.mapping.read_bytes()!=self.mapping_raw:raise WorkflowError('trusted mapping drift')
        key=Path(path).as_posix().casefold()
        if key not in self.rows:raise WorkflowError('unlisted internal control reference')
        target,h=self.rows[key]
        if expected is not None and expected!=h:raise WorkflowError('logical material SHA identity mismatch')
        self._regular(target);raw=target.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=h or target.read_bytes()!=raw:raise WorkflowError('control material bytes drift')
        return target


def install_local_materials(value):
    """One trusted pre-dispatch bootstrap per clean process; no Plan/model switch."""
    global _ACTIVE
    if type(value) is not LocalMaterials:raise WorkflowError('trusted concrete local materials required')
    with _LOCK:
        if _ACTIVE is not None:raise WorkflowError('local material binding cannot be swapped')
        _ACTIVE=value


def material_path(path,expected=None):
    if _ACTIVE is None:
        payload=Path(__file__).resolve().parents[3]
        if (payload/'release.json').is_file() and (internal(path) or Path(path).is_absolute() and not Path(path).resolve().is_relative_to(payload)):
            raise WorkflowError('payload runtime requires explicit Host-local control mapping; no external fallback')
        return Path(path)
    return _ACTIVE.resolve(path,expected) if internal(path) or exact_formal(path) else Path(path)


def candidate_role_inputs(role,project_root):
    if not (Path(__file__).resolve().parents[3]/'release.json').is_file():return None
    if _ACTIVE is None or _ACTIVE.root.resolve()!=Path(project_root).resolve() or not hasattr(_ACTIVE,'role_inputs'):
        raise WorkflowError('candidate Host requires its trusted bound local material overlay')
    return _ACTIVE.role_inputs(role)
