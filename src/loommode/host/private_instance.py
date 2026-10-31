"""Explicit pinned Host input for retained, optional instance-specific admission.

Nothing is discovered from an environment variable, model message or user home.
Install only from reviewed Host bootstrap code, before importing legacy clients.
This preserves historical facts; it grants no permission and restores no State.
"""
import hashlib
import json
from pathlib import Path
from threading import RLock

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object

_ACTIVE = None
_LOCK = RLock()
_MODULES = frozenset({'managed_native', 'materials', 'forward', 'successor', 'successor_factory'})
_CONSTANTS = {
    'materials': {'_INTERNAL', 'SIX_FORMALS'},
    'managed_native': {'RECORDS', 'TRUSTED_RECORDS_ROOT', 'HOST_CONFIGURATION', 'ACCEPTED_NATIVE',
        'V2_REVIEW', 'V2_SHA256', 'RUNTIME_GRANT', 'OWNER_GRANT', 'CONTINUATION_RUNTIME_GRANT',
        'CONTINUATION_OWNER_GRANT', 'F3_RUNTIME_GRANT', 'F3_OWNER_GRANT', 'F4_RUNTIME_GRANT',
        'F4_OWNER_GRANT', 'F4_FIXTURE', 'F3_FIXTURE', 'F3_PRIOR_FIXTURE', 'F3_SECOND_FIXTURE',
        'F3_THIRD_FIXTURE', 'F3_RETRY_EVIDENCE', '_CONTINUATION_CHAIN', 'BINARY', 'BINARY_SHA256'},
    'forward': set(), 'successor_factory': set(),
    'successor': {'V014_OWNER_SHA256', 'V014_QUOTE', 'V013_OWNER_SHA256', 'V012_OWNER_SHA256',
        'V011_OWNER_SHA256', 'V010_OWNER_SHA256', 'V009_OWNER_SHA256', 'V008_OWNER_SHA256',
        'V007_OWNER_SHA256', 'V006_OWNER_SHA256', 'V005_OWNER_SHA256'},
}


def _decode(value):
    if isinstance(value, dict):
        if set(value) == {'__path__'}:
            return Path(value['__path__'])
        if set(value) == {'__tuple__'}:
            return tuple(_decode(v) for v in value['__tuple__'])
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


def install_private_instance(path, *, expected_sha256):
    """One immutable installation from a pin in trusted bootstrap source.

    Host code is the trust boundary, as for NativeHostLocations. Never expose
    this operation as a model tool or load its pin from untrusted project JSON.
    """
    global _ACTIVE
    from .materials import LocalMaterials
    path = Path(path)
    LocalMaterials._regular(path)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise WorkflowError('private instance input pin mismatch')
    value = json.loads(raw, object_pairs_hook=unique_json_object)
    if (set(value) != {'format', 'modules'} or value['format'] != 'HOST_PRIVATE_INSTANCE_V1'
            or set(value['modules']) != _MODULES):
        raise WorkflowError('unknown private instance input')
    decoded = _decode(value['modules'])
    for name, entry in decoded.items():
        if (not isinstance(entry, dict) or set(entry) != {'constants', 'literals'}
                or not isinstance(entry['constants'], dict) or not isinstance(entry['literals'], dict)
                or set(entry['constants']) != _CONSTANTS[name]):
            raise WorkflowError('private input cannot replace executable module members')
    with _LOCK:
        if _ACTIVE is not None:
            raise WorkflowError('private instance binding cannot be replaced')
        _ACTIVE = decoded
        # Exported names remain available for explicitly bootstrapped historical
        # harnesses. Existing imports before bootstrap are deliberately not fixed
        # up: an incorrect bootstrap order must fail closed.
        import importlib
        for name, entry in decoded.items():
            module = importlib.import_module('loommode.host.' + name)
            for key, item in entry.get('constants', {}).items():
                setattr(module, key, item)


def private_value(module, key):
    with _LOCK:
        if _ACTIVE is None:
            raise WorkflowError('optional historical admission requires explicit pinned Host private input')
        try:
            return _ACTIVE[module]['literals'][key]
        except KeyError as exc:
            raise WorkflowError('private historical identity is unavailable') from exc


def require_private_instance():
    if _ACTIVE is None:
        raise WorkflowError('optional historical admission requires explicit pinned Host private input')
