"""Workspace-wide OS lease; owned runtime files never enter the Git workspace."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from threading import RLock

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import unique_json_object

_LOCAL_LOCK = RLock()
_LEASES = {}


def workspace_identity(workspace) -> str:
    path = Path(workspace).resolve(strict=True)
    if not path.is_dir():
        raise WorkflowError("workspace must be an existing directory")
    # resolve follows symlinks/junctions; normcase folds Windows drive/path case.
    return os.path.normcase(str(path))


def _known_local_appdata() -> Path:
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 0x1C, None, 0, buffer) != 0:
        raise WorkflowError("OS local runtime directory unavailable")
    return Path(buffer.value)


def _check_namespace(path: Path) -> None:
    # Inspect the original spelling before resolve can follow a junction.
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise WorkflowError("linked/reparse runtime namespace: " + str(component))


def _runtime_base() -> Path:
    if os.name == "nt":
        known = _known_local_appdata()
        parts = [part.casefold() for part in known.parts]
        if any(parts[index:index + 3] == ["appdata", "local", "packages"]
               for index in range(len(parts) - 2)):
            raise WorkflowError("Package LocalAppData is not the canonical Host environment; "
                                "start in an ordinary Windows user session: " + str(known))
        _check_namespace(known)
        # OS known folder, deliberately independent of TEMP/TMP and CLI options.
        return known.resolve(strict=True) / "Temp" / "loommode-runtime-v1"
    return Path("/tmp") / ("loommode-runtime-v1-" + str(os.getuid()))


def runtime_preflight(workspace) -> dict:
    """Read-only identity/path checks. Writability is proved only by real operations."""
    key = workspace_identity(workspace)
    root = _runtime_base()
    _check_namespace(root)
    if not root.parent.is_dir():
        raise WorkflowError("OS runtime parent is unavailable: " + str(root.parent))
    target = root / hashlib.sha256(key.encode("utf-8")).hexdigest()
    _check_namespace(target)
    if os.name == "nt":
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.c_ulong(len(buffer))
        if not ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(length)):
            raise WorkflowError("OS runtime user identity unavailable")
        user = buffer.value
    else:
        user = str(os.getuid())
    return {"workspace": key, "runtime_root": str(root), "runtime_directory": str(target),
            "os_user": user, "writability": "NOT_TESTED_READ_ONLY", "permissions_expanded": False}


def _unlinked(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise WorkflowError("linked/reparse runtime path is not owned: " + str(path))
    if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise WorkflowError("runtime path has unknown owner or public access")


def runtime_directory(workspace) -> Path:
    facts = runtime_preflight(workspace)
    key = facts["workspace"]
    root = Path(facts["runtime_root"])
    # Never traverse a link at an existing component of the runtime namespace.
    _check_namespace(root)
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _unlinked(root)
    target = root / hashlib.sha256(key.encode("utf-8")).hexdigest()
    marker = target / "owner.json"
    expected = {"format": "LOOMMODE_RUNTIME_V1", "workspace": key}
    try:
        target.mkdir(mode=0o700)
        with marker.open("x", encoding="utf-8") as stream:
            os.chmod(marker, 0o600)
            json.dump(expected, stream)
    except FileExistsError:
        pass
    _unlinked(target)
    actual = None
    for attempt in range(20):
        if marker.exists():
            _unlinked(marker)
            try:
                actual = json.loads(marker.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object)
                break
            except (ValueError, OSError):
                pass
        # A concurrent creator can be publishing its create-only marker.
        if attempt < 19:
            time.sleep(0.05)
    if actual is None:
        raise WorkflowError("runtime ownership marker is unavailable/invalid; inspect without cleanup")
    if actual != expected:
        raise WorkflowError("runtime directory belongs to an unknown/mismatched owner")
    return target


class WorkspaceLease:
    def __init__(self, workspace):
        self.workspace = workspace_identity(workspace)
        self.directory = runtime_directory(workspace)
        self.owner = None
        self.held = False
        self._stream = None

    def acquire(self) -> bool:
        with _LOCAL_LOCK:
            if self.held:
                return True
            if self.workspace in _LEASES:
                return False
            path = self.directory / "writer.lock"
            if path.exists():
                _unlinked(path)
                for _ in range(20):
                    if path.stat().st_size != 0:
                        break
                    time.sleep(0.05)  # Concurrent create-only lease-byte publication.
                if not path.is_file() or path.stat().st_size != 1:
                    raise WorkflowError("unknown workspace lease file; preserve it")
            else:
                try:
                    with path.open("xb") as stream:
                        os.chmod(path, 0o600)
                        stream.write(b"L")
                except FileExistsError:
                    _unlinked(path)
            self._stream = path.open("r+b", buffering=0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self._stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self._stream.close()
                self._stream = None
                return False
            if self._stream.read(1) != b"L":
                self._stream.close()
                self._stream = None
                raise WorkflowError("unknown workspace lease content; preserve it")
            _LEASES[self.workspace] = self
            self.held = True
            return True

    def release(self) -> None:
        with _LOCAL_LOCK:
            if not self.held:
                return
            if os.name == "nt":
                import msvcrt
                self._stream.seek(0)
                msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
            self._stream.close()
            self._stream = None
            self.held = False
            del _LEASES[self.workspace]


@contextmanager
def writer_operation(engine, workspace):
    retained = getattr(engine, "_workspace_writer_lease", None)
    if retained is not None:
        if not retained.held or retained.workspace != workspace_identity(workspace) or retained.owner is not engine:
            raise WorkflowError("workspace writer ownership is invalid")
        yield
        return
    lease = WorkspaceLease(workspace)
    if not lease.acquire():
        raise WorkflowError("workspace already has a live/unknown writer; use its original Host")
    try:
        yield
    finally:
        lease.release()
