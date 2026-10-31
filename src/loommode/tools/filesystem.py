"""Workspace and exact-target filesystem boundaries."""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Iterable

from loommode.codex.errors import ErrorCategory, LoomModeError


def _norm(path: Path) -> str:
    return os.path.normcase(str(path))


def _contains(root: Path, path: Path) -> bool:
    try:
        common = os.path.commonpath([_norm(root), _norm(path)])
    except ValueError:
        return False
    return common == _norm(root)


def normalize_relative(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "target must be a relative path")
    candidate = Path(value)
    pure = PurePath(value)
    if candidate.is_absolute() or pure.anchor or ":" in value:
        raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "absolute targets are denied")
    parts = candidate.parts
    if any(part in {"", ".", ".."} for part in parts):
        raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "path traversal is denied")
    return Path(*parts).as_posix()


class WorkspaceGuard:
    def __init__(self, allowed_roots: Iterable[Path]) -> None:
        roots: list[Path] = []
        for root in allowed_roots:
            resolved = root.resolve(strict=True)
            if not resolved.is_dir():
                raise LoomModeError(ErrorCategory.CONFIG_ERROR, f"allowlisted root is not a directory: {root}")
            roots.append(resolved)
        if not roots:
            raise LoomModeError(ErrorCategory.CONFIG_ERROR, "at least one workspace root is required")
        self.allowed_roots = tuple(roots)

    def canonical_workspace(self, workspace: Path) -> Path:
        try:
            resolved = workspace.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise LoomModeError(
                ErrorCategory.WORKSPACE_ERROR,
                f"workspace does not exist: {workspace}",
            ) from exc
        if not resolved.is_dir():
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "workspace is not a directory")
        if not any(_contains(root, resolved) for root in self.allowed_roots):
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "workspace is outside the allowlist")
        return resolved

    @staticmethod
    def target(workspace: Path, relative: str, *, must_exist: bool) -> tuple[str, Path]:
        normalized = normalize_relative(relative)
        raw = workspace / Path(normalized)
        try:
            resolved = raw.resolve(strict=must_exist)
        except (FileNotFoundError, OSError) as exc:
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, f"target does not exist: {normalized}") from exc
        if not must_exist:
            try:
                parent = raw.parent.resolve(strict=True)
            except (FileNotFoundError, OSError) as exc:
                raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "target parent does not exist") from exc
            resolved = parent / raw.name
        if not _contains(workspace, resolved) or resolved == workspace:
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "target escapes the workspace")
        return normalized, resolved


@dataclass(frozen=True)
class ReplaceResult:
    path: str
    changed: bool
    before_bytes: int
    after_bytes: int
    diff: str
    diff_truncated: bool


class BoundedFileSystem:
    def __init__(
        self,
        workspace: Path,
        *,
        readable: Iterable[str],
        writable: Iterable[str],
        max_read_bytes: int = 128_000,
        max_write_bytes: int = 128_000,
        max_diff_chars: int = 20_000,
    ) -> None:
        self.workspace = workspace.resolve(strict=True)
        self.readable = frozenset(normalize_relative(path) for path in readable)
        self.writable = frozenset(normalize_relative(path) for path in writable)
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.max_diff_chars = max_diff_chars

    def list_allowed(self) -> dict[str, list[str]]:
        present = [path for path in sorted(self.readable) if (self.workspace / path).is_file()]
        return {"files": present}

    def read_text(self, relative: str) -> dict[str, object]:
        normalized = normalize_relative(relative)
        if normalized not in self.readable:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "read target is not authorized")
        _, path = WorkspaceGuard.target(self.workspace, normalized, must_exist=True)
        if not path.is_file():
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "read target is not a regular file")
        size = path.stat().st_size
        if size > self.max_read_bytes:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "read target exceeds the size limit")
        return {"path": normalized, "text": path.read_text(encoding="utf-8"), "bytes": size}

    def replace_text(self, relative: str, expected: str, replacement: str) -> ReplaceResult:
        normalized = normalize_relative(relative)
        if normalized not in self.writable:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "write target is not authorized")
        if not expected:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "empty replacement anchors are denied")
        if len(expected.encode("utf-8")) > self.max_write_bytes or len(replacement.encode("utf-8")) > self.max_write_bytes:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "replacement input exceeds the size limit")
        _, path = WorkspaceGuard.target(self.workspace, normalized, must_exist=True)
        if not path.is_file():
            raise LoomModeError(ErrorCategory.WORKSPACE_ERROR, "write target is not a regular file")
        before = path.read_text(encoding="utf-8")
        occurrences = before.count(expected)
        if occurrences != 1:
            raise LoomModeError(
                ErrorCategory.TOOL_EXECUTION_ERROR,
                "expected text must occur exactly once",
                details={"occurrences": occurrences},
            )
        after = before.replace(expected, replacement, 1)
        after_bytes = len(after.encode("utf-8"))
        if after_bytes > self.max_write_bytes:
            raise LoomModeError(ErrorCategory.TOOL_PERMISSION_ERROR, "result exceeds the write size limit")
        diff = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=f"a/{normalized}",
                tofile=f"b/{normalized}",
            )
        )
        truncated = len(diff) > self.max_diff_chars
        path.write_text(after, encoding="utf-8", newline="")
        return ReplaceResult(
            path=normalized,
            changed=True,
            before_bytes=len(before.encode("utf-8")),
            after_bytes=after_bytes,
            diff=diff[: self.max_diff_chars],
            diff_truncated=truncated,
        )
