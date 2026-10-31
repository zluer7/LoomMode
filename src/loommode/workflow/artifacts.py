"""Host-selected immutable records and narrowly authorized maintenance."""
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from .errors import WorkflowError
from .state import identity, unique_json_object
from loommode.roles.contracts import ARTIFACT_KINDS

PART_II = b"## Part II \xe2\x80\x94 Long-term Role Experience"


class ArtifactStore:
    def __init__(self, records_root: Path, project: str, stage_id: str,
                 maintenance_targets: dict[str, Path] | None = None,
                 maintenance_authorities: dict[str, set[str]] | None = None) -> None:
        self.root = records_root.resolve()
        self.project, self.stage = identity(project), identity(stage_id)
        self.targets = {k: v.resolve() for k, v in (maintenance_targets or {}).items()}
        self.authorities = maintenance_authorities or {}
        for path in self.targets.values():
            self._guard(path)
        self.target_digests = {key: hashlib.sha256(path.read_bytes()).hexdigest()
                               for key, path in self.targets.items() if path.is_file()}

    def _guard(self, path: Path) -> Path:
        canonical = path.resolve()
        if not canonical.is_relative_to(self.root):
            raise WorkflowError("artifact path escapes Records root")
        return canonical

    def _directory(self, kind: str) -> Path:
        bucket = {"FINAL_TASK_CONSTRAINT": "Constraints", "CONSTRAINT_DRAFT": "Constraints",
                  "EXECUTION_REPORT": "Reports", "INDEPENDENT_REVIEW": "Reports"}.get(kind, "Workflow")
        cycle = "LM1" if bucket == "Reports" and self.project == "LM" else self.stage
        return self._guard(self.root / bucket / self.project / cycle)

    def save(self, kind: str, content: str, *, task_id: str | None = None) -> str:
        if kind not in ARTIFACT_KINDS or not isinstance(content, str) or not content.strip():
            raise WorkflowError("unknown artifact kind or empty content")
        key = identity(task_id) if task_id else self.stage
        directory = self._directory(kind)
        directory.mkdir(parents=True, exist_ok=True)
        frozen = kind == "FINAL_TASK_CONSTRAINT"
        version = 1
        while True:
            name = f"{key}_{kind}.md" if frozen else f"{key}_{kind}_v{version:03d}.md"
            path = self._guard(directory / name)
            if not path.exists():
                break
            if frozen:
                raise WorkflowError("frozen Final Constraint already exists")
            version += 1
        return self._publish(path, content.encode("utf-8"), immutable=True)

    def _publish(self, path: Path, data: bytes, *, immutable: bool) -> str:
        path = self._guard(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=".loommode-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if immutable:
                # Atomic publication without replacing an existing frozen file.
                os.link(temp, path)
            else:
                os.replace(temp, path)
            return f"{path}#sha256={hashlib.sha256(data).hexdigest()}"
        except OSError as exc:
            raise WorkflowError("artifact write failed; workflow must stop") from exc
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def read(self, reference: str) -> str:
        try:
            raw_path, expected = reference.rsplit("#sha256=", 1)
            data = self._guard(Path(raw_path)).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise WorkflowError("formal artifact digest changed")
            return data.decode("utf-8")
        except (ValueError, OSError, UnicodeError) as exc:
            raise WorkflowError("invalid formal artifact reference") from exc

    def read_json(self, reference: str) -> dict[str, Any]:
        def reject_constant(value: str):
            raise WorkflowError(f"non-finite formal JSON value: {value}")
        value = json.loads(self.read(reference), object_pairs_hook=unique_json_object, parse_constant=reject_constant)
        if not isinstance(value, dict):
            raise WorkflowError("formal artifact is not an object")
        return value

    def assert_task_reference(self, reference: str, kind: str, task_id: str) -> None:
        raw_path = reference.rsplit("#sha256=", 1)[0]
        path = self._guard(Path(raw_path))
        key = identity(task_id)
        directories = {self._directory(kind)}
        old_bucket = ('Constraints' if kind in {'FINAL_TASK_CONSTRAINT', 'CONSTRAINT_DRAFT'} else
                      'Reports' if kind in {'EXECUTION_REPORT', 'INDEPENDENT_REVIEW'} else 'Workflow')
        directories.add(self._guard(self.root / old_bucket / self.project / self.stage))
        if self.project == 'LM' and old_bucket == 'Reports':
            directories.add(self._guard(self.root / 'Reports' / 'LM' / 'LM1'))
        if self.project == "LM" and kind in {"EXECUTION_REPORT", "INDEPENDENT_REVIEW"}:
            # Frozen historical references remain valid; only new saves use LM1.
            directories.add(self._guard(self.root / "Reports" / self.project / self.stage))
        if path.parent not in directories:
            raise WorkflowError("formal reference belongs to a different Stage")
        name = f"{key}_{kind}"
        pattern = re.escape(name) + (r"\.md" if kind == "FINAL_TASK_CONSTRAINT" else r"_v[0-9]{3,}\.md")
        if not re.fullmatch(pattern, path.name):
            raise WorkflowError("formal reference does not belong to the current Task/kind")
        self.read(reference)

    def preflight_maintenance(self, target: str, content: str, authority_ref: str, *, role_files=None) -> str:
        """Check the explicitly registered target's trusted bytes without effects."""
        if target == "ROLE_MEMORY" or target.startswith("ROLE_MEMORY:"):
            raise WorkflowError("role memory requires dedicated Part II consolidation")
        if target not in self.targets or authority_ref not in self.authorities.get(target, set()):
            raise WorkflowError("maintenance lacks explicit Host authorization")
        if not isinstance(content, str) or not content.strip():
            raise WorkflowError("empty maintenance content")
        path = self._guard(self.targets[target])
        if path != self.targets[target]:
            raise WorkflowError("maintenance target binding changed")
        bindings = role_files() if callable(role_files) else role_files
        if bindings is not None:
            if not isinstance(bindings, dict):
                raise WorkflowError('invalid actual runtime role-file mapping')
            for role_path in bindings.values():
                actual = Path(role_path).resolve()
                try:
                    same_file = path == actual or path.samefile(actual)
                except OSError as exc:
                    raise WorkflowError('actual runtime role ownership cannot be verified') from exc
                if same_file:
                    raise WorkflowError('actual runtime role file cannot be replaced by ordinary maintenance')
        for key, memory_path in self.targets.items():
            if key == "ROLE_MEMORY" or key.startswith("ROLE_MEMORY:"):
                memory_path = self._guard(memory_path)
                try:
                    same_file = path == memory_path or path.samefile(memory_path)
                except OSError as exc:
                    raise WorkflowError("configured memory alias cannot be verified") from exc
                if same_file:
                    raise WorkflowError("role memory alias requires dedicated Part II consolidation")
        expected = self.target_digests.get(target)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise WorkflowError("maintenance target lacks a trusted current digest pin")
        try:
            current = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise WorkflowError("maintenance current target cannot be verified") from exc
        if current != expected:
            raise WorkflowError("maintenance target current digest changed")
        return expected

    def maintain(self, target: str, content: str, authority_ref: str, *, role_files=None) -> str:
        previous = self.preflight_maintenance(target, content, authority_ref, role_files=role_files)
        # Preserve the old evidence before a specifically authorized replacement.
        self.save("DECISION", json.dumps({"target": target, "old_sha256": previous,
                                         "authority": authority_ref}, ensure_ascii=False))
        if self.preflight_maintenance(target, content, authority_ref, role_files=role_files) != previous:
            raise WorkflowError("maintenance trusted revision changed before replacement")
        reference = self._publish(self.targets[target], content.encode("utf-8"), immutable=False)
        self.target_digests[target] = reference.rsplit('#sha256=', 1)[1]
        return reference

    def promote_issues(self, stage_id, issues, triage, *, role_files=None):
        """Selected same-phase merge with an explicit, pinned current target."""
        selected = [row for row in triage if row['disposition'] == 'PROMOTE_TO_MAJOR_PHASE']
        if not selected:
            return None
        key = 'MAJOR_PHASE_ISSUE_LEDGER'
        if key not in self.targets or len(self.authorities.get(key, set())) != 1:
            raise WorkflowError('selected issue promotion requires explicit Major Phase target/authority')
        authority = next(iter(self.authorities[key]))
        # Guard actual fixed-role ownership before reading/parsing a merge target.
        self.preflight_maintenance(key, 'Selected same-phase issue promotion.', authority, role_files=role_files)
        path = self.targets[key]
        original = path.read_bytes()
        expected = self.target_digests.get(key)
        if expected != hashlib.sha256(original).hexdigest():
            raise WorkflowError('Major Phase target current digest changed; contributions must be reconciled')
        from .governance import stage_tuple
        cycle, phase, _ = stage_tuple(stage_id)
        value = json.loads(original, object_pairs_hook=unique_json_object)
        if set(value) != {'major_phase', 'issues'} or value['major_phase'] != f'{cycle}-{phase}' or not isinstance(value['issues'], dict):
            raise WorkflowError('typed current Major Phase target identity mismatch')
        for row in selected:
            issue = issues[row['issue_id']]
            prior = value['issues'].get(row['issue_id'])
            if prior and (prior['origin_ref'] != issue['origin_ref'] or prior['revision'] > issue['revision']):
                raise WorkflowError('promotion would lose existing issue origin/current revision')
            value['issues'][row['issue_id']] = {**issue, 'source_stage': stage_id, 'disposition': row['disposition'], 'reason': row['reason']}
        ref = self.maintain(key, json.dumps(value, ensure_ascii=False, indent=2), authority, role_files=role_files)
        return ref

    def preflight_memory_ownership(self, role_files=None) -> None:
        """Verify explicit owners and, when exposed, actual runtime filenames."""
        paths = {}
        for key, target in self.targets.items():
            if key.startswith('ROLE_MEMORY:'):
                path = self._guard(target)
                if path != target:
                    raise WorkflowError('memory target binding changed')
                paths[key.split(':', 1)[1]] = path
        if not paths:
            return
        def same_file(left, right):
            try:
                return left == right or left.samefile(right)
            except OSError as exc:
                raise WorkflowError('memory physical ownership cannot be verified') from exc
        owners = list(paths.items())
        for number, (role, path) in enumerate(owners):
            if any(same_file(path, other_path) for _, other_path in owners[number + 1:]):
                raise WorkflowError('distinct memory roles cannot share a physical target')
        bindings = role_files() if callable(role_files) else role_files
        if bindings is None:
            return  # Existing no-map participants retain explicit trusted targets.
        if not isinstance(bindings, dict):
            raise WorkflowError('invalid actual runtime role-file mapping')
        actual = {getattr(role, 'value', role): Path(path).resolve() for role, path in bindings.items()}
        for role, path in paths.items():
            # Same inode at another name is insufficient: replace would split it.
            if actual.get(role) != path:
                raise WorkflowError('memory target differs from its actual corresponding runtime file')
            if any(other != role and same_file(path, other_path) for other, other_path in actual.items()):
                raise WorkflowError('memory target is also owned by another actual runtime role')

    def preflight_memory(self, role: str, authority_ref: str, *, role_files=None) -> bytes:
        """Read only registered, authorized and unchanged trusted role bytes."""
        self.preflight_memory_ownership(role_files)
        key = f"ROLE_MEMORY:{role}"
        if key not in self.targets or authority_ref not in self.authorities.get(key, set()):
            raise WorkflowError("memory lacks explicit Host authorization")
        path = self._guard(self.targets[key])
        if path != self.targets[key]:
            raise WorkflowError("memory target binding changed")
        expected = self.target_digests.get(key)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise WorkflowError("memory target lacks a trusted current digest pin")
        try:
            original = path.read_bytes()
        except OSError as exc:
            raise WorkflowError("memory current target cannot be verified") from exc
        if hashlib.sha256(original).hexdigest() != expected:
            raise WorkflowError("memory target current digest changed")
        if original.count(PART_II) != 1:
            raise WorkflowError("role Part II boundary missing or ambiguous")
        return original

    def consolidate_memory(self, role: str, experiences: list[dict[str, Any]], authority_ref: str, *, role_files=None) -> str | None:
        key = f"ROLE_MEMORY:{role}"
        original = self.preflight_memory(role, authority_ref, role_files=role_files)
        path = self.targets[key]
        prefix, memory = original.split(PART_II)
        added = []
        for candidate in experiences:
            if candidate["role"] != role or not candidate["source_refs"]:
                raise WorkflowError("memory must be consolidated by its corresponding role with provenance")
            lesson = candidate["lesson"]
            if lesson.encode("utf-8") in memory or any(x["lesson"] == lesson for x in added):
                continue
            added.append(candidate)
        if not added:
            return None
        suffix = "\n\n" + "\n".join(
            f"- Lesson: {c['lesson']}\n  Conditions: {c['conditions']}\n  Sources: {', '.join(c['source_refs'])}\n  Experience grants no authority or tool permissions."
            for c in added)
        data = prefix + PART_II + memory + suffix.encode("utf-8")
        if data.count(PART_II) != 1 or data.split(PART_II)[0] != prefix:
            raise WorkflowError("one Part II boundary and byte-identical Part I required")
        self.save("ROLE_EXPERIENCE", json.dumps(added, ensure_ascii=False))
        if self.targets.get(key) != path or self.preflight_memory(role, authority_ref, role_files=role_files) != original:
            raise WorkflowError("memory trusted revision or binding changed before replacement")
        reference = self._publish(path, data, immutable=False)
        self.target_digests[key] = reference.rsplit('#sha256=', 1)[1]
        return reference
