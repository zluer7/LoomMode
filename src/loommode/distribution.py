"""Offline candidate generation and integrity checks; no project loading or upgrades.

The caller supplies roots. Git is used only for immutable object reads. Official
materials come from a digest-pinned recipe, never from project overlays.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from .version import __version__

RECIPE_PATH = "config/distribution.recipe.json"
HISTORY_PATH = "config/releases/1.0.0-historical.json"
MANIFEST_NAME = "release.json"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
_SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_OFFICIAL = {
    **{name: ("role", f"Docs/Roles/{name}.md", f"official/roles/{name}.md")
       for name in ("Promoter", "Constraint", "Discussant", "Decision")},
    **{name: ("policy", f"Docs/{name}.md", f"official/policy/{name}.md")
       for name in ("Workflow_Protocol", "Execution_Context_and_Model_Policy", "Workspace_and_Record_Lifecycle")},
}
_COMPATIBILITY = {
    "workflow_contract": "V1_ACCEPTED_WITH_LIMITS", "state_schema_version": 1,
    "context_schema_version": 1, "codex_tested_versions": ["0.159.2", "0.160.0"],
    "permission_semantics": "UNCHANGED", "breaking_changes": False,
}


class DistributionError(ValueError):
    """An input, immutable target, or candidate identity is invalid."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json(raw: bytes) -> dict[str, Any]:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise DistributionError("duplicate JSON field")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise DistributionError("invalid JSON identity") from exc
    if not isinstance(value, dict):
        raise DistributionError("JSON identity must be an object")
    return value


def _digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX.fullmatch(value))


def _object(value: Any) -> bool:
    return isinstance(value, str) and bool(_OBJECT.fullmatch(value))


def semver(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or len(value) > 32 or not _SEMVER.fullmatch(value):
        raise DistributionError("version must be an exact numeric X.Y.Z")
    return tuple(int(part) for part in value.split("."))


def relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or re.search(r'[\\:<>"|?*\x00-\x1f]', value):
        raise DistributionError("invalid payload path")
    path = PurePosixPath(value)
    parts = value.split("/")
    if path.is_absolute() or any(part in {"", ".", ".."} or part.endswith((".", " ")) for part in parts):
        raise DistributionError("payload path must be canonical and relative")
    if any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part) for part in parts):
        raise DistributionError("reserved device path")
    return value


def _paths(values: list[str]) -> list[str]:
    if not isinstance(values, list) or not values:
        raise DistributionError("explicit nonempty file list required")
    paths = [relative_path(value) for value in values]
    if len({value.casefold() for value in paths}) != len(paths):
        raise DistributionError("duplicate or case-colliding paths")
    names = {value.casefold() for value in paths}
    if any(str(parent).casefold() in names for value in paths for parent in PurePosixPath(value).parents if str(parent) != "."):
        raise DistributionError("file/directory collision")
    spelling = {}
    for value in paths:
        for count in range(1, len(PurePosixPath(value).parts) + 1):
            prefix = "/".join(PurePosixPath(value).parts[:count])
            if spelling.setdefault(prefix.casefold(), prefix) != prefix:
                raise DistributionError("case-colliding directory paths")
    return sorted(paths)


def _reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _root(path: Path, *, must_exist: bool = True) -> Path:
    """Reject linked ancestors before resolving a caller-supplied root."""
    path = path.absolute()
    for ancestor in reversed((path, *path.parents)):
        if ancestor.exists() or ancestor.is_symlink():
            if _reparse(ancestor):
                raise DistributionError("symlink/junction root or ancestor is not allowed")
    if must_exist and not path.is_dir():
        raise DistributionError("root must be an existing directory")
    return path.resolve(strict=must_exist)


def _file(root: Path, relative: str) -> Path:
    relative_path(relative)
    root = _root(root)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if not current.exists() or _reparse(current):
            raise DistributionError("symlink/junction source is not allowed")
    if not current.resolve(strict=True).is_relative_to(root) or not current.is_file():
        raise DistributionError("source is outside root or not a file")
    return current


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args],
                              capture_output=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise DistributionError("unable to read source Git object") from exc


def _source(root: Path, commit: str | None):
    root = _root(root)
    if commit is not None:
        if not _object(commit):
            raise DistributionError("committed source requires an exact Git commit hash")
        if _git(root, "rev-parse", commit + "^{commit}").decode().strip() != commit:
            raise DistributionError("not the specified commit")
        tree = _git(root, "rev-parse", commit + "^{tree}").decode().strip()

        def read(relative: str) -> bytes:
            relative_path(relative)
            entry = _git(root, "ls-tree", commit, "--", relative).decode().strip()
            if not entry.startswith(("100644 blob ", "100755 blob ")):
                raise DistributionError("missing or linked Git source: " + relative)
            return _git(root, "show", commit + ":" + relative)

        return read, {"kind": "git_commit", "commit": commit, "tree": tree}
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    return lambda relative: _file(root, relative).read_bytes(), {
        "kind": "candidate_file_snapshot", "base_commit": head, "base_tree": tree,
        "scope": "explicit product files; not a committed tree or entire worktree"}


def _unique(data: bytes, marker: str) -> int:
    encoded = marker.encode("utf-8")
    if data.count(encoded) != 1:
        raise DistributionError("missing or duplicate source marker: " + marker)
    return data.index(encoded)


def _section(data: bytes, spec: dict[str, str]) -> bytes:
    heading = ("## " + spec["title"]).encode("utf-8")
    matches = list(re.finditer(rb"(?m)^" + re.escape(heading) + rb"\r?$", data))
    if len(matches) != 1:
        raise DistributionError("missing or duplicate section: " + spec["title"])
    start = matches[0].start()
    following = re.search(rb"(?m)^## ", data[matches[0].end():])
    end = matches[0].end() + following.start() if following else len(data)
    section = data[start:end]
    if spec.get("end_before"):
        section = section[:_unique(section, spec["end_before"])]
    if spec.get("body_start"):
        position = _unique(section, spec["body_start"])
        section = section[:section.index(b"\n") + 1] + b"\n" + section[position:]
    return section


def _portable_links(data: bytes) -> bytes:
    names = {"Workflow_Protocol.md", "Execution_Context_and_Model_Policy.md", "Workspace_and_Record_Lifecycle.md"}

    def rewrite(match: re.Match[str]) -> str:
        label, target = match.groups()
        name = target.split("#", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
        if name in names:
            anchor = "#" + target.split("#", 1)[1] if "#" in target else ""
            return f"[{label}]({name}{anchor})"
        return f"{label} (source provenance: {target})"

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", rewrite, data.decode("utf-8")).encode("utf-8")


def _official(root: Path, specs: list[dict[str, Any]]) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    files, identities = {}, []
    for spec in specs:
        key = relative_path(spec["source"])
        raw = _file(root, key).read_bytes()
        if not _digest(spec["sha256"]) or sha256(raw) != spec["sha256"]:
            raise DistributionError("official source digest mismatch: " + key)
        output = relative_path(spec["output"])
        prefix = f"# LoomMode official material — {spec['name']}\n\nGenerated from `{key}`; source SHA-256 `{spec['sha256']}`. Canonical authority remains at its approved source. Project paths and source examples do not select runtime files or grant permissions.\n\n".encode("utf-8")
        slices = []
        if spec["kind"] == "role":
            begin = _unique(raw, "## Part I — Fixed Role Definition")
            end = _unique(raw, "## Part II — Long-term Role Experience")
            if begin >= end:
                raise DistributionError("invalid role boundaries")
            body = raw[begin:end]
            slices.append({"selector": "Part I exact bytes", "sha256": sha256(body)})
            value = prefix + body + "## Part II — Long-term Role Experience\n\nProject experience is supplied separately by the project Host; no source-project experience is included.\n".encode("utf-8")
        elif spec["kind"] == "policy":
            sections = [_section(raw, section) for section in spec["sections"]]
            slices = [{"selector": section["title"], "sha256": sha256(value)} for section, value in zip(spec["sections"], sections)]
            body = b"\n".join(sections)
            for literal in spec.get("omit_literals", []):
                _unique(body, literal)
                body = body.replace(literal.encode("utf-8"), b"")
            for guard in spec["required_guards"]:
                if guard.encode("utf-8") not in body:
                    raise DistributionError("required policy guard absent: " + guard)
            for replacement in spec.get("replace_literals", []):
                _unique(body, replacement["source"])
                body = body.replace(replacement["source"].encode("utf-8"), replacement["replacement"].encode("utf-8"))
            value = prefix + _portable_links(body)
        else:
            raise DistributionError("unknown official projection kind")
        if output in files:
            raise DistributionError("duplicate official output")
        files[output] = value
        identities.append({"source": key, "source_sha256": sha256(raw), "output": output,
                           "slices": slices, "output_sha256": sha256(value)})
    return files, identities


def _compatibility(value: Any, release_version: str | None = None):
    """Validate declaration identity, never release permission or admission.

    A trusted Host judges the referenced documents' authority and scope. This
    validator does not infer approval from prose or unpinned payload metadata.
    """
    if not isinstance(value, dict) or type(value.get("breaking_changes")) is not bool:
        raise DistributionError("explicit boolean Breaking declaration missing/invalid")
    if any(type(value.get(key)) is not type(expected) for key, expected in _COMPATIBILITY.items()):
        raise DistributionError("invalid compatibility field type")
    if value["breaking_changes"] is False:
        if value != _COMPATIBILITY:
            raise DistributionError("unsupported workflow/schema/permission compatibility")
        return None
    review = value.get("breaking_review")
    required = {"release_version", "baseline_version", "changes", "migration_review", "owner_authorization"}
    if not isinstance(review, dict) or set(review) not in (required, required | {"version_exception"}):
        raise DistributionError("Migration Review and Owner scope references required for Breaking metadata")
    target, baseline = semver(review["release_version"]), semver(review["baseline_version"])
    if "version_exception" in review:
        # Exact Owner-approved historical-special version-number exceptions only.
        # Its digest is provenance, not publisher authentication or project access.
        if (target, baseline) not in {((1, 3, 0), (1, 2, 1)), ((1, 3, 1), (1, 2, 1)), ((1, 3, 2), (1, 2, 1)), ((1, 3, 3), (1, 2, 1)), ((1, 4, 0), (1, 2, 1)), ((1, 5, 0), (1, 2, 1))}:
            raise DistributionError("version exception is limited to 1.3.0, 1.3.1, 1.3.2, 1.3.3, 1.4.0 or 1.5.0 from 1.2.1")
    elif target[0] <= baseline[0]:
        raise DistributionError("Breaking Major review/source version or baseline mismatch")
    if release_version is not None and review["release_version"] != release_version:
        raise DistributionError("Breaking Major review/source version or baseline mismatch")
    changes = review["changes"]
    if (not isinstance(changes, list) or not changes
            or any(not isinstance(item, str) or not item.strip() for item in changes)
            or len(set(changes)) != len(changes)):
        raise DistributionError("explicit nonempty distinct Breaking changes required")
    for name in ("migration_review", "owner_authorization", *(["version_exception"] if "version_exception" in review else [])):
        ref = review[name]
        if not isinstance(ref, dict) or set(ref) != {"record", "sha256"} or not _digest(ref["sha256"]):
            raise DistributionError("digest-pinned Migration Review and Owner scope records required")
        relative_path(ref["record"])
    expected = {**_COMPATIBILITY, "breaking_changes": True, "breaking_review": review}
    if value != expected:
        raise DistributionError("unsupported workflow/schema/permission compatibility")
    return review


def _breaking_authorities(official_root: Path, compatibility: dict[str, Any]) -> None:
    """Check exact Records bytes; do not distribute internal process bodies."""
    review = _compatibility(compatibility)
    if review is not None:
        for name in ("migration_review", "owner_authorization", *(["version_exception"] if "version_exception" in review else [])):
            ref = review[name]
            if sha256(_file(official_root, ref["record"]).read_bytes()) != ref["sha256"]:
                raise DistributionError("Breaking authority record digest mismatch: " + name)


def _recipe(raw: bytes) -> dict[str, Any]:
    recipe = _json(raw)
    if recipe.get("schema_version") != 1 or recipe.get("recipe_id") != "loommode-core-v1":
        raise DistributionError("unsupported recipe")
    paths = _paths(recipe.get("files"))
    required = {RECIPE_PATH, HISTORY_PATH, "src/loommode/version.py", "pyproject.toml"}
    if not required.issubset(paths) or MANIFEST_NAME in paths:
        raise DistributionError("recipe omits core identity or includes manifest")
    specs = recipe.get("official")
    if not isinstance(specs, list) or len(specs) != len(_OFFICIAL):
        raise DistributionError("four roles and three policies required")
    names = []
    for spec in specs:
        if not isinstance(spec, dict) or spec.get("name") not in _OFFICIAL:
            raise DistributionError("unknown official material")
        names.append(spec["name"])
        if (spec.get("kind"), spec.get("source"), spec.get("output")) != _OFFICIAL[spec["name"]] or not _digest(spec.get("sha256")):
            raise DistributionError("invalid official identity")
        if spec["kind"] == "policy":
            sections = spec.get("sections")
            guards = spec.get("required_guards")
            if not isinstance(sections, list) or not sections or not isinstance(guards, list) or not guards:
                raise DistributionError("explicit policy sections and guards required")
            if any(not isinstance(section, dict) or not isinstance(section.get("title"), str)
                   or not section["title"] or set(section) - {"title", "end_before", "body_start"}
                   or any(not isinstance(value, str) or not value for value in section.values()) for section in sections):
                raise DistributionError("invalid policy selector")
            if len({section["title"] for section in sections}) != len(sections):
                raise DistributionError("duplicate policy selector")
            if any(not isinstance(guard, str) or not guard for guard in guards):
                raise DistributionError("invalid policy guard")
    if len(set(names)) != len(_OFFICIAL):
        raise DistributionError("duplicate official material")
    _compatibility(recipe.get("compatibility"))
    _paths(paths + [spec["output"] for spec in specs])
    return recipe


def _inventory(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [{"path": path, "bytes": len(files[path]), "sha256": sha256(files[path])} for path in _paths(list(files))]


def _version(raw: bytes) -> str:
    tree = ast.parse(raw.decode("utf-8"))
    values = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    if len(values) != 1:
        raise DistributionError("one literal product version required")
    semver(values[0])
    return values[0]


def _prepare(dev_root: Path, official_root: Path, source_commit: str | None,
             candidate_snapshot: bool) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Read the exact source and pinned projections without allocating output."""
    if (source_commit is None) == (not candidate_snapshot):
        raise DistributionError("select exactly one committed source or explicit candidate snapshot")
    read, source = _source(dev_root, source_commit)
    recipe_raw = read(RECIPE_PATH)
    recipe = _recipe(recipe_raw)
    paths = _paths(recipe["files"])
    required = {RECIPE_PATH, HISTORY_PATH, "src/loommode/version.py", "pyproject.toml"}
    if not required.issubset(paths) or MANIFEST_NAME in paths:
        raise DistributionError("recipe omits core identity or includes manifest")
    if source_commit is not None:
        production={line.decode('utf8') for line in _git(dev_root,'ls-tree','-r','--name-only','-z',source_commit,'--','src/loommode').split(bytes([0])) if line and line.endswith(b'.py')}
    else:
        production={p.relative_to(_root(dev_root)).as_posix() for p in (_root(dev_root)/'src/loommode').rglob('*.py')}
    declared={p for p in paths if p.startswith('src/loommode/') and p.endswith('.py')}
    if not production or declared!=production:raise DistributionError('recipe must exactly cover production Python closure')
    files = {path: read(path) for path in paths}
    if files[RECIPE_PATH] != recipe_raw:
        raise DistributionError("recipe changed during snapshot")
    version = _version(files["src/loommode/version.py"])
    _compatibility(recipe["compatibility"], version)
    if version != __version__:
        raise DistributionError("generator and source product version differ")
    packaging = tomllib.loads(files["pyproject.toml"].decode("utf-8"))
    if "version" in packaging["project"] or packaging["tool"]["setuptools"]["dynamic"]["version"] != {"attr": "loommode.version.__version__"}:
        raise DistributionError("packaging must read the single version source")
    _breaking_authorities(official_root, recipe["compatibility"])
    source["files_sha256"] = sha256(canonical_json(_inventory(files)))
    if candidate_snapshot:
        source["snapshot_sha256"] = source["files_sha256"]
    generated, official = _official(official_root, recipe["official"])
    if set(generated) & set(files):
        raise DistributionError("official/development file collision")
    files.update(generated)
    entries = _inventory(files)
    manifest = {"schema_version": 1, "release_version": version, "release_status": "CANDIDATE",
                "acceptance": {"status": "PENDING", "reference": None}, "source": source,
                "recipe": {"id": recipe["recipe_id"], "sha256": sha256(recipe_raw)},
                "official_inputs": official, "files": entries,
                "payload_sha256": sha256(canonical_json(entries)),
                "compatibility": recipe["compatibility"]}
    return files, manifest


def _write_payload(target: Path, files: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, Any]:
    try:
        target.mkdir()  # Exclusive allocation; partial evidence is never deleted.
    except FileExistsError as exc:
        raise DistributionError("release target already exists; no overwrite") from exc
    for path, value in files.items():
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(value)
    encoded = canonical_json(manifest)
    with (target / MANIFEST_NAME).open("xb") as stream:
        stream.write(encoded)
    return verify_distribution(target, expected_manifest_sha256=sha256(encoded))


def build_candidate(dev_root: Path, official_root: Path, distribution_root: Path, *,
                    source_commit: str | None = None, candidate_snapshot: bool = False) -> dict[str, Any]:
    """Generate one immutable candidate in .staging; existing targets are refused.

    Snapshot mode must be explicit. No wall-clock timestamp or physical source
    root enters identity, so identical inputs reproduce identical bytes.
    """
    files, manifest = _prepare(dev_root, official_root, source_commit, candidate_snapshot)
    manifest_hash = sha256(canonical_json(manifest))
    root = _root(distribution_root, must_exist=False)
    root.mkdir(parents=True, exist_ok=True)
    root = _root(root)
    staging = root / ".staging"
    if staging.exists() and _reparse(staging):
        raise DistributionError("linked staging root")
    staging.mkdir(exist_ok=True)
    target = staging / f"{manifest['release_version']}-candidate-{manifest_hash}"
    return _write_payload(target, files, manifest)


def publish_accepted(dev_root: Path, official_root: Path, distribution_root: Path, *,
                     source_commit: str, acceptance_record: Path, acceptance_record_id: str,
                     expected_acceptance_sha256: str, expected_recipe_sha256: str,
                     expected_payload_sha256: str, expected_source_files_sha256: str) -> dict[str, Any]:
    """Trusted Host publication after explicit formal acceptance, never an upgrade.

    The Host must establish that the immutable record approves this exact source
    and these pins. Hash/schema checks do not authenticate an authority or infer
    permission from a document. No candidate is modified or copied as source.
    """
    pins = (expected_acceptance_sha256, expected_recipe_sha256, expected_payload_sha256,
            expected_source_files_sha256)
    if not all(_digest(pin) for pin in pins):
        raise DistributionError("explicit accepted record/recipe/payload/source pins required")
    relative_path(acceptance_record_id)
    record_path = _file(Path(acceptance_record).absolute().parent, Path(acceptance_record).name)
    if sha256(record_path.read_bytes()) != expected_acceptance_sha256:
        raise DistributionError("formal acceptance record digest mismatch")
    files, manifest = _prepare(dev_root, official_root, source_commit, False)
    if (manifest["source"]["kind"] != "git_commit"
            or manifest["recipe"]["sha256"] != expected_recipe_sha256
            or manifest["payload_sha256"] != expected_payload_sha256
            or manifest["source"]["files_sha256"] != expected_source_files_sha256):
        raise DistributionError("source/recipe/payload differs from trusted Host acceptance pins")
    if sha256(record_path.read_bytes()) != expected_acceptance_sha256:
        raise DistributionError("formal acceptance record changed during generation")
    manifest["release_status"] = "ACCEPTED"
    manifest["acceptance"] = {"status": "ACCEPTED", "reference": {
        "record": acceptance_record_id, "sha256": expected_acceptance_sha256, "decision": "ACCEPTED"}}
    root = _root(distribution_root, must_exist=False)
    root.mkdir(parents=True, exist_ok=True)
    root = _root(root)
    return _write_payload(root / manifest["release_version"], files, manifest)


def verify_distribution(root: Path, *, expected_manifest_sha256: str | None = None) -> dict[str, Any]:
    """Verify exact files and integrity. This does not establish official acceptance."""
    root = _root(root)
    raw = _file(root, MANIFEST_NAME).read_bytes()
    actual_manifest_hash = sha256(raw)
    if expected_manifest_sha256 is not None and actual_manifest_hash != expected_manifest_sha256:
        raise DistributionError("manifest digest mismatch")
    manifest = _json(raw)
    if manifest.get("schema_version") != 1:
        raise DistributionError("unknown manifest schema")
    acceptance = manifest.get("acceptance")
    if manifest.get("release_status") == "CANDIDATE" and acceptance == {"status": "PENDING", "reference": None}:
        acceptance_status = "PENDING"
    elif manifest.get("release_status") == "ACCEPTED" and isinstance(acceptance, dict) and set(acceptance) == {"status", "reference"} and acceptance["status"] == "ACCEPTED":
        ref = acceptance["reference"]
        if (not isinstance(ref, dict) or set(ref) != {"record", "sha256", "decision"}
                or not isinstance(ref["record"], str) or not ref["record"].strip() or not _digest(ref["sha256"])
                or ref["decision"] != "ACCEPTED" or manifest.get("source", {}).get("kind") != "git_commit"):
            raise DistributionError("incomplete acceptance reference or noncommitted accepted source")
        acceptance_status = "ACCEPTED"
    else:
        raise DistributionError("unaccepted/unknown release metadata")
    semver(manifest["release_version"])
    _compatibility(manifest.get("compatibility"), manifest["release_version"])
    entries = manifest.get("files")
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise DistributionError("invalid manifest inventory")
    names = _paths([entry["path"] for entry in entries])
    if MANIFEST_NAME in names or entries != sorted(entries, key=lambda entry: entry["path"]):
        raise DistributionError("noncanonical manifest file list")
    expected_dirs = {str(parent) for name in names for parent in PurePosixPath(name).parents if str(parent) != "."}
    actual_files, actual_dirs = set(), set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if _reparse(path):
                raise DistributionError("symlink/junction payload is not allowed")
            rel = path.relative_to(root).as_posix()
            (actual_dirs if path.is_dir() else actual_files).add(rel)
    if actual_files != set(names) | {MANIFEST_NAME} or actual_dirs != expected_dirs:
        raise DistributionError("missing, additional, or mismatched payload paths")
    for entry in entries:
        if set(entry) != {"path", "bytes", "sha256"} or type(entry["bytes"]) is not int or entry["bytes"] < 0 or not _digest(entry["sha256"]):
            raise DistributionError("invalid file identity")
        data = _file(root, entry["path"]).read_bytes()
        if len(data) != entry["bytes"] or sha256(data) != entry["sha256"]:
            raise DistributionError("file digest/size mismatch: " + entry["path"])
    if sha256(canonical_json(entries)) != manifest["payload_sha256"]:
        raise DistributionError("payload identity mismatch")
    if _version(_file(root, "src/loommode/version.py").read_bytes()) != manifest["release_version"]:
        raise DistributionError("manifest/product version mismatch")
    recipe_raw = _file(root, RECIPE_PATH).read_bytes()
    recipe = _recipe(recipe_raw)
    if manifest["compatibility"] != recipe["compatibility"]:
        raise DistributionError("manifest/recipe compatibility mismatch")
    if manifest.get("recipe") != {"id": recipe["recipe_id"], "sha256": sha256(recipe_raw)}:
        raise DistributionError("recipe identity mismatch")
    source_entries = [entry for entry in entries if entry["path"] in recipe["files"]]
    if set(names) != set(recipe["files"]) | {spec["output"] for spec in recipe["official"]}:
        raise DistributionError("manifest/recipe inventory mismatch")
    source = manifest.get("source", {})
    if not isinstance(source, dict) or source.get("files_sha256") != sha256(canonical_json(source_entries)):
        raise DistributionError("source inventory digest mismatch")
    if source.get("kind") == "candidate_file_snapshot":
        if not _object(source.get("base_commit")) or not _object(source.get("base_tree")) or source.get("snapshot_sha256") != source["files_sha256"]:
            raise DistributionError("invalid candidate snapshot identity")
    elif source.get("kind") == "git_commit":
        if not _object(source.get("commit")) or not _object(source.get("tree")) or "snapshot_sha256" in source:
            raise DistributionError("invalid committed source identity")
    else:
        raise DistributionError("unknown source identity")
    officials = manifest.get("official_inputs")
    if not isinstance(officials, list) or len(officials) != len(recipe["official"]):
        raise DistributionError("invalid official inventory")
    for official, spec in zip(officials, recipe["official"]):
        if (official.get("source"), official.get("source_sha256"), official.get("output")) != (spec["source"], spec["sha256"], spec["output"]):
            raise DistributionError("official source/recipe identity mismatch")
        if not _digest(official.get("output_sha256")) or not isinstance(official.get("slices"), list) or not official["slices"]:
            raise DistributionError("invalid official slice identity")
        if any(not isinstance(item, dict) or not isinstance(item.get("selector"), str) or not _digest(item.get("sha256")) for item in official["slices"]):
            raise DistributionError("invalid official slice digest")
        if sha256(_file(root, official["output"]).read_bytes()) != official["output_sha256"]:
            raise DistributionError("official material mismatch")
    return {"root": str(root), "release_version": manifest["release_version"], "release_status": manifest["release_status"],
            "manifest_sha256": actual_manifest_hash, "payload_sha256": manifest["payload_sha256"],
            "source": manifest["source"], "file_count": len(entries), "integrity": "PASS",
            "acceptance": acceptance_status, "project_validation": "NOT_PERFORMED"}


def verify_historical_identity(dev_root: Path, records_root: Path, history_root: Path) -> dict[str, Any]:
    """Validate the controlled historical designation without rewriting old bytes."""
    data = _json(_file(dev_root, HISTORY_PATH).read_bytes())
    if data.get("schema_version") != 1 or data.get("release_status") != "HISTORICAL_DESIGNATION" or data.get("release_version") != "1.0.0" or data.get("legacy_implementation_version") != "0.1.0":
        raise DistributionError("invalid historical designation")
    source = data["source"]
    _, resolved = _source(dev_root, source["commit"])
    if resolved["tree"] != source["tree"]:
        raise DistributionError("historical Git tree mismatch")
    if len(data["official_inputs"]) != 9:
        raise DistributionError("nine historical official inputs required")
    for item in data["official_inputs"] + data["acceptance_refs"]:
        roots = {"Records": records_root, "History": history_root}
        if item["workspace"] not in roots or sha256(_file(roots[item["workspace"]], item["path"]).read_bytes()) != item["sha256"]:
            raise DistributionError("historical material digest mismatch")
    return {"release_version": data["release_version"], "release_status": data["release_status"],
            "legacy_implementation_version": data["legacy_implementation_version"],
            "source": source, "official_inputs": 9, "integrity": "PASS", "historical_payload": "NOT_CREATED"}
