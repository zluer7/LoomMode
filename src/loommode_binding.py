"""Opt-in local binding guard. Standard library only; never imports LoomMode until bootstrap.

The Host owns trusted release/lock inputs and supplies validation evidence. Hashes
prove identity, not authorization. Activation assumes one authorized Host writer.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROLES = ("Promoter", "Constraint", "Discussant", "Decision")
POLICIES = ("Workflow_Protocol", "Execution_Context_and_Model_Policy", "Workspace_and_Record_Lifecycle")


class BindingError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BindingError("duplicate JSON key")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise BindingError("invalid JSON") from exc
    if not isinstance(result, dict):
        raise BindingError("JSON object required")
    return result


def version(value):
    if not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise BindingError("exact numeric X.Y.Z required")
    return tuple(map(int, value.split(".")))


def requested_bounds(requested):
    if isinstance(requested, str):
        exact = version(requested)
        return exact, exact, True
    if not isinstance(requested, dict) or set(requested) != {"minimum", "maximum_exclusive"}:
        raise BindingError("exact version or one explicit [minimum, maximum_exclusive) interval required")
    lower, upper = version(requested["minimum"]), version(requested["maximum_exclusive"])
    if lower >= upper:
        raise BindingError("empty version interval")
    return lower, upper, False


def _relative(value):
    if not isinstance(value, str) or not value or re.search(r'[\\:<>"|?*\x00-\x1f]', value):
        raise BindingError("invalid relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") or part.endswith((".", " ")) or
           re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part) for part in parts):
        raise BindingError("noncanonical relative path")
    return value


def _linked(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _root(path):
    path = Path(path).absolute()
    for ancestor in reversed((path, *path.parents)):
        if (ancestor.exists() or ancestor.is_symlink()) and _linked(ancestor):
            raise BindingError("symlink/junction root or ancestor")
    if not path.is_dir():
        raise BindingError("explicit existing root required")
    return path.resolve(strict=True)


def _file(root, relative, *, allow_missing=False):
    root = _root(root)
    path = root
    for part in PurePosixPath(_relative(relative)).parts:
        path /= part
        if (path.exists() or path.is_symlink()) and _linked(path):
            raise BindingError("symlink/junction path")
    if not path.resolve().is_relative_to(root):
        raise BindingError("path escaped root")
    if not path.is_file() and not (allow_missing and not path.exists()):
        raise BindingError("required file missing or wrong type")
    return path


def validate_release_status(manifest):
    """Shared metadata boundary; accepted references are trusted Host provenance."""
    status, acceptance = manifest.get("release_status"), manifest.get("acceptance")
    if status == "CANDIDATE" and acceptance == {"status": "PENDING", "reference": None}:
        return "PENDING"
    if status == "ACCEPTED" and isinstance(acceptance, dict) and set(acceptance) == {"status", "reference"} and acceptance["status"] == "ACCEPTED":
        ref = acceptance["reference"]
        if (isinstance(ref, dict) and set(ref) == {"record", "sha256", "decision"}
                and isinstance(ref["record"], str) and ref["record"].strip()
                and _sha(ref["sha256"]) and ref["decision"] == "ACCEPTED"
                and manifest.get("source", {}).get("kind") == "git_commit"):
            return "ACCEPTED"
    raise BindingError("unaccepted/incomplete release metadata or noncommitted accepted source")


def _compatibility(compat, release_version):
    """Stdlib contract check, retaining historical tested-binary metadata.

    Integrity inspection is independent of permission to import or activate.
    Referenced release-scope records are provenance, never project admission.
    """
    expected = {"workflow_contract": "V1_ACCEPTED_WITH_LIMITS", "state_schema_version": 1,
                "context_schema_version": 1, "codex_tested_versions": ["0.159.2", "0.160.0"],
                "permission_semantics": "UNCHANGED", "breaking_changes": False}
    if (not isinstance(compat, dict) or type(compat.get("breaking_changes")) is not bool
            or any(type(compat.get(key)) is not type(value) for key, value in expected.items())):
        raise BindingError("Migration Review required: invalid compatibility declaration")
    tested = compat["codex_tested_versions"]
    if (not tested or any(not isinstance(item, str) for item in tested) or len(set(tested)) != len(tested)):
        raise BindingError("invalid tested Codex version metadata")
    for item in tested:
        version(item)
    # Tested binaries are release-specific facts, not the current checkout's
    # contract constant (accepted 1.0.1 records only 0.159.2).
    expected["codex_tested_versions"] = tested
    if compat["breaking_changes"]:
        review = compat.get("breaking_review")
        fields = {"release_version", "baseline_version", "changes", "migration_review", "owner_authorization"}
        if not isinstance(review, dict) or set(review) not in (fields, fields | {"version_exception"}):
            raise BindingError("Migration Review and Owner scope required for Breaking declaration")
        target, baseline = version(review["release_version"]), version(review["baseline_version"])
        if (review["release_version"] != release_version
                or ("version_exception" in review and (target, baseline) not in
                    {((1, 3, 0), (1, 2, 1)), ((1, 3, 1), (1, 2, 1)), ((1, 3, 2), (1, 2, 1)), ((1, 3, 3), (1, 2, 1)), ((1, 4, 0), (1, 2, 1)), ((1, 5, 0), (1, 2, 1))})
                or ("version_exception" not in review and target[0] <= baseline[0])):
            raise BindingError("Migration Review declaration version/baseline mismatch")
        changes = review["changes"]
        if (not isinstance(changes, list) or not changes
                or any(not isinstance(item, str) or not item.strip() for item in changes)
                or len(set(changes)) != len(changes)):
            raise BindingError("Migration Review requires distinct nonempty changes")
        for name in ("migration_review", "owner_authorization", *(["version_exception"] if "version_exception" in review else [])):
            ref = review[name]
            if not isinstance(ref, dict) or set(ref) != {"record", "sha256"} or not _sha(ref["sha256"]):
                raise BindingError("Migration Review requires digest-pinned scope records")
            _relative(ref["record"])
        expected.update(breaking_changes=True, breaking_review=review)
    if compat != expected:
        raise BindingError("Migration Review required for unsupported workflow/schema/permission change")


def _verified_payload(root, pin=None, *, candidate=False):
    """Verify all bytes and paths before executing any payload Python code."""
    root = _root(root)
    raw = _file(root, "release.json").read_bytes()
    actual_pin = digest(raw)
    if pin is not None and (not _sha(pin) or actual_pin != pin):
        raise BindingError("manifest pin mismatch")
    m = _json(raw)
    status=validate_release_status(m)
    if m.get("schema_version") != 1 or status != ("PENDING" if candidate else "ACCEPTED"):
        raise BindingError("candidate requires CANDIDATE/PENDING; production requires ACCEPTED")
    if candidate and (root.parent.name!='.staging' or root.name!=m['release_version']+'-candidate-'+actual_pin):
        raise BindingError('candidate must be its exact exclusively built staging payload')
    version(m["release_version"])
    compat = m.get("compatibility", {})
    _compatibility(compat, m["release_version"])
    entries = m.get("files")
    if not isinstance(entries, list) or not entries:
        raise BindingError("explicit inventory required")
    spellings, files, dirs = {}, set(), set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} or type(item["bytes"]) is not int or item["bytes"] < 0 or not _sha(item["sha256"]):
            raise BindingError("invalid file inventory")
        name = _relative(item["path"])
        if name in files or name == "release.json":
            raise BindingError("duplicate/reserved payload file")
        files.add(name)
        parts = PurePosixPath(name).parts
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            if spellings.setdefault(prefix.casefold(), prefix) != prefix:
                raise BindingError("case collision")
        dirs.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
        data = _file(root, name).read_bytes()
        if len(data) != item["bytes"] or digest(data) != item["sha256"]:
            raise BindingError("payload file size/digest mismatch")
    if files & dirs or entries != sorted(entries, key=lambda item: item["path"]):
        raise BindingError("inventory collision/order")
    actual_files, actual_dirs = set(), set()
    for directory, child_dirs, child_files in os.walk(root, followlinks=False):
        for name in child_dirs + child_files:
            path = Path(directory) / name
            if _linked(path):
                raise BindingError("linked payload")
            (actual_dirs if path.is_dir() else actual_files).add(path.relative_to(root).as_posix())
    if actual_files != files | {"release.json"} or actual_dirs != dirs or digest(canonical(entries)) != m.get("payload_sha256"):
        raise BindingError("missing/extra payload or inventory identity mismatch")
    recipe_raw = _file(root, "config/distribution.recipe.json").read_bytes()
    recipe = _json(recipe_raw)
    if compat != recipe.get("compatibility"):
        raise BindingError("manifest/recipe compatibility mismatch; Migration Review cannot be bypassed")
    recipe_files = recipe.get("files")
    if (recipe.get("schema_version") != 1 or recipe.get("recipe_id") != "loommode-core-v1"
            or not isinstance(recipe_files, list) or not recipe_files
            or any(not isinstance(name, str) for name in recipe_files)
            or len({name.casefold() for name in recipe_files}) != len(recipe_files)):
        raise BindingError("invalid source recipe inventory")
    if m.get("recipe") != {"id": recipe.get("recipe_id"), "sha256": digest(recipe_raw)}:
        raise BindingError("recipe identity mismatch")
    source = m["source"]
    selected = [item for item in entries if item["path"] in recipe.get("files", [])]
    if (not re.fullmatch(r"[0-9a-f]{40}", source.get("commit", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", source.get("tree", ""))
            or source.get("files_sha256") != digest(canonical(selected)) or "snapshot_sha256" in source):
        raise BindingError("committed source identity mismatch")
    officials = m.get("official_inputs", [])
    specs = recipe.get("official", [])
    expected = {f"official/roles/{name}.md" for name in ROLES} | {f"official/policy/{name}.md" for name in POLICIES}
    if (not isinstance(officials, list) or not isinstance(specs, list) or len(officials) != 7 or len(specs) != 7
            or any(not isinstance(item, dict) for item in officials + specs)
            or {item.get("output") for item in officials} != expected or files != set(recipe_files) | expected):
        raise BindingError("official/inventory closure mismatch")
    for item, spec in zip(officials, specs):
        if (item.get("source"), item.get("source_sha256"), item.get("output")) != (spec.get("source"), spec.get("sha256"), spec.get("output")):
            raise BindingError("official source identity differs from pinned recipe")
        if not _sha(item.get("source_sha256")) or digest(_file(root, item["output"]).read_bytes()) != item.get("output_sha256"):
            raise BindingError("official text digest mismatch")
    tree = ast.parse(_file(root, "src/loommode/version.py").read_text(encoding="utf-8"))
    values = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
              and isinstance(node.value, ast.Constant) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
    if values != [m["release_version"]]:
        raise BindingError("runtime version source mismatch")
    return root, m, actual_pin


def _release(root, pin=None):
    return _verified_payload(root,pin)


def _candidate_release(root,pin):
    if not _sha(pin):raise BindingError('trusted exact candidate manifest pin required')
    return _verified_payload(root,pin,candidate=True)


def _request(project_root, request_path):
    path = _file(project_root, request_path)
    raw = path.read_bytes()
    data = _json(raw)
    if set(data) != {"schema_version", "requested", "overlay"} or data["schema_version"] != 1:
        raise BindingError("unsupported request; validation belongs to trusted Host evidence")
    requested_bounds(data["requested"])
    overlay = data["overlay"]
    if not isinstance(overlay, dict) or set(overlay) != {"authority", "mapping", "roles"}:
        raise BindingError("explicit overlay categories required")
    if not isinstance(overlay["roles"], dict) or set(overlay["roles"]) != set(ROLES):
        raise BindingError("four explicit project role experience references required")
    refs = []
    for category in ("authority", "mapping"):
        if not isinstance(overlay[category], list):
            raise BindingError("overlay lists required")
        refs.extend((category, relative) for relative in overlay[category])
    refs.extend(("role:" + role, overlay["roles"][role]) for role in ROLES)
    if len({relative.casefold() for _, relative in refs if isinstance(relative, str)}) != len(refs):
        raise BindingError("duplicate overlay references")
    identities = [{"category": category, "path": _relative(relative),
                   "sha256": digest(_file(project_root, relative).read_bytes())} for category, relative in sorted(refs)]
    return data, digest(raw), identities


def _lock_shape(lock):
    if lock.get("schema_version") != 1 or lock.get("status") != "ACTIVATED" or not isinstance(lock.get("identity"), dict):
        raise BindingError("not a Host-activated lock")
    if lock.get("fingerprint") != digest(canonical(lock["identity"])):
        raise BindingError("lock fingerprint mismatch")
    validation = lock.get("validation", {})
    if validation.get("status") != "VALIDATED" or validation.get("fingerprint") != lock["fingerprint"]:
        raise BindingError("project validation missing/stale")
    for key in ("smoke", "compatibility"):
        _check_evidence_ref(validation.get(key))
    if lock["identity"].get("transition") == "MINOR":
        _check_evidence_ref(validation.get("minimal_delta"))
    if lock["identity"].get("compatibility", {}).get("breaking_changes") is True:
        _check_admission(lock["identity"], validation.get("breaking_admission"))


def _prior_lock(project_root, request_path, lock_path):
    """Check old identity without requiring old request bytes to equal new ones."""
    target = _file(project_root, lock_path, allow_missing=True)
    if not target.exists():
        return None, None
    raw = target.read_bytes()
    old = _json(raw)
    _lock_shape(old)
    identity = old["identity"]
    if (identity.get("project_root") != str(project_root) or identity.get("request_path") != request_path
            or identity.get("lock_path") != lock_path):
        raise BindingError("prior lock targets a different project/request/path")
    root, manifest, pin = _release(identity["release_root"], identity["manifest_sha256"])
    expected = {"release_root": str(root), "resolved_version": manifest["release_version"], "manifest_sha256": pin,
                **{key: manifest[key] for key in ("payload_sha256", "source", "recipe", "compatibility", "official_inputs")}}
    if any(identity.get(key) != value for key, value in expected.items()):
        raise BindingError("prior lock release identity mismatch")
    return identity["resolved_version"], digest(raw)


def _identity(project_root, request_path, lock_path, release_root, prior_version, prior_lock_sha256, *, review_only=False, candidate_pin=None):
    project_root = _root(project_root)
    _file(project_root, lock_path, allow_missing=True)
    request, request_sha, overlay = _request(project_root, request_path)
    root, manifest, manifest_sha = (_candidate_release(release_root,candidate_pin) if candidate_pin is not None else _release(release_root))
    lower, upper, exact = requested_bounds(request["requested"])
    resolved = version(manifest["release_version"])
    if not review_only and not (resolved == lower if exact else lower <= resolved < upper):
        raise BindingError("release outside requested version")
    transition = "FIRST"
    if prior_version is not None:
        previous = version(prior_version)
        transition = ("DOWNGRADE" if resolved < previous else "MAJOR" if resolved[0] != previous[0] else
                      "MINOR" if resolved[1] != previous[1] else "PATCH" if resolved[2] != previous[2] else "REVALIDATE")
    return {"project_root": str(project_root), "request_path": _relative(request_path), "lock_path": _relative(lock_path),
            "request_sha256": request_sha, "requested": request["requested"], "release_root": str(root),
            "resolved_version": manifest["release_version"], "manifest_sha256": manifest_sha,
            "payload_sha256": manifest["payload_sha256"], "source": manifest["source"], "recipe": manifest["recipe"],
            "compatibility": manifest["compatibility"], "official_inputs": manifest["official_inputs"], "overlay": overlay,
            "prior_version": prior_version, "prior_lock_sha256": prior_lock_sha256, "transition": transition}


def propose_binding(project_root, release_roots, *, request_path="config/loommode.version.json", lock_path="config/loommode.version.lock.json"):
    """Read explicit roots only. Produce no active lock and perform no smoke commands."""
    project_root = _root(project_root)
    request, _, _ = _request(project_root, request_path)
    lower, upper, exact = requested_bounds(request["requested"])
    matches = []
    for root in release_roots:
        actual, manifest, pin = _release(root)
        selected = version(manifest["release_version"])
        if selected == lower if exact else lower <= selected < upper:
            matches.append((selected, actual, pin))
    if not matches:
        raise BindingError("no explicitly supplied accepted payload satisfies request; no fallback")
    highest = max(item[0] for item in matches)
    choices = [item for item in matches if item[0] == highest]
    if len(choices) != 1:
        raise BindingError("ambiguous exact release roots")
    previous, previous_sha = _prior_lock(project_root, request_path, lock_path)
    identity = _identity(project_root, request_path, lock_path, choices[0][1], previous, previous_sha)
    return {"schema_version": 1, "status": "PROPOSED", "identity": identity,
            "fingerprint": digest(canonical(identity)), "validation": None}


def review_binding(project_root, release_root, *, request_path="config/loommode.version.json", lock_path="config/loommode.version.lock.json"):
    """Inspect one explicit target while retaining the current request and lock.

    No payload import, Writer acquisition, workflow restart or permission grant.
    The target may differ from the current request; this object cannot activate.
    """
    root = _root(project_root)
    previous, previous_sha = _prior_lock(root, request_path, lock_path)
    identity = _identity(root, request_path, lock_path, release_root, previous, previous_sha, review_only=True)
    return {"schema_version": 1, "status": "REVIEW_ONLY", "identity": identity,
            "fingerprint": digest(canonical(identity)), "validation": None}


def _checked_proposal(proposed, *, allow_review=False):
    statuses = {"PROPOSED", "REVIEW_ONLY"} if allow_review else {"PROPOSED"}
    if (not isinstance(proposed, dict) or proposed.get("schema_version") != 1
            or proposed.get("status") not in statuses or not isinstance(proposed.get("identity"), dict)):
        raise BindingError("an unactivated PROPOSED binding is required")
    identity = proposed["identity"]
    try:
        root = _root(identity["project_root"])
        previous, previous_sha = _prior_lock(root, identity["request_path"], identity["lock_path"])
        observed = _identity(root, identity["request_path"], identity["lock_path"], identity["release_root"],
                             previous, previous_sha, review_only=proposed["status"] == "REVIEW_ONLY")
    except (KeyError, TypeError) as exc:
        raise BindingError("incomplete proposed identity") from exc
    if observed != identity or digest(canonical(observed)) != proposed.get("fingerprint"):
        raise BindingError("binding changed or proposed evidence stale")
    return identity


def _activation_transition(identity, admission=None):
    if (identity["transition"] == "MAJOR" and identity["compatibility"]["breaking_changes"]
            and isinstance(admission, dict)):
        _check_admission(identity, admission)  # Exact actual Owner/reviewer bytes before import/activation.
        return
    if identity["transition"] in {"MAJOR", "DOWNGRADE"}:
        raise BindingError("Migration Review required for major change or downgrade; read-only inspection remains available")


def _check_evidence_ref(value):
    if (not isinstance(value, dict) or set(value) != {"status", "reference", "sha256"}
            or value["status"] != "PASS" or not isinstance(value["reference"], str) or not value["reference"].strip()
            or not _sha(value["sha256"])):
        raise BindingError("bounded trusted Host evidence missing/failed")


@dataclass(frozen=True)
class BreakingAdmission:
    """Trusted Host attestation; documents/digests are not signatures or grants.

    BINDING_ONLY covers bounded validation import and version-lock activation.
    The Host authenticates Owner/reviewer scope and the actual Dev workspace.
    """
    fingerprint: str
    workspace: str
    migration_review: dict
    owner_authorization: dict
    operation: str = "BINDING_ONLY"


def _check_admission(identity, admission):
    if (not isinstance(admission, dict)
            or set(admission) != {"fingerprint", "workspace", "migration_review", "owner_authorization", "operation"}
            or admission["fingerprint"] != digest(canonical(identity)) or admission["operation"] != "BINDING_ONLY"
            or not isinstance(admission["workspace"], str)):
        raise BindingError("Breaking activation requires exact Migration Review and Owner binding-only admission")
    workspace = _root(admission["workspace"])
    project = _root(identity["project_root"])
    if str(workspace) != admission["workspace"] or not workspace.is_relative_to(project):
        raise BindingError("admission workspace differs from canonical project workspace")
    for key, origin, decision in (("migration_review", "INDEPENDENT_BINDING_REVIEW", "PASS"),
                                  ("owner_authorization", "OWNER_BINDING_AUTHORIZATION", "APPROVED")):
        ref = admission[key]
        _check_evidence_ref(ref)
        raw = _file(project, ref["reference"]).read_bytes()
        if digest(raw) != ref["sha256"]:
            raise BindingError("Breaking admission evidence bytes changed")
        body = _json(raw)
        expected = {"origin": origin, "decision": decision, "operation": admission["operation"],
                    "fingerprint": admission["fingerprint"], "workspace": admission["workspace"]}
        if any(body.get(name) != value for name, value in expected.items()):
            raise BindingError("Breaking admission evidence identity/scope mismatch")
    return admission


@dataclass(frozen=True)
class HostEvidence:
    """Explicit trusted Host result, never reconstructed from project validated:true."""
    fingerprint: str
    smoke: dict
    compatibility: dict
    minimal_delta: dict | None = None
    breaking_admission: BreakingAdmission | None = None


def _validated_lock(proposed, evidence):
    identity = _checked_proposal(proposed)
    fingerprint = digest(canonical(identity))
    if not isinstance(evidence, HostEvidence) or evidence.fingerprint != fingerprint:
        raise BindingError("binding changed or Host evidence stale")
    _activation_transition(identity, asdict(evidence.breaking_admission)
        if isinstance(evidence.breaking_admission, BreakingAdmission) else None)
    _check_evidence_ref(evidence.smoke)
    _check_evidence_ref(evidence.compatibility)
    if identity["transition"] == "MINOR":
        _check_evidence_ref(evidence.minimal_delta)
    validation = {"status": "VALIDATED", "fingerprint": fingerprint,
                  "smoke": evidence.smoke, "compatibility": evidence.compatibility, "minimal_delta": evidence.minimal_delta}
    if identity["compatibility"]["breaking_changes"]:
        if not isinstance(evidence.breaking_admission, BreakingAdmission):
            raise BindingError("Breaking activation requires typed Migration Review and Owner admission")
        validation["breaking_admission"] = _check_admission(identity, asdict(evidence.breaking_admission))
    return {**proposed, "status": "ACTIVATED", "validation": validation}


def activate_binding(proposed, evidence: HostEvidence):
    """Activate only the version lock; never construct an Engine or restore State.

    Breaking uses the verified target's existing OS Writer on the Host-attested
    Dev workspace, then rechecks all inputs while held. Compatible Hosts retain
    their existing single-writer contract. This is not general CAS/transaction.
    """
    lock = _validated_lock(proposed, evidence)
    if not lock["identity"]["compatibility"]["breaking_changes"]:
        return _write_lock(lock)
    _import_runtime(proposed)
    ownership = importlib.import_module("loommode.host.ownership")
    assert_runtime_origins(proposed)
    lease = ownership.WorkspaceLease(lock["validation"]["breaking_admission"]["workspace"])
    if not lease.acquire():
        raise BindingError("workspace has a live/unknown Writer; binding activation refused")
    try:
        return _write_lock(_validated_lock(proposed, evidence))
    finally:
        lease.release()


def _write_lock(lock):
    identity = lock["identity"]
    target = _file(identity["project_root"], identity["lock_path"], allow_missing=True)
    def check_current():
        current = digest(target.read_bytes()) if target.exists() else None
        if current != identity["prior_lock_sha256"]:
            raise BindingError("lock conflict: existing bytes changed; preserve them")
    check_current()
    if not target.parent.is_dir():
        raise BindingError("Host must create the authorized lock parent first")
    temporary = target.with_name("." + target.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical(lock))
            stream.flush()
            os.fsync(stream.fileno())
        check_current()
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()  # Only the unique file allocated by this invocation.
    return lock


def verify_binding(project_root, *, request_path="config/loommode.version.json", lock_path="config/loommode.version.lock.json"):
    root = _root(project_root)
    lock = _json(_file(root, lock_path).read_bytes())
    _lock_shape(lock)
    identity = lock["identity"]
    if identity.get("project_root") != str(root) or identity.get("request_path") != request_path or identity.get("lock_path") != lock_path:
        raise BindingError("lock targets a different project/request/path")
    observed = _identity(root, request_path, lock_path, identity["release_root"], identity["prior_version"], identity["prior_lock_sha256"])
    _activation_transition(observed, lock["validation"].get("breaking_admission"))
    _release(identity["release_root"], identity["manifest_sha256"])
    if observed != identity:
        raise BindingError("request/release/official/overlay changed: project validation invalid")
    return lock


def assert_runtime_origins(lock):
    root = Path(lock["identity"]["release_root"]) / "src/loommode"
    for name, module in tuple(sys.modules.items()):
        if name == "loommode" or name.startswith("loommode."):
            origin = getattr(module, "__file__", None)
            if not origin or not Path(origin).resolve().is_relative_to(root):
                raise BindingError("existing Dev/other/mixed LoomMode module: " + name)


def _import_runtime(lock):
    assert_runtime_origins(lock)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(lock["identity"]["release_root"]) / "src"))
    runtime = importlib.import_module("loommode")
    expected = Path(lock["identity"]["release_root"]) / "src/loommode/__init__.py"
    if Path(runtime.__file__).resolve() != expected or runtime.__version__ != lock["identity"]["resolved_version"]:
        raise BindingError("actual Python runtime differs from lock")
    assert_runtime_origins(lock)
    return lock, runtime


def bootstrap_for_validation(proposed, *, admission: BreakingAdmission | None = None):
    """Trusted Host smoke only: verified proposed inputs, no activation/validation claim."""
    identity = _checked_proposal(proposed)
    _activation_transition(identity, asdict(admission) if isinstance(admission, BreakingAdmission) else None)
    if identity["compatibility"]["breaking_changes"]:
        if not isinstance(admission, BreakingAdmission):
            raise BindingError("Breaking validation import requires typed Migration Review and Owner admission")
        _check_admission(identity, asdict(admission))
    return _import_runtime(proposed)


def bootstrap(project_root, **paths):
    """Pin bytes before production import and confirm runtime origins/version."""
    return _import_runtime(verify_binding(project_root, **paths))


def runtime_inputs(project_root, *, role, **paths):
    """Read official material and matching project experience separately; no overlay writes."""
    if role not in ROLES:
        raise BindingError("unknown intelligent role")
    lock = verify_binding(project_root, **paths)
    assert_runtime_origins(lock)
    return _material_inputs(lock, role)


def review_inputs(proposed, *, role):
    """Read proposed/inspection materials without payload imports or a Writer."""
    if role not in ROLES:
        raise BindingError("unknown intelligent role")
    _checked_proposal(proposed, allow_review=True)
    return {**_material_inputs(proposed, role), "mode": "READ_ONLY", "activation_permitted": False}


def _material_inputs(lock, role):
    identity = lock["identity"]
    release = Path(identity["release_root"])
    role_files = {name: _file(release, f"official/roles/{name}.md") for name in ROLES}
    materials = {"official-policy:" + name: _file(release, f"official/policy/{name}.md").read_text(encoding="utf-8") for name in POLICIES}
    for ref in identity["overlay"]:
        if not ref["category"].startswith("role:") or ref["category"] == "role:" + role:
            materials["project-overlay:" + ref["category"] + ":" + ref["path"]] = _file(identity["project_root"], ref["path"]).read_text(encoding="utf-8")
    return {"role_files": role_files, "materials": materials, "fingerprint": lock["fingerprint"]}


@dataclass(frozen=True)
class CandidateHostScope:
    """Trusted Host technical input. This is no business/model authorization."""
    source_commit: str
    manifest_sha256: str
    marker_path: str
    marker_sha256: str
    authority_path: str
    authority_sha256: str


def propose_candidate_binding(project_root,release_root,scope: CandidateHostScope,*,request_path='config/loommode.version.json',lock_path='config/loommode.version.lock.json'):
    if type(scope) is not CandidateHostScope:raise BindingError('explicit trusted Host candidate scope required')
    root=_root(project_root)
    if scope.marker_path!='.loommode-project-root':raise BindingError('actual project marker required')
    if not re.fullmatch(r'[0-9a-f]{40}',scope.source_commit):raise BindingError('reviewed committed source required')
    for path,h in ((scope.marker_path,scope.marker_sha256),(scope.authority_path,scope.authority_sha256)):
        if not _sha(h) or digest(_file(root,path).read_bytes())!=h:raise BindingError('candidate marker/authority pin changed')
    request,_,overlay=_request(root,request_path)
    if not any(x=={'category':'authority','path':scope.authority_path,'sha256':scope.authority_sha256} for x in overlay):
        raise BindingError('candidate scope must be a pinned project-local authority overlay')
    previous,prior_sha=_prior_lock(root,request_path,lock_path)
    identity=_identity(root,request_path,lock_path,release_root,previous,prior_sha,candidate_pin=scope.manifest_sha256)
    if identity['source'].get('kind')!='git_commit' or identity['source'].get('commit')!=scope.source_commit:
        raise BindingError('candidate source differs from reviewed commit')
    identity['candidate_scope']=asdict(scope)
    return {'schema_version':1,'status':'CANDIDATE_VALIDATION_ONLY','identity':identity,
        'fingerprint':digest(canonical(identity)),'validation':None,'business_authority':False}


def _checked_candidate(proposed):
    if not isinstance(proposed,dict) or proposed.get('status')!='CANDIDATE_VALIDATION_ONLY' or proposed.get('business_authority') is not False:
        raise BindingError('candidate-only binding required')
    try:
        i=proposed['identity'];scope=CandidateHostScope(**i['candidate_scope'])
        actual=propose_candidate_binding(i['project_root'],i['release_root'],scope,request_path=i['request_path'],lock_path=i['lock_path'])
    except (KeyError,TypeError) as exc:raise BindingError('incomplete candidate identity') from exc
    if actual!=proposed:raise BindingError('stale candidate/overlay/scope identity')
    return i


def bootstrap_candidate_for_validation(proposed,*,admission: BreakingAdmission | None=None,material_mapping_path=None):
    """Candidate import only. Never creates a production ACTIVATED lock."""
    identity=_checked_candidate(proposed)
    value=asdict(admission) if isinstance(admission,BreakingAdmission) else None
    _activation_transition(identity,value)
    if identity['compatibility']['breaking_changes']:
        if not isinstance(admission,BreakingAdmission):raise BindingError('candidate Breaking import needs original Migration/Owner admission')
        _check_admission(identity,value)
    result=_import_runtime(proposed)
    if material_mapping_path is not None:
        rows=[r for r in identity['overlay'] if r['category']=='mapping' and r['path']==material_mapping_path]
        if len(rows)!=1:raise BindingError('material mapping must be a pinned Host mapping overlay')
        from loommode.host.materials import LocalMaterials,install_local_materials
        row=rows[0]
        local=LocalMaterials(identity['project_root'],
            {'path':str(_file(identity['project_root'],row['path'])),'sha256':row['sha256']},allowed_mapping_sha256=row['sha256'])
        frozen_proposal=canonical(proposed)
        local.role_inputs=lambda role:candidate_inputs(_json(frozen_proposal),role=role)
        install_local_materials(local)
    return result


def candidate_inputs(proposed,*,role):
    if role not in ROLES:raise BindingError('unknown intelligent role')
    _checked_candidate(proposed)
    return {**_material_inputs(proposed,role),'mode':'CANDIDATE_VALIDATION_ONLY','business_authority':False}
