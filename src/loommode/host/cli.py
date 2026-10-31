"""A bounded saved-state reader, with explicit identity and project path mapping."""
import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from loommode.codex.context import ContextRegistry
from loommode.codex.errors import LoomModeError
from loommode.roles.contracts import ARTIFACT_KINDS
from loommode.workflow.artifacts import ArtifactStore
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import identity
from .decision import DecisionEntry
from .state_view import StateProjection, saved_state_provider


def _process_store(root: Path, project: str, stage_id: str, tuple_parts: tuple[str, str, str],
                   *, namespace_guard=None) -> ArtifactStore:
    parts = tuple(identity(part) for part in tuple_parts)
    if namespace_guard is not None:
        namespace_guard(root)

    class ProcessStore(ArtifactStore):
        def _guard(self, path: Path) -> Path:
            if namespace_guard is not None:
                namespace_guard(path)
            return super()._guard(path)

        def _directory(self, kind: str) -> Path:
            if kind not in ARTIFACT_KINDS:
                raise WorkflowError("unknown artifact kind")
            bucket = ("Process/Constraints" if kind in {"FINAL_TASK_CONSTRAINT", "PLAN_REFERENCE"} else
                      "Process/Reports" if kind in {"EXECUTION_REPORT", "INDEPENDENT_REVIEW"} else
                      "Stage-Records" if kind in {"STAGE_RECORD", "STAGE_KNOWLEDGE", "ROLE_EXPERIENCE"} else
                      "Issue-Ledger" if kind == "STAGE_ISSUE_LEDGER" else "Process/Working")
            return self._guard(self.root / bucket / Path(*parts))

        def assert_task_reference(self, reference: str, kind: str, task_id: str) -> None:
            suffixes = {"FINAL_TASK_CONSTRAINT": "_Task_Constraint.md", "EXECUTION_REPORT": "_Execution_Report.md"}
            path = self._guard(Path(reference.rsplit("#sha256=", 1)[0]))
            if kind in suffixes and path.name == identity(task_id) + suffixes[kind]:
                if path.parent != self._directory(kind):
                    raise WorkflowError("formal reference belongs to a different Records tuple")
                self.read(reference)
                return
            super().assert_task_reference(reference, kind, task_id)

    return ProcessStore(root, project, stage_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Decision entry; does not run or resume a workflow.")
    parser.add_argument("--project", required=True)
    parser.add_argument("--stage-id", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--records-root", type=Path, required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--registry-file", type=Path)
    parser.add_argument("--layout", choices=("legacy", "process"), required=True)
    parser.add_argument("--cycle")
    parser.add_argument("--group")
    parser.add_argument("--records-stage")
    parser.add_argument("--stage-input-ref")
    parser.add_argument("--stage-input-file", type=Path)
    parser.add_argument("--artifact-ref")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    parts = (args.cycle, args.group, args.records_stage)
    if args.layout == "process" and not all(parts):
        parser.error("process layout requires explicit --cycle, --group and --records-stage")
    if args.layout == "legacy" and any(parts):
        parser.error("Records tuple is only used with process layout")
    if bool(args.stage_input_ref) != bool(args.stage_input_file):
        parser.error("--stage-input-ref and --stage-input-file must be supplied together")
    try:
        artifacts = (_process_store(args.records_root, args.project, args.stage_id, parts)
                     if args.layout == "process" else ArtifactStore(args.records_root, args.project, args.stage_id))
        authority = {args.stage_input_ref: args.stage_input_file.read_text(encoding="utf-8")} if args.stage_input_ref else {}
        registry = ContextRegistry(args.registry_file) if args.registry_file else ContextRegistry()
        source = SimpleNamespace(path=args.state_file, project=args.project, stage_id=args.stage_id)
        entry = DecisionEntry(StateProjection(project=args.project, stage_id=args.stage_id, workspace=args.workspace,
                              artifacts=artifacts, registry=registry, state_provider=saved_state_provider(source),
                              source_ref=str(args.state_file.resolve()), authority_materials=authority))
        if args.artifact_ref:
            print(entry.read_artifact(args.artifact_ref))
        else:
            snapshot = entry.query()
            print(json.dumps(snapshot.as_dict(), ensure_ascii=False, indent=2) if args.as_json else snapshot.summary())
            return 0 if snapshot.view["availability"] == "AVAILABLE" else 2
    except (WorkflowError, LoomModeError, OSError, ValueError, TypeError) as exc:
        print(f"Decision entry unavailable: {exc}")
        return 2
    return 0
