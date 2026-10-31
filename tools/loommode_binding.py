"""Neutral opt-in CLI: stdlib guard verifies locked bytes before importing LoomMode."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # Before the first dynamic guard/payload load.
spec = importlib.util.spec_from_file_location("loommode_binding_guard", Path(__file__).resolve().parents[1] / "src/loommode_binding.py")
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("review", "propose", "verify", "bootstrap"))
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, action="append", default=[])
    parser.add_argument("--request-path", default="config/loommode.version.json")
    parser.add_argument("--lock-path", default="config/loommode.version.lock.json")
    parser.add_argument("--role", choices=guard.ROLES, default="Promoter")
    args = parser.parse_args()
    paths = {"request_path": args.request_path, "lock_path": args.lock_path}
    if args.command == "review":
        if len(args.release_root) != 1:
            parser.error("review requires one explicit target --release-root")
        review = guard.review_binding(args.project_root, args.release_root[0], **paths)
        result = {"review": review, "inputs": guard.review_inputs(review, role=args.role)}
    elif args.command == "propose":
        result = guard.propose_binding(args.project_root, args.release_root, **paths)
    elif args.command == "verify":
        result = guard.verify_binding(args.project_root, **paths)
    else:
        lock, runtime = guard.bootstrap(args.project_root, **paths)
        guard.runtime_inputs(args.project_root, role="Promoter", **paths)
        result = {"fingerprint": lock["fingerprint"], "module_file": runtime.__file__, "version": runtime.__version__,
                  "release_root": lock["identity"]["release_root"], "project_validation": lock["validation"]["status"]}
    # JSON consumers get the same Unicode values on every Windows code page.
    print(json.dumps(result, ensure_ascii=True, indent=2, default=str))


if __name__ == "__main__":
    main()
