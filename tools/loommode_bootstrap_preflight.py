"""Read-only pinned first-use configuration check; no factory or model launch."""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from loommode.host.bootstrap import preflight
from loommode.codex.errors import LoomModeError
from loommode.workflow.errors import WorkflowError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(preflight(args.config, expected_sha256=args.sha256), ensure_ascii=False, indent=2))
    except (OSError, ValueError, TypeError, WorkflowError, LoomModeError) as exc:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc), 'writes': 0}, ensure_ascii=False))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
