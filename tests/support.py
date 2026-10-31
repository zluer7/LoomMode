from __future__ import annotations

import subprocess
from pathlib import Path


def run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
    )


def make_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "calc.py").write_text(
        "def add(left, right):\n    return left - right\n",
        encoding="utf-8",
    )
    (root / "test_calc.py").write_text(
        "import unittest\nfrom calc import add\n\n"
        "class CalcTest(unittest.TestCase):\n"
        "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n\n"
        "if __name__ == '__main__':\n    unittest.main()\n",
        encoding="utf-8",
    )
    assert run(["git", "init", "-q"], root).returncode == 0
    assert run(["git", "add", "--", "calc.py", "test_calc.py"], root).returncode == 0
    committed = run(
        [
            "git",
            "-c",
            "user.name=LoomMode Test",
            "-c",
            "user.email=loommode-test@invalid.local",
            "commit",
            "-q",
            "-m",
            "fixture baseline",
        ],
        root,
    )
    assert committed.returncode == 0, committed.stderr
    return root
