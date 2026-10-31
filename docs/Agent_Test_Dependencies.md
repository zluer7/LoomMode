# Dependencies and reproducibility

Runtime: Python 3.11 or newer; all production imports are standard library.
Windows is the first test target. No runtime pip dependency is declared.
Git is needed for the disposable engineering test's original/current inventory.
A legitimate installed Codex app-server binary is needed only for the later
authorized live test; pin its actual unlinked executable bytes/version. Do not
bundle or copy another machine's credentials, Codex installation or Git.

Included pure-Python wheel: `wheels/loommode-2.0.0-py3-none-any.whl`.
Install with `python -m pip install --no-index --no-deps <wheel>` into a fresh
venv. Tools/config/docs remain beside the source; the wheel alone is incomplete
for agent-assisted first use. No wheel dependency fetch is necessary.

Rebuilding requires setuptools>=68 and wheel. This candidate was built with
Python3.13.5, pip25.1, setuptools72.1.0, wheel0.45.1 using
`pip wheel --no-index --no-deps --no-build-isolation`. Local metadata identifies
pip/setuptools/wheel as MIT tools; they are not redistributed by this package.
Python and external binaries have their own terms. This is an inventory, not
legal clearance or a vulnerability certification. No lock pins unrelated
site-packages; optional providers are outside the Codex-only test path.

If the new computer lacks Python/Git/Codex, use its approved installation route
within the actual later authorization. Do not guess a download, enter passwords,
change shared ACLs or introduce a paid route. Existing legitimate sign-in should
be used; required interactive login remains an actual user action. A2 offline
tests do not establish authentication or protocol compatibility.

LoomMode code is provided under Apache License2.0; LICENSE is included verbatim
in both candidate and wheel. Names/logos, user data and third-party materials
retain separate rights. No identified selected third-party attribution requires
NOTICE; see LICENSE_SCOPE.md. Copyright 2026 争流儿, as declared by the Owner; this does not claim an independent legal-title audit.

Repeatable candidate build: use the same selected source, Python/pip/setuptools/wheel versions and a pinned --source-date-epoch with tools/agent_test_package.py. Compare wheel, manifest and core ZIP bytes across separate output roots. The source allowlist/config and build helper must remain identical.
