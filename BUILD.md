# LoomMode 2.0.0 selected source — candidate

Copyright 2026 争流儿. Apache-2.0. Owner acceptance/publication remains pending.
This tree retains the original relative names for the complete selected source;
public document target names are mapped by config/agent_test_package.json.
It contains no source-project Records, private State/Grant, .git or credentials.

Use Python 3.13.5, pip 25.1, setuptools 72.1.0 and wheel 0.45.1 to reproduce the
recorded build. These tools are not bundled. Runtime is standard-library only.
Verify SOURCE_SHA256SUMS before running any helper. From this tree, with fresh
disjoint output/evidence directories, run:

```powershell
python -B tools/agent_test_package.py --source . --specification config/agent_test_package.json --target <new-candidate> --evidence <new-build-evidence> --archive <new-output>/LoomMode-2.0.0-Agent-Test.zip --source-date-epoch 1793318400
```

This performs a real offline wheel build. The epoch fixes build container dates;
it is not a publication date or an Owner acceptance event. Compare resulting core
ZIP/manifest/wheel hashes with the supplied candidate identity. Different tool
versions need separate qualification before claiming bit-for-bit reproducibility.
The full first-use candidate archive includes its own README/installation guide;
the wheel alone does not contain tools, config and roles.
