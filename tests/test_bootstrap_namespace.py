"""First-use no-follow guards and operation-time rechecks, no Host/models."""
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from loommode.host.bootstrap import _output_path, _registry
from loommode.host.cli import _process_store
from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import WorkflowState
from tests.test_public_bootstrap import PublicBootstrapTests


def junction(link, target):
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)], check=True, capture_output=True)
    else:
        link.symlink_to(target, target_is_directory=True)


class BootstrapNamespaceTests(unittest.TestCase):
    setUp = PublicBootstrapTests.setUp
    tearDown = PublicBootstrapTests.tearDown
    save = PublicBootstrapTests.save
    inspect = PublicBootstrapTests.inspect

    def outside(self):
        target = self.root / 'protected'
        target.mkdir()
        (target / 'sentinel').write_bytes(b'protected original bytes')
        return target

    def test_runtime_and_all_records_bucket_descendants_reject_before_target_queries(self):
        runtime = self.root / 'Runtime'
        records = self.root / 'Records'
        cases = [(runtime / 'workflow', runtime / 'workflow/FX/FX-A1/state.json'),
                 (runtime / 'contexts.json', runtime / 'contexts.json'),
                 (runtime / 'contexts.json.tmp', runtime / 'contexts.json.tmp')]
        cases += [(records / bucket / 'FX', records / bucket / 'FX/A/A1') for bucket in
                  ('Process/Constraints', 'Process/Working', 'Process/Reports', 'Stage-Records', 'Issue-Ledger')]
        target = self.outside()
        original_exists = Path.exists
        original_iterdir = Path.iterdir
        for link, queried in cases:
            with self.subTest(link=link):
                junction(link, target)
                def exists(path):
                    if path == queried:
                        self.fail('followed the linked target before namespace rejection')
                    return original_exists(path)
                def iterdir(path):
                    if path == queried:
                        self.fail('enumerated linked target before namespace rejection')
                    return original_iterdir(path)
                try:
                    with patch.object(Path, 'exists', exists), patch.object(Path, 'iterdir', iterdir):
                        with self.assertRaisesRegex(WorkflowError, 'linked output namespace'):
                            self.inspect()
                finally:
                    os.rmdir(link) if os.name == 'nt' else link.unlink()
                self.assertEqual((target / 'sentinel').read_bytes(), b'protected original bytes')
                self.assertEqual(sorted(p.name for p in target.iterdir()), ['sentinel'])

    def test_state_registry_and_artifact_recheck_after_preflight(self):
        facts = self.inspect()
        target = self.outside()
        runtime = self.root / 'Runtime'
        junction(runtime / 'workflow', target)
        with self.assertRaisesRegex(WorkflowError, 'linked output namespace'):
            facts['state_store'].save(WorkflowState('FX', 'FX-A1'))
        os.rmdir(runtime / 'workflow') if os.name == 'nt' else (runtime / 'workflow').unlink()
        registry = _registry(runtime, runtime / 'contexts.json')
        junction(runtime / 'contexts.json.tmp', target)
        with self.assertRaisesRegex(WorkflowError, 'linked output namespace'):
            registry._save()
        os.rmdir(runtime / 'contexts.json.tmp') if os.name == 'nt' else (runtime / 'contexts.json.tmp').unlink()
        root = self.root / 'Records'
        artifacts = _process_store(root, 'FX', 'FX-A1', ('FX', 'A', 'A1'),
            namespace_guard=lambda path: _output_path(root, path))
        junction(root / 'Process/Working/FX', target)
        with self.assertRaisesRegex(WorkflowError, 'linked output namespace'):
            artifacts.save('DECISION', 'must not publish')
        os.rmdir(root / 'Process/Working/FX') if os.name == 'nt' else (root / 'Process/Working/FX').unlink()
        self.assertEqual(sorted(p.name for p in target.iterdir()), ['sentinel'])

    def test_normal_state_registry_and_artifact_writes_remain_within_roots(self):
        facts = self.inspect()
        facts['state_store'].save(WorkflowState('FX', 'FX-A1'))
        facts['state_store'].save(WorkflowState('FX', 'FX-A1'))
        root = self.root / 'Runtime'
        registry = _registry(root, root / 'contexts.json')
        registry._save()
        registry._save()
        root = self.root / 'Records'
        artifacts = _process_store(root, 'FX', 'FX-A1', ('FX', 'A', 'A1'),
            namespace_guard=lambda path: _output_path(root, path))
        ref = artifacts.save('DECISION', 'normal bounded output')
        self.assertEqual(artifacts.read(ref), 'normal bounded output')


if __name__ == '__main__':
    unittest.main()
