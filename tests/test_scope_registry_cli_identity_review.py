"""Optional offline registry CLI requires two distinct physical manifest files."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_capability_registry_offline.py"
MANIFEST = b'{"capabilities":[{"capability_id":"web-baseline","state":"planning","requires_explicit_activation":true}]}'


def invoke(before: Path, after: Path):
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(before), str(after)],
        text=True, capture_output=True, timeout=15,
    )
    return completed.returncode, json.loads(completed.stdout)


class RegistryManifestIdentityTests(unittest.TestCase):
    def test_same_path_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp) / "before.json"
            baseline.write_bytes(MANIFEST)
            status, receipt = invoke(baseline, baseline)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["reason"], "same_file_is_not_two_snapshots")
            self.assertIs(receipt["permit_issued"], False)
            self.assertIs(receipt["execution_enabled"], False)

    def test_hardlink_rejected_as_same_inode(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp) / "before.json"
            alias = Path(temp) / "after.json"
            baseline.write_bytes(MANIFEST)
            try:
                os.link(baseline, alias)
            except OSError as exc:
                self.skipTest(f"hardlinks unavailable: {type(exc).__name__}")
            status, receipt = invoke(baseline, alias)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["reason"], "same_file_is_not_two_snapshots")
            self.assertIs(receipt["merge_approved"], False)

    def test_distinct_equal_files_only_review(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp) / "before.json"
            candidate = Path(temp) / "after.json"
            baseline.write_bytes(MANIFEST)
            candidate.write_bytes(MANIFEST)
            self.assertNotEqual(os.stat(baseline).st_ino, os.stat(candidate).st_ino)
            status, receipt = invoke(baseline, candidate)
            self.assertEqual(status, 3)
            self.assertEqual(receipt["status"], "REVIEW_ONLY")
            self.assertIs(receipt["authorization_verified"], False)
            self.assertIs(receipt["release_approved"], False)

    def test_distinct_changed_file_is_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp) / "before.json"
            candidate = Path(temp) / "after.json"
            baseline.write_bytes(MANIFEST)
            candidate.write_bytes(MANIFEST.replace(b"planning", b"lab_only"))
            status, receipt = invoke(baseline, candidate)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["changed_capabilities"], ["web-baseline"])
            self.assertIs(receipt["execution_enabled"], False)

    def test_directory_does_not_block_or_succeed(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp)
            candidate = baseline / "after.json"
            candidate.write_bytes(MANIFEST)
            status, receipt = invoke(baseline, candidate)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["reason"], "unreadable_local_manifest")
            self.assertIs(receipt["permit_issued"], False)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_named_pipe_never_blocks_or_succeeds(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline = Path(temp) / "fifo.json"
            candidate = Path(temp) / "after.json"
            os.mkfifo(baseline)
            candidate.write_bytes(MANIFEST)
            status, receipt = invoke(baseline, candidate)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["reason"], "unreadable_local_manifest")
            self.assertIs(receipt["execution_enabled"], False)


if __name__ == "__main__":
    unittest.main()
