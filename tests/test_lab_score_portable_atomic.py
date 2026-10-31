"""Portable ZIP publication must be atomic, no-overwrite and rollback-safe."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup import lab_score_calibration as cal
from lightup import lab_score_handoff as handoff


class PortableAtomicTests(unittest.TestCase):
    def original_report(self, root: Path):
        originals = [root / "source-a", root / "source-b"]
        for original in originals:
            self.assertTrue(cal.run_lab_score_calibration(original)["passed"])
        return cal.compare_saved_calibration_history(originals)

    def test_final_filename_is_not_visible_until_fsynced_and_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            report = self.original_report(parent)
            dest = parent / "atomic"
            observed = []
            real_fsync = os.fsync

            def inspect_during_fsync(fd):
                # The first fsync is before publishing final name.
                if not observed:
                    self.assertTrue(dest.is_dir())
                    self.assertEqual(list(dest.glob("*.zip")), [])
                    self.assertEqual([p.name for p in dest.iterdir()],
                                     ["." + handoff._FILENAME + ".tmp"])
                    observed.append(True)
                return real_fsync(fd)

            with patch.object(handoff.os, "fsync", side_effect=inspect_during_fsync):
                zip_path = handoff.save_portable_review(dest, report, lambda: None)
            self.assertEqual(observed, [True])
            self.assertEqual(zip_path.parent, dest)
            self.assertEqual([p.name for p in dest.iterdir()], [handoff._FILENAME])
            self.assertEqual(zip_path.stat().st_mode & 0o777, 0o600)

    def test_prepublication_source_refusal_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            report = self.original_report(parent)
            dest = parent / "atomic-refusal"
            calls = []

            def verify():
                calls.append(True)
                if len(calls) == 2:
                    raise ValueError("simulated source swap")

            with self.assertRaisesRegex(ValueError, "source swap"):
                handoff.save_portable_review(dest, report, verify)
            self.assertEqual(len(calls), 2)
            self.assertEqual(list(dest.iterdir()), [])
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)

    def test_postpublication_source_refusal_rolls_back_only_own_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            report = self.original_report(parent)
            dest = parent / "atomic-rollback"
            calls = []

            def verify():
                calls.append(True)
                if len(calls) == 3:
                    self.assertTrue((dest / handoff._FILENAME).is_file())
                    raise ValueError("post-link source drift")

            with self.assertRaisesRegex(ValueError, "source drift"):
                handoff.save_portable_review(dest, report, verify)
            self.assertEqual(len(calls), 3)
            self.assertEqual(list(dest.iterdir()), [])
