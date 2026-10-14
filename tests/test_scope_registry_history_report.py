"""Offline human-readable scope report acceptance: no authority or text leakage."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from lightup.capabilities import get_capabilities
from lightup.capability_registry_history_report import render_capability_registry_history_markdown
from scripts.export_scope_capability_registry_offline import snapshot_manifest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/render_scope_registry_history_offline.py"


def cap(state="planning", description="Synthetic description", activation=True):
    return {
        "capability_id": "web-baseline", "state": state,
        "requires_explicit_activation": activation,
        "name": "Web review", "description": description,
    }


def manifest(*entries):
    return json.dumps({"capabilities": list(entries)}).encode()


def cli(paths):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, paths)],
                          text=True, capture_output=True, timeout=15)


class RegistryHistoryReportTests(unittest.TestCase):
    def setUp(self):
        self.baseline = manifest(cap())
        self.changed = manifest(cap(state="lab_only"))

    def assert_denies_authority(self, report):
        self.assertIn("**Authority: NONE.**", report)
        self.assertIn("No authorization verified", report)
        self.assertIn("permit issued", report)
        self.assertIn("execution enabled", report)
        self.assertIn("merge approved", report)
        self.assertIn("release approved", report)
        self.assertIn("Do not run security tests", report)

    def test_identical_snapshots_only_review_not_consent(self):
        report, code = render_capability_registry_history_markdown((self.baseline, self.baseline))
        self.assertEqual(code, 3)
        self.assertIn("REVIEW_ONLY", report)
        self.assertIn("No differences in the declared metadata", report)
        self.assert_denies_authority(report)

    def test_reverted_intermediate_lab_reclassification_visible(self):
        report, code = render_capability_registry_history_markdown((self.baseline, self.changed, self.baseline))
        self.assertEqual(code, 2)
        self.assertIn("HOLD", report)
        self.assertIn("| 1 → 2 | \`web-baseline\` | state |", report)
        self.assertIn("| 2 → 3 | \`web-baseline\` | state |", report)
        self.assert_denies_authority(report)

    def test_added_and_removed_capability_visible(self):
        expanded = manifest(cap(), {**cap(), "capability_id": "wireless-lab"})
        report, code = render_capability_registry_history_markdown((self.baseline, expanded, self.baseline))
        self.assertEqual(code, 2)
        self.assertIn("wireless-lab", report)
        self.assertIn("added", report)
        self.assertIn("removed", report)

    def test_activation_risk_flag_visible(self):
        changed = manifest(cap(activation=False))
        report, code = render_capability_registry_history_markdown((self.baseline, changed))
        self.assertEqual(code, 2)
        self.assertIn("requires_explicit_activation", report)
        self.assert_denies_authority(report)

    def test_description_is_never_echoed(self):
        modified = manifest(cap(description="private-brand-sensitive-marker"))
        report, code = render_capability_registry_history_markdown((self.baseline, modified))
        self.assertEqual(code, 2)
        self.assertIn("description", report)
        self.assertNotIn("private-brand-sensitive-marker", report)
        self.assertNotIn("Synthetic description", report)

    def test_invalid_bidi_text_cannot_be_rendered_as_review(self):
        poison = manifest(cap(description="header\u202e hack"))
        report, code = render_capability_registry_history_markdown((self.baseline, poison))
        self.assertEqual(code, 2)
        self.assertIn("cannot be safely reviewed", report)
        self.assertNotIn("hack", report)
        self.assert_denies_authority(report)

    def test_invalid_nonbytes_input_is_hold(self):
        report, code = render_capability_registry_history_markdown((self.baseline, "not-bytes"))
        self.assertEqual(code, 2)
        self.assertNotIn("not-bytes", report)

    def test_empty_and_one_snapshot_are_hold(self):
        for collection in ((), (self.baseline,)):
            report, code = render_capability_registry_history_markdown(collection)
            self.assertEqual(code, 2)
            self.assert_denies_authority(report)

    def test_declared_count_sixteen_review_only(self):
        report, code = render_capability_registry_history_markdown((self.baseline,) * 16)
        self.assertEqual(code, 3)
        self.assertIn("Declared snapshots: **16**", report)

    def test_real_exported_registry_description_reversion_holds(self):
        original = get_capabilities()
        modified = (replace(original[0], description=original[0].description + " synthetic version"),) + original[1:]
        report, code = render_capability_registry_history_markdown(
            (snapshot_manifest(original), snapshot_manifest(modified), snapshot_manifest(original)))
        self.assertEqual(code, 2)
        self.assertIn(original[0].capability_id, report)
        self.assertNotIn(original[0].description, report)

    def test_cli_two_files_identical_only_review(self):
        with tempfile.TemporaryDirectory() as folder:
            files = [Path(folder) / f"{i}.json" for i in range(2)]
            for file in files:
                file.write_bytes(self.baseline)
            run = cli(files)
            self.assertEqual(run.returncode, 3, run.stderr)
            self.assertIn("REVIEW_ONLY", run.stdout)
            self.assert_denies_authority(run.stdout)

    def test_cli_reverted_history_is_hold(self):
        with tempfile.TemporaryDirectory() as folder:
            files = [Path(folder) / f"{i}.json" for i in range(3)]
            for file, content in zip(files, (self.baseline, self.changed, self.baseline)):
                file.write_bytes(content)
            run = cli(files)
            self.assertEqual(run.returncode, 2)
            self.assertIn("2 → 3", run.stdout)
            self.assert_denies_authority(run.stdout)

    def test_cli_same_physical_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            first = Path(folder) / "one.json"
            first.write_bytes(self.baseline)
            run = cli((first, first))
            self.assertEqual(run.returncode, 2)
            self.assertIn("cannot be safely reviewed", run.stdout)
            self.assert_denies_authority(run.stdout)

    def test_cli_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "one.json", Path(folder) / "two.json"
            first.write_bytes(self.baseline)
            try:
                os.link(first, second)
            except OSError:
                self.skipTest("hardlinks unsupported")
            run = cli((first, second))
            self.assertEqual(run.returncode, 2)
            self.assert_denies_authority(run.stdout)

    def test_cli_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "one.json", Path(folder) / "two.json"
            first.write_bytes(self.baseline)
            second.symlink_to(first)
            run = cli((first, second))
            self.assertEqual(run.returncode, 2)
            self.assertIn("HOLD", run.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unsupported")
    def test_cli_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as folder:
            first, pipe = Path(folder) / "one.json", Path(folder) / "fifo"
            first.write_bytes(self.baseline)
            os.mkfifo(pipe)
            run = cli((first, pipe))
            self.assertEqual(run.returncode, 2)
            self.assert_denies_authority(run.stdout)


if __name__ == "__main__":
    unittest.main()
