"""End-to-end smoke contract for the checked-in SYNTHETIC GitHub export."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_github_rest_import_20261015 import review
from scope_issue_github_rest_report_20261015 import render

EXAMPLE = ROOT / "lab" / "scope_github_rest_export_synthetic_20261015.json"
FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


class EndToEndRestSmokeTests(unittest.TestCase):
    def test_example_is_valid_utf8_json(self):
        raw = EXAMPLE.read_bytes()
        self.assertTrue(json.loads(raw)["repository"] == "Zennay/Lightup")

    def test_example_has_no_real_credentials_or_targets(self):
        raw = EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("SYNTHETIC", raw)
        self.assertNotIn("https://", raw)
        self.assertNotIn("token", raw.lower())

    def test_import_of_sample_stays_hold(self):
        r = review(EXAMPLE.read_bytes())
        self.assertEqual(r["status"], "HOLD")
        self.assertTrue(all(r[k] is False for k in FLAGS))

    def test_example_detects_old_rename_path_overlap(self):
        r = review(EXAMPLE.read_bytes())
        self.assertEqual(r["observed_path_collisions"], [
            {"path": "tests/old_owner.py", "prs": [820001, 820002]},
        ])

    def test_unclaimed_issues_never_displayed(self):
        r = review(EXAMPLE.read_bytes())
        self.assertTrue(r["candidate_list_suppressed"])
        self.assertEqual(r["unclaimed_candidates_not_permission"], [])
        self.assertFalse(r["source_provenance_verified"])

    def test_nederlands_report_mentions_synthetic_conflict(self):
        report = render(EXAMPLE.read_bytes())
        self.assertIn("Conflictgroep 1: PR #820001, #820002", report)
        self.assertIn("tests/old_owner.py", report)
        self.assertIn("HOLD", report)

    def test_import_cli_returns_two_from_checked_in_example(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_github_rest_import_20261015.py")]
        process = subprocess.run(cmd, input=EXAMPLE.read_bytes(),
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stdout)["status"], "HOLD")

    def test_report_cli_returns_two_from_checked_in_example(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_github_rest_report_20261015.py")]
        process = subprocess.run(cmd, input=EXAMPLE.read_bytes(),
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertIn("tests/old_owner.py", process.stdout.decode("utf-8"))
        self.assertNotIn(b"Traceback", process.stderr)


if __name__ == "__main__":
    unittest.main()
