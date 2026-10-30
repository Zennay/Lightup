"""Private saved synthetic HUMAN-history workspace, original offline fixtures."""
from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup import lab_canary
from lightup.lab_canary_handoff import save_private_canary_handoff
from lightup.lab_canary_history import compare_private_canary_handoffs
from lightup.lab_canary_history_store import (
    save_private_history_snapshot, verify_private_history_snapshot,
)


class PrivateCanaryHistoryStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = lab_canary._run_canary()
        if cls.original["status"] != "PASS":
            raise AssertionError("fixed synthetic localhost canary failed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.before = self.root / "before"
        self.after = self.root / "after"
        self.snapshot = self.root / "snapshot"
        for name in (self.before, self.after):
            save_private_canary_handoff(
                str(name), self.original, lab_canary._render_text(self.original)
            )

    def compare(self):
        return compare_private_canary_handoffs(str(self.before), str(self.after))

    def create(self):
        return save_private_history_snapshot(str(self.snapshot), self.compare())

    def test_real_original_pass_snapshot_saved_and_independently_reopened(self):
        self.create()
        self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            {p.name for p in self.snapshot.iterdir()},
            {"history.json", "history.html", "manifest.json"},
        )
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600
                            for p in self.snapshot.iterdir()))
        receipt = verify_private_history_snapshot(str(self.snapshot))
        self.assertEqual(receipt["review_status"], "PASS")
        self.assertTrue(receipt["transport_integrity"])
        for k in ("source_authenticated", "consent_authenticated",
                  "authorization_granted", "external_target_authorized", "deployment"):
            self.assertIs(receipt[k], False)

    def test_second_open_never_reruns_a_canary_or_overwrites_original(self):
        self.create()
        captured = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("unexpected subprocess or scorer")):
            with redirect_stdout(captured):
                status = lab_canary.main([
                    "--verify-private-history-output-dir", str(self.snapshot),
                    "--format", "json",
                ])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(captured.getvalue())["review_status"], "PASS")
        with self.assertRaises(FileExistsError):
            self.create()

    def test_private_snapshot_changes_fail_closed_without_file_path_leak(self):
        self.create()
        source = self.snapshot / "history.json"
        source.write_bytes(source.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            verify_private_history_snapshot(str(self.snapshot))
        output = io.StringIO()
        with redirect_stdout(output):
            code = lab_canary.main([
                "--verify-private-history-output-dir", str(self.snapshot),
                "--format", "json",
            ])
        self.assertEqual(code, 2)
        receipt = json.loads(output.getvalue())
        self.assertIs(receipt["transport_integrity"], False)
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertNotIn(str(self.root), output.getvalue())

    def test_full_cli_create_reopen_and_no_overwrite(self):
        output = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("CLI re-ran scorer")):
            with redirect_stdout(output):
                status = lab_canary.main([
                    "--compare-private-report-dirs", str(self.before),
                    str(self.after), "--private-history-output-dir",
                    str(self.snapshot), "--format", "json",
                ])
        self.assertEqual(status, 0)
        self.assertIs(json.loads(output.getvalue())["snapshot_saved"], True)
        output = io.StringIO()
        with redirect_stdout(output):
            status = lab_canary.main([
                "--verify-private-history-output-dir", str(self.snapshot),
                "--format", "json",
            ])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["review_status"], "PASS")
        output = io.StringIO()
        with redirect_stdout(output):
            status = lab_canary.main([
                "--compare-private-report-dirs", str(self.before),
                str(self.after), "--private-history-output-dir",
                str(self.snapshot), "--format", "json",
            ])
        self.assertEqual(status, 2)
        self.assertIs(json.loads(output.getvalue())["snapshot_saved"], False)
        self.assertNotIn(str(self.root), output.getvalue())

    def test_source_free_hold_snapshot_created_with_exit_2(self):
        from shutil import rmtree
        rmtree(self.after)
        held = {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False,
            "deployment_authorized": False, "failure_stage": "service",
        }
        save_private_canary_handoff(str(self.after), held,
                                    lab_canary._render_text(held))
        out = io.StringIO()
        with redirect_stdout(out):
            code = lab_canary.main([
                "--compare-private-report-dirs", str(self.before),
                str(self.after), "--private-history-output-dir",
                str(self.snapshot), "--format", "json",
            ])
        self.assertEqual(code, 2)
        self.assertIs(json.loads(out.getvalue())["snapshot_saved"], True)
        self.assertEqual(verify_private_history_snapshot(str(self.snapshot))["review_status"], "HOLD")

    def test_rehashed_forged_passive_html_is_rejected(self):
        self.create()
        altered = self.snapshot / "history.html"
        altered.write_text(
            altered.read_text().replace("NOT AUTHORIZATION",
                                         "AUTHORIZED TO SCAN ALL TARGETS")
        )
        manifest = self.snapshot / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"]["history.html"] = hashlib.sha256(altered.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(data, sort_keys=True))
        with self.assertRaises(ValueError):
            verify_private_history_snapshot(str(self.snapshot))

    def test_forged_release_or_incomplete_source_not_saved(self):
        result = self.compare()
        result["authorization_granted"] = True
        with self.assertRaises(ValueError):
            save_private_history_snapshot(str(self.snapshot), result)
        self.assertFalse(self.snapshot.exists())
        same = compare_private_canary_handoffs(str(self.before), str(self.before))
        with self.assertRaises(ValueError):
            save_private_history_snapshot(str(self.snapshot), same)
        self.assertFalse(self.snapshot.exists())

    def test_hold_regression_snapshot_is_reviewable_but_not_cleared(self):
        result = self.compare()
        result["review_status"] = "HOLD"
        result["regressions"].append({
            "metric": "synthetic_canary", "change": "PASS_TO_HOLD"
        })
        with self.assertRaises(ValueError):
            save_private_history_snapshot(str(self.snapshot), result)
        self.assertFalse(self.snapshot.exists())

        # A real first-party failure remains HOLD in the saved source-free kit.
        from shutil import rmtree
        rmtree(self.after)
        hold = {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False,
            "deployment_authorized": False, "failure_stage": "http",
        }
        save_private_canary_handoff(str(self.after), hold, lab_canary._render_text(hold))
        self.create()
        verified = verify_private_history_snapshot(str(self.snapshot))
        self.assertEqual(verified["review_status"], "HOLD")
        self.assertIs(verified["authorization_granted"], False)


if __name__ == "__main__":
    unittest.main()
