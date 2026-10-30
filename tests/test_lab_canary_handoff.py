"""M1 private offline canary handoff: source-free actual synthetic loopback producer."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup import lab_canary
from lightup.lab_canary_handoff import (
    save_private_canary_handoff, verify_private_canary_handoff,
)


class PrivateCanaryHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synthetic = lab_canary._run_canary()
        if cls.synthetic["status"] != "PASS":
            raise AssertionError("first-party synthetic loopback canary failed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "new-private-report"

    def produce(self, result=None):
        result = self.synthetic if result is None else result
        return save_private_canary_handoff(
            str(self.path), result, lab_canary._render_text(result)
        )

    def test_original_synthetic_lab_run_can_be_saved_and_independently_reopened(self):
        self.produce()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            {x.name for x in self.path.iterdir()},
            {"canary.json", "operator.txt", "manifest.json"},
        )
        self.assertTrue(all(x.stat().st_mode & 0o777 == 0o600
                            for x in self.path.iterdir()))
        verified = verify_private_canary_handoff(str(self.path))
        self.assertTrue(verified["transport_integrity"])
        self.assertEqual(verified["review_status"], "PASS")
        for key in ("source_authenticated", "consent_authenticated",
                    "authorization_granted", "deployment"):
            self.assertIs(verified[key], False)
        self.assertNotIn(str(self.root), json.dumps(verified))

    def test_cli_read_only_verification_without_running_scorer(self):
        self.produce()
        result = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("unexpected scorer invocation")):
            with redirect_stdout(result):
                code = lab_canary.main([
                    "--verify-private-report-dir", str(self.path),
                    "--format", "json",
                ])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(result.getvalue())["review_status"], "PASS")

    def test_original_bytes_modified_must_fail_closed_without_private_leak(self):
        self.produce()
        source = self.path / "canary.json"
        source.write_bytes(source.read_bytes() + b" ")
        out = io.StringIO()
        with redirect_stdout(out):
            code = lab_canary.main([
                "--verify-private-report-dir", str(self.path), "--format", "json"
            ])
        self.assertEqual(code, 2)
        receipt = json.loads(out.getvalue())
        self.assertFalse(receipt["transport_integrity"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertNotIn(str(self.root), out.getvalue())

    def test_overwrite_symlink_and_extra_file_all_refused(self):
        self.produce()
        with self.assertRaises(FileExistsError):
            self.produce()
        with self.assertRaises(Exception):
            verify_private_canary_handoff(str(self.path / ".." / "new-private-report"))
        (self.path / "untracked-private-data").write_text("synthetic")
        with self.assertRaises(ValueError):
            verify_private_canary_handoff(str(self.path))
        alias = self.root / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            verify_private_canary_handoff(str(alias))

    def test_hold_report_retains_original_failure_stage(self):
        held = {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False,
            "deployment_authorized": False, "failure_stage": "tls",
        }
        self.produce(held)
        self.assertEqual(
            verify_private_canary_handoff(str(self.path))["review_status"], "HOLD"
        )

    def test_unknown_private_fields_and_false_pass_cannot_be_published(self):
        altered = dict(self.synthetic, password="example")
        with self.assertRaises(ValueError):
            self.produce(altered)
        self.assertFalse(self.path.exists())
        altered = dict(self.synthetic, fixed_loopback_socket_boundary_enforced=False)
        with self.assertRaises(ValueError):
            self.produce(altered)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
