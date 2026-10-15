"""Real subprocess acceptance for HOLD-only #1147 source-RED diagnostics.

Invokes only the local installed-source synthetic receipt module; no network,
customer data, grants, real targets or target execution.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = "scripts.scope_1147_red_receipt_cli"
EXPECTED_FLAGS = (
    "can_authorize", "can_dispatch", "can_merge",
    "can_deploy", "can_scan", "can_release",
)


class Scope1147ReceiptProcessTests(unittest.TestCase):
    def run_receipt(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict]:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT / "src"), str(ROOT / "tests"))
        )
        proc = subprocess.run(
            [sys.executable, "-m", MODULE, *arguments],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.stderr, "")
        self.assertEqual(proc.stdout.count("\n"), 1)
        self.assertTrue(proc.stdout.endswith("\n"))
        report = json.loads(proc.stdout)
        self.assertIs(type(report), dict)
        self.assertEqual(set(report), {"status", "issue", "reason", *EXPECTED_FLAGS})
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["issue"], "1147")
        for field in EXPECTED_FLAGS:
            self.assertIs(report[field], False)
        return proc, report

    def test_actual_os_process_confirms_only_known_red_and_exits_nonzero(self):
        proc, report = self.run_receipt()
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(report["reason"], "KNOWN_SOURCE_RED_CONFIRMED")

    def test_refuses_extra_arguments_without_echoing_them(self):
        sensitive_marker = "secret-fixture--not-a-real-customer.invalid"
        proc, report = self.run_receipt("--target", sensitive_marker)
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(report["reason"], "INVALID_INVOCATION")
        self.assertNotIn(sensitive_marker, proc.stdout)

    def test_repeatable_process_receipt_has_no_broadening_or_output_drift(self):
        first, first_report = self.run_receipt()
        second, second_report = self.run_receipt()
        self.assertEqual(first.returncode, 2)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first_report, second_report)
        self.assertEqual(first_report["reason"], "KNOWN_SOURCE_RED_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
