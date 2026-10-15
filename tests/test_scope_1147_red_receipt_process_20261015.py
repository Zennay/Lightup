"""Real subprocess acceptance for HOLD-only #1147 source-RED diagnostics.

Invokes only the local installed-source synthetic receipt module; no network,
customer data, grants, real targets or target execution.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts import scope_1147_red_receipt_cli as receipt_cli


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

    def test_internal_original_source_runner_crash_stays_opaque_hold(self):
        # A synthetic internal crash can NEVER become a source-RED receipt.
        marker = "sensitive-fixture-value-must-never-echo"
        output = io.StringIO()
        error = io.StringIO()
        with (
            patch.object(
                unittest.defaultTestLoader,
                "loadTestsFromTestCase",
                side_effect=RuntimeError(marker),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(error),
        ):
            exit_code = receipt_cli.main([])
        self.assertEqual(exit_code, 3)
        self.assertEqual(error.getvalue(), "")
        self.assertEqual(output.getvalue().count("\n"), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["reason"], "UNVERIFIED")
        self.assertNotIn(marker, output.getvalue())
        for flag in EXPECTED_FLAGS:
            self.assertIs(report[flag], False)

    def test_silently_dropped_entire_source_test_suite_stays_hold(self):
        # A loader that accidentally runs ZERO tests must not pass by default.
        output = io.StringIO()
        with (
            patch.object(
                unittest.defaultTestLoader,
                "loadTestsFromTestCase",
                return_value=unittest.TestSuite(),
            ),
            contextlib.redirect_stdout(output),
        ):
            exit_code = receipt_cli.main([])
        self.assertEqual(exit_code, 3)
        self.assertEqual(output.getvalue().count("\n"), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["reason"], "UNVERIFIED")
        self.assertEqual(report["status"], "HOLD")
        for flag in EXPECTED_FLAGS:
            self.assertIs(report[flag], False)

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
