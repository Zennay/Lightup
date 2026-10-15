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
import tempfile
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

    def test_successful_hold_does_not_change_caller_python_process_settings(self):
        # main([]) is also imported by tests: no sys.path or bytecode leakage.
        original_path = sys.path[:]
        with patch.object(sys, "dont_write_bytecode", False):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = receipt_cli.main([])
            self.assertEqual(status, 2)
            self.assertFalse(sys.dont_write_bytecode)
        self.assertEqual(sys.path, original_path)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")

    def test_diagnostic_crash_restores_caller_python_process_settings(self):
        original_path = sys.path[:]
        with (
            patch.object(sys, "dont_write_bytecode", False),
            patch.object(
                unittest.defaultTestLoader,
                "loadTestsFromTestCase",
                side_effect=RuntimeError("synthetic error must be suppressed"),
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            status = receipt_cli.main([])
            self.assertFalse(sys.dont_write_bytecode)
        self.assertEqual(sys.path, original_path)
        self.assertEqual(status, 3)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["reason"], "UNVERIFIED")
        for flag in EXPECTED_FLAGS:
            self.assertIs(report[flag], False)

    def test_invalid_invocation_never_changes_caller_python_process_settings(self):
        original_path = sys.path[:]
        original_bytecode = sys.dont_write_bytecode
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = receipt_cli.main(["--unknown-fake-argument"])
        self.assertEqual(status, 3)
        self.assertEqual(sys.path, original_path)
        self.assertIs(sys.dont_write_bytecode, original_bytecode)
        self.assertEqual(json.loads(output.getvalue())["reason"], "INVALID_INVOCATION")

    def test_inert_fixture_intercepts_attempted_process_and_shell_without_evidence(self):
        # Deliberately attempt calls ONLY under active mocks. Nothing is
        # executed: the assertion is raised before OS-level process creation.
        from test_scope_1147_duplicate_key_installed_matrix_20261015 import (
            DuplicateArgumentKeysInstalledSource1147,
        )
        fixture = DuplicateArgumentKeysInstalledSource1147(
            "test_unique_names_permit_exact_once_with_durable_evidence"
        )
        fixture.setUp()
        try:
            with self.assertRaisesRegex(AssertionError, "never use"):
                subprocess.Popen(["fictional-command-that-does-not-exist"])
            with self.assertRaisesRegex(AssertionError, "never use"):
                os.system("fictional-command-that-does-not-exist")
            fixture.effect_guards[3].assert_called_once()
            fixture.effect_guards[4].assert_called_once()
            self.assertEqual(fixture.calls, [])
            self.assertEqual(fixture.evidence_count(), 0)
        finally:
            fixture.doCleanups()

    def test_cli_cannot_report_known_red_after_source_control_roster_loss(self):
        # The original source issue may still exist, but losing a safe
        # regression control makes this receipt untrustworthy: stay HOLD.
        sensitive = "no-echo-fixture-unsafe-control-roster"
        output = io.StringIO()
        with (
            patch(
                "test_scope_1147_expected_red_integrity_20261015.verify_source_test_roster",
                side_effect=AssertionError(sensitive),
            ),
            contextlib.redirect_stdout(output),
        ):
            status = receipt_cli.main([])
        self.assertEqual(status, 3)
        self.assertNotIn(sensitive, output.getvalue())
        self.assertEqual(output.getvalue().count("\n"), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["reason"], "UNVERIFIED")
        for flag in EXPECTED_FLAGS:
            self.assertIs(report[flag], False)

    def test_refuses_extra_arguments_without_echoing_them(self):
        sensitive_marker = "secret-fixture--not-a-real-customer.invalid"
        proc, report = self.run_receipt("--target", sensitive_marker)
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(report["reason"], "INVALID_INVOCATION")
        self.assertNotIn(sensitive_marker, proc.stdout)

    def test_original_source_receipt_from_unrelated_working_directory(self):
        # Explicit repo-local PYTHONPATH is required for python -m outside the
        # repository; receipt must never derive its safety scope from cwd.
        original, expected = self.run_receipt()
        self.assertEqual(original.returncode, 2)
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT), str(ROOT / "src"), str(ROOT / "tests"))
        )
        with tempfile.TemporaryDirectory() as unrelated_cwd:
            proc = subprocess.run(
                [sys.executable, "-m", MODULE],
                cwd=unrelated_cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=15, check=False,
            )
            self.assertEqual(list(Path(unrelated_cwd).iterdir()), [])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(proc.stdout, original.stdout)
        self.assertEqual(json.loads(proc.stdout), expected)

    def test_process_invocation_does_not_derive_authority_from_untrusted_cwd(self):
        # An unrelated directory and stray .invalid marker must not create
        # approval, change the receipt or leave any output files behind.
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT), str(ROOT / "src"), str(ROOT / "tests"))
        )
        with tempfile.TemporaryDirectory() as unrelated_cwd:
            marker = Path(unrelated_cwd) / "untrusted-fixture.invalid"
            marker.write_text("not authorization", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-m", MODULE],
                cwd=unrelated_cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=15, check=False,
            )
            self.assertEqual(sorted(p.name for p in Path(unrelated_cwd).iterdir()),
                             [marker.name])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "")
        self.assertNotIn(marker.name, proc.stdout)
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "KNOWN_SOURCE_RED_CONFIRMED")
        for flag in EXPECTED_FLAGS:
            self.assertIs(result[flag], False)

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
