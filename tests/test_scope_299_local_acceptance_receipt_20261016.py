"""Acceptance for the non-authorizing local #299-only test-suite receipt.

Runs only owned synthetic tests; does not touch targets or CI/VPS.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scope_299_local_acceptance_receipt_20261016.py"
FLAGS = {
    "can_authorize", "can_dispatch", "can_deploy", "can_merge",
    "can_release", "can_scan",
}


def invoke(*args: str):
    proc = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), *args],
        cwd=ROOT, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=25, check=False,
    )
    output = proc.stdout.decode("utf-8")
    if len(output.splitlines()) != 1:
        raise AssertionError("exactly one JSON receipt must be emitted")
    return proc.returncode, json.loads(output), proc.stderr.decode("utf-8")


class Scope299LocalSuiteReceiptAcceptance(unittest.TestCase):
    def assert_hold(self, result, reason: str, status_code: int):
        code, parsed, stderr = result
        self.assertEqual(code, status_code)
        self.assertEqual(stderr, "")
        self.assertIs(type(parsed), dict)
        self.assertEqual(parsed["status"], "HOLD")
        self.assertEqual(parsed["reason"], reason)
        self.assertEqual(parsed["evidence_class"], "local_untrusted")
        self.assertEqual(set(parsed), {"status", "reason", "evidence_class", *FLAGS})
        for field in FLAGS:
            self.assertIs(parsed[field], False)
        self.assertLess(len(json.dumps(parsed)), 275)

    def test_run_exact_owned_current_source_and_cli_suite(self):
        self.assert_hold(
            invoke("--offline-local-suite-only"),
            "open_source_reds_observed",
            2,
        )

    def test_no_optin_cannot_run_or_claim_evidence(self):
        self.assert_hold(invoke(), "invalid_command", 3)

    def test_target_and_grant_and_deploy_options_are_refused(self):
        for args in (
            ("--target", "some.example.test"),
            ("--grant",),
            ("--scan",),
            ("--deploy",),
            ("--offline-local-suite-only", "--target", "some.example.test"),
            ("--offline-local-suite-only", "--authorize"),
            ("--offline-local-suite-only", "--file", "secret.json"),
        ):
            with self.subTest(args=args):
                self.assert_hold(invoke(*args), "invalid_command", 3)

    def test_unknown_or_misleading_args_stay_hold(self):
        for args in (
            ("--help",), ("--offline-synthetic-only",),
            ("--offline-synthetic-pair-only",), ("--offline-local-suite-only", "success"),
        ):
            with self.subTest(args=args):
                self.assert_hold(invoke(*args), "invalid_command", 3)

    def test_receipt_reason_allowlist_prevents_arbitrary_output(self):
        sys.path.insert(0, str(ROOT))
        try:
            from scripts.scope_299_local_acceptance_receipt_20261016 import receipt
            untrusted = "FICTIONAL-SECRET-NO-ECHO-ABC123"
            actual = receipt(untrusted)
            self.assertNotIn(untrusted, actual)
            self.assertEqual(json.loads(actual)["reason"], "contract_changed")
            for reason in ("open_source_reds_observed", "contract_changed", "invalid_command"):
                parsed = json.loads(receipt(reason))
                self.assertEqual(parsed["reason"], reason)
                self.assertEqual(parsed["status"], "HOLD")
                self.assertTrue(all(parsed[key] is False for key in FLAGS))
        finally:
            sys.path.pop(0)

    def test_suite_contract_is_locked_to_only_three_owned_modules(self):
        sys.path.insert(0, str(ROOT))
        try:
            from scripts import scope_299_local_acceptance_receipt_20261016 as script
            self.assertEqual(script.EXPECTED_TESTS, 81)
            self.assertEqual(script.EXPECTED_SOURCE_REDS, 24)
            self.assertEqual(
                script.TEST_MODULES,
                (
                    "test_scope_299_legacy_provenance_red_20261015",
                    "test_scope_299_legacy_provenance_review_20261016",
                    "test_scope_299_legacy_pair_review_20261016",
                    "test_scope_299_owner_portable_acceptance_20261016",
                ),
            )
        finally:
            sys.path.pop(0)

    def test_no_target_or_external_service_imports_in_receipt_runner(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(name.name.split(".")[0] for name in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertEqual(
            imported, {"__future__", "json", "pathlib", "socket", "sys", "unittest"},
        )

    def test_optin_never_returns_success_exit_code(self):
        code, data, _stderr = invoke("--offline-local-suite-only")
        self.assertEqual(code, 2)
        self.assertEqual(data["status"], "HOLD")
        self.assertNotIn("permission", data)
        self.assertNotIn("authorized", data)
        self.assertNotIn("source_verified", data)


if __name__ == "__main__":
    unittest.main()
