"""Fail-closed offline acceptance for source-backed lab admission audit #1422."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_scope_installed_lab_policy_1422_offline import (
    LAB, NOT_LAB, TOTAL_CHECKS, ScopeDecision, ScopeReason,
    audit_installed_scope, main,
)


class _FixturePolicy:
    def __init__(self, *, allow_private_lab):
        self.enabled = allow_private_lab

    def decide(self, target):
        positive = {original: (canonical, reason) for original, canonical, reason in LAB}
        if target.value in positive:
            host, reason = positive[target.value]
            if reason is ScopeReason.LOOPBACK:
                return ScopeDecision(True, host, ScopeReason.LOOPBACK)
            if self.enabled:
                return ScopeDecision(True, host, ScopeReason.PRIVATE_LAB)
            return ScopeDecision(False, host, ScopeReason.OUT_OF_SCOPE)
        if target.value in NOT_LAB:
            return ScopeDecision(False, "fictional", ScopeReason.OUT_OF_SCOPE)
        raise ValueError("unexpected fixture input")


class InstalledScopeLabAuditTests(unittest.TestCase):
    def assert_never_authority(self, receipt):
        self.assertEqual(
            {key: receipt[key] for key in (
                "authorization_verified", "permit_issued", "execution_enabled",
                "merge_approved", "release_approved"
            )},
            dict.fromkeys((
                "authorization_verified", "permit_issued", "execution_enabled",
                "merge_approved", "release_approved"
            ), False),
        )
        self.assertEqual(set(receipt), {
            "status", "checked_count", "total_count",
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved",
        })
        self.assertEqual(receipt["total_count"], TOTAL_CHECKS)
        self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
        self.assertEqual(receipt["checked_count"], TOTAL_CHECKS if
                         receipt["status"] == "REVIEW_ONLY" else 0)

    def test_fixture_complete_strict_policy_is_review_only_without_authority(self):
        receipt = audit_installed_scope(_FixturePolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")

    def test_real_checkout_policy_audit_is_diagnostic_not_permission(self):
        self.assert_never_authority(audit_installed_scope())

    def test_one_misclassified_documentation_address_holds_entire_review(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1" and self.enabled:
                    return ScopeDecision(True, target.value, ScopeReason.PRIVATE_LAB)
                return super().decide(target)
        receipt = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")

    def test_wrong_ipv6_loopback_or_bad_normalization_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "[::1]":
                    return ScopeDecision(True, "::01", ScopeReason.LOOPBACK)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_disabled_switch_cannot_admit_private_lab(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "10.0.0.1":
                    return ScopeDecision(True, target.value, ScopeReason.PRIVATE_LAB)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_nonboolean_allowed_identity_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1":
                    return ScopeDecision(0, target.value, ScopeReason.OUT_OF_SCOPE)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_noncanonical_reason_identity_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1":
                    return ScopeDecision(False, target.value, "out_of_scope")
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_polymorphic_decision_identity_holds(self):
        class DerivedDecision(ScopeDecision):
            pass
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1":
                    return DerivedDecision(False, target.value, ScopeReason.OUT_OF_SCOPE)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_policy_exception_is_private_hold_receipt(self):
        def broken(*, allow_private_lab):
            raise RuntimeError("a simulated customer secret that must never leak")
        receipt = audit_installed_scope(broken)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertNotIn("secret", json.dumps(receipt))

    def test_in_process_strict_fixture_never_uses_network_or_subprocess(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")):
            self.assertEqual(audit_installed_scope(_FixturePolicy)["status"], "REVIEW_ONLY")

    def test_invalid_cli_arguments_hold_without_echo(self):
        for args in (["--literal", "customer-secret.example"], ["--help"], ["--json", "--json"]):
            with self.subTest(args=args):
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    exit_code = main(args)
                self.assertEqual(exit_code, 2)
                self.assertEqual(json.loads(buffer.getvalue())["status"], "HOLD")
                self.assertNotIn("customer-secret", buffer.getvalue())
                self.assertEqual(len(buffer.getvalue().splitlines()), 1)

    def test_cli_real_subprocess_is_single_receipt_and_never_success(self):
        script = ROOT / "scripts" / "audit_scope_installed_lab_policy_1422_offline.py"
        proc = subprocess.run(
            [sys.executable, "-B", str(script)],
            capture_output=True, text=True, timeout=15, cwd=ROOT, check=False,
        )
        self.assertIn(proc.returncode, (2, 3))
        self.assertFalse(proc.stderr)
        self.assertEqual(len(proc.stdout.splitlines()), 1)
        receipt = json.loads(proc.stdout)
        self.assert_never_authority(receipt)
        self.assertEqual(proc.returncode, 3 if receipt["status"] == "REVIEW_ONLY" else 2)


if __name__ == "__main__":
    unittest.main()
