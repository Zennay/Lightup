"""#1422: real LAB_ONLY ActivationGate issue chain; offline RED witnesses.

No network, DNS, executor, adapter, persisted grant or real permit is used.
Known unsafe current-source admissions are intentional expected failures.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy, ExecutionPermit
from lightup.models import Target
from lightup.scope import ScopePolicy

SCRIPT = ROOT / "scripts" / "audit_scope_activation_lab_permit_1422_offline.py"
SPEC = importlib.util.spec_from_file_location("scope_activation_lab_permit_1422", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ActualActivationPermitChainRED(unittest.TestCase):
    def setUp(self):
        self.gate = ActivationGate(
            ScopePolicy(allow_private_lab=True),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )

    def _must_deny_without_target_io(self, literal: str):
        # The source's only token creator is replaced with a marker to avoid
        # generating any real authorization artifact.
        with patch("lightup.activation.token_urlsafe", return_value="SYNTHETIC"):
            with self.assertRaises(PermissionError):
                self.gate.issue(Target(literal), "synthetic_reference_only")

    @unittest.expectedFailure
    def test_documentation_192_0_2_denied_before_permit(self):
        self._must_deny_without_target_io("192.0.2.1")

    @unittest.expectedFailure
    def test_documentation_198_51_100_denied_before_permit(self):
        self._must_deny_without_target_io("198.51.100.1")

    @unittest.expectedFailure
    def test_documentation_203_0_113_denied_before_permit(self):
        self._must_deny_without_target_io("203.0.113.1")

    @unittest.expectedFailure
    def test_benchmark_198_18_denied_before_permit(self):
        self._must_deny_without_target_io("198.18.0.1")

    @unittest.expectedFailure
    def test_unspecified_0_0_0_0_denied_before_permit(self):
        self._must_deny_without_target_io("0.0.0.0")

    @unittest.expectedFailure
    def test_broadcast_255_255_255_255_denied_before_permit(self):
        self._must_deny_without_target_io("255.255.255.255")

    @unittest.expectedFailure
    def test_ipv6_documentation_denied_before_permit(self):
        self._must_deny_without_target_io("[2001:db8::1]")

    @unittest.expectedFailure
    def test_ipv4_link_local_denied_before_permit(self):
        self._must_deny_without_target_io("169.254.1.1")

    @unittest.expectedFailure
    def test_ipv4_mapped_documentation_denied_before_permit(self):
        self._must_deny_without_target_io("[::ffff:192.0.2.1]")

    @unittest.expectedFailure
    def test_ipv6_link_local_denied_before_permit(self):
        self._must_deny_without_target_io("[fe80::1]")

    def test_actual_known_lab_controls_are_not_public_approval(self):
        for literal in AUDIT.SAFE_LAB:
            with self.subTest(sample=literal):
                with patch("lightup.activation.token_urlsafe", return_value="SYNTHETIC"):
                    permit = self.gate.issue(Target(literal), "synthetic_reference_only")
                self.assertIs(type(permit), ExecutionPermit)
                self.assertEqual(permit.permit_id, "SYNTHETIC")
                self.assertIs(permit.mode, ActivationMode.LAB_ONLY)

    def test_plan_only_is_terminal_for_all_synthetic_samples(self):
        gate = ActivationGate(
            ScopePolicy(), ActivationPolicy(mode=ActivationMode.PLAN_ONLY)
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for literal in AUDIT.SAFE_LAB + AUDIT.NOT_LAB:
                with self.subTest(sample=literal), self.assertRaises(PermissionError):
                    gate.issue(Target(literal), "synthetic_reference_only")

    def test_lockdown_denies_special_and_private_except_loopback(self):
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for literal in (
                "192.0.2.1", "198.18.0.1", "[2001:db8::1]",
                "169.254.1.1", "10.1.2.3", "192.168.1.1",
            ):
                with self.subTest(sample=literal), self.assertRaises(PermissionError):
                    gate.issue(Target(literal), "synthetic_reference_only")

    def test_expected_red_is_assertion_not_import_error(self):
        names = tuple(
            name for name in dir(self)
            if name.startswith("test_")
            and name.endswith("_denied_before_permit")
        )
        self.assertEqual(len(names), 10)
        result = unittest.TestResult()
        unittest.TestSuite(type(self)(name) for name in names).run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(len(result.expectedFailures), len(names))
        for _case, trace in result.expectedFailures:
            self.assertIn("AssertionError", trace)

    def test_auditor_reports_unsafe_chain_only_as_hold(self):
        result = AUDIT.audit()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["checked"], 46)
        self.assertGreaterEqual(result["violations"], 10)
        self.assertEqual(type(result["violations"]), int)
        for key in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "scan_allowed", "merge_approved", "release_approved",
        ):
            self.assertIs(result[key], False)

    def test_ipv4_mapped_and_ipv6_linklocal_lockdown_is_terminal(self):
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for literal in ("[::ffff:192.0.2.1]", "[fe80::1]"):
                with self.subTest(sample=literal), self.assertRaises(PermissionError):
                    gate.issue(Target(literal), "synthetic_reference_only")

    def test_cli_single_fixed_receipt_no_literal_or_token_reflection(self):
        run = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT, capture_output=True, text=True, timeout=12, check=False,
        )
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stderr, "")
        self.assertEqual(len(run.stdout.splitlines()), 1)
        receipt = json.loads(run.stdout)
        self.assertEqual(receipt, AUDIT.audit())
        self.assertNotIn("192.0.2.1", run.stdout)
        self.assertNotIn("NO_REAL_PERMIT", run.stdout)

    def test_invalid_argv_always_hold_without_reflection(self):
        secret = "SYNTHETIC_NEVER_ECHO_SECRET"
        run = subprocess.run(
            [sys.executable, str(SCRIPT), "--target", secret],
            cwd=ROOT, capture_output=True, text=True, timeout=12, check=False,
        )
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stderr, "")
        self.assertEqual(json.loads(run.stdout)["checked"], 0)
        self.assertNotIn(secret, run.stdout)

    def test_unanticipated_gate_failure_fails_closed_without_exception_detail(self):
        with patch.object(AUDIT, "ActivationGate", side_effect=ValueError("SENSITIVE")):
            receipt = AUDIT.audit()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["checked"], 0)
        self.assertEqual(receipt["violations"], 1)
        self.assertNotIn("SENSITIVE", json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
