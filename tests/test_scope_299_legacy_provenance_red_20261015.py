"""Issue #299: synthetic legacy authorization provenance, installed-source RED contract.

Only canonical in-memory test inputs (.example.test and documentation IPs).
Never dispatch a handler, resolve DNS, issue live consent, or contact a target.
Existing source is intentionally NOT changed by this acceptance branch.
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


HOST = "review.example.test"
PUBLIC_IP = "203.0.113.27"
CAPABILITY = "synthetic-no-dispatch"


def _host_policy() -> ScopePolicy:
    return ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({HOST}))


def _network_policy() -> ScopePolicy:
    return ScopePolicy(allow_private_lab=False, explicit_networks=("203.0.113.0/24",))


class _ForeignString(str):
    """Deliberate producer-noncanonical subclass, never an issuer identity."""


class LegacyAuthorization299Tests(unittest.TestCase):
    def test_canonical_public_host_keeps_current_scope_behavior(self):
        auth = Authorization(owner="fictional-owner", reference="NOT-A-CONSENT")
        target = Target(HOST, authorization=auth)
        self.assertEqual(_host_policy().decide(target).reason, ScopeReason.EXPLICIT_HOST)
        self.assertTrue(_host_policy().decide(target).allowed)
        self.assertEqual((auth.owner, auth.reference), ("fictional-owner", "NOT-A-CONSENT"))

    def test_canonical_public_network_keeps_current_scope_behavior(self):
        auth = Authorization(owner="fictional-owner", reference="NOT-A-CONSENT")
        self.assertEqual(
            _network_policy().decide(Target(PUBLIC_IP, authorization=auth)).reason,
            ScopeReason.EXPLICIT_NETWORK,
        )

    def test_missing_public_authorization_still_denies(self):
        self.assertEqual(
            _host_policy().decide(Target(HOST)).reason, ScopeReason.AUTHORIZATION_MISSING
        )
        self.assertEqual(
            _network_policy().decide(Target(PUBLIC_IP)).reason,
            ScopeReason.AUTHORIZATION_MISSING,
        )

    def test_expired_public_authorization_still_denies(self):
        expired = Authorization(
            owner="fictional-owner",
            reference="NOT-A-CONSENT",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        self.assertEqual(
            _host_policy().decide(Target(HOST, authorization=expired)).reason,
            ScopeReason.AUTHORIZATION_EXPIRED,
        )

    def test_plan_only_cannot_issue_even_with_canonical_provenance(self):
        gate = ActivationGate(_host_policy(), ActivationPolicy())
        with self.assertRaises(PermissionError):
            gate.issue(
                Target(HOST, Authorization("fictional-owner", "NOT-A-CONSENT")),
                CAPABILITY,
            )

    def test_lab_only_does_not_promote_public_target_to_lab(self):
        gate = ActivationGate(
            _host_policy(),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB"),
        )
        with self.assertRaises(PermissionError):
            gate.issue(
                Target(HOST, Authorization("fictional-owner", "NOT-A-CONSENT")),
                CAPABILITY,
            )

    @unittest.expectedFailure
    def test_red_blank_owner_cannot_allow_explicit_public_host(self):
        auth = Authorization(owner="", reference="NOT-A-CONSENT")
        self.assertFalse(_host_policy().decide(Target(HOST, auth)).allowed)

    @unittest.expectedFailure
    def test_red_blank_reference_cannot_allow_explicit_public_network(self):
        auth = Authorization(owner="fictional-owner", reference="")
        self.assertFalse(_network_policy().decide(Target(PUBLIC_IP, auth)).allowed)

    @unittest.expectedFailure
    def test_red_whitespace_only_owner_cannot_allow_public_host(self):
        auth = Authorization(owner=" \t ", reference="NOT-A-CONSENT")
        self.assertFalse(_host_policy().decide(Target(HOST, auth)).allowed)

    @unittest.expectedFailure
    def test_red_padded_provenance_cannot_allow_public_network(self):
        auth = Authorization(owner=" fictional-owner ", reference=" NOT-A-CONSENT ")
        self.assertFalse(_network_policy().decide(Target(PUBLIC_IP, auth)).allowed)

    @unittest.expectedFailure
    def test_red_noncanonical_subclass_provenance_cannot_allow_public_host(self):
        auth = Authorization(owner=_ForeignString("fictional-owner"), reference="NOT-A-CONSENT")
        self.assertFalse(_host_policy().decide(Target(HOST, auth)).allowed)

    @unittest.expectedFailure
    def test_red_authorized_mode_cannot_sanitize_blank_client_provenance(self):
        # An operator activation marker is NOT a replacement for client authority.
        gate = ActivationGate(
            _host_policy(),
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED, activation_reference="SYNTHETIC-OPERATOR"
            ),
        )
        with self.assertRaises(PermissionError):
            gate.issue(Target(HOST, Authorization(owner="", reference="")), CAPABILITY)


class LegacyAuthorization299OracleTests(unittest.TestCase):
    def test_strict_installed_source_red_oracle_and_green_controls(self):
        """Reject crashes/skips and unexpected successes disguised as intended REDs.

        This verifier replays the six RED + six controls inside a private result.
        It will FAIL as soon as the source is fixed, until the owner migrates the
        RED assertions to ordinary green tests. It is *not* release evidence.
        """
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(LegacyAuthorization299Tests)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.testsRun, 12)
        self.assertEqual(result.errors, [], "unexpected source/test harness error")
        self.assertEqual(result.failures, [], "unexpected green control failure")
        self.assertEqual(result.skipped, [], "a required case was skipped")
        self.assertEqual(
            len(result.expectedFailures), 6,
            "source RED contract changed: investigate; never auto-promote",
        )
        self.assertEqual(result.unexpectedSuccesses, [])
        failures = {
            case._testMethodName: detail
            for case, detail in result.expectedFailures
        }
        expected = {
            "test_red_blank_owner_cannot_allow_explicit_public_host",
            "test_red_blank_reference_cannot_allow_explicit_public_network",
            "test_red_whitespace_only_owner_cannot_allow_public_host",
            "test_red_padded_provenance_cannot_allow_public_network",
            "test_red_noncanonical_subclass_provenance_cannot_allow_public_host",
            "test_red_authorized_mode_cannot_sanitize_blank_client_provenance",
        }
        self.assertEqual(set(failures), expected)
        for name, detail in failures.items():
            if "authorized_mode" in name:
                self.assertIn("AssertionError: PermissionError not raised", detail)
            else:
                self.assertIn("AssertionError: True is not false", detail)
            self.assertNotIn("Traceback (most recent call last):\\n  File \"", detail.split("AssertionError:")[-1])


if __name__ == "__main__":
    unittest.main()
