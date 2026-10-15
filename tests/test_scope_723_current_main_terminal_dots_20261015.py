"""Current-main terminal-dot authority contract for LightUp issue #723.

Deliberate source RED tests use expectedFailure while src/lightup/scope.py is
owned by another worker. A passing test run is NOT evidence of safe policy.
No target I/O, grants, or production state are modified.
"""
from __future__ import annotations

import os
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


_HOST = "terminal-dot.example.test"
_SYNTHETIC_ONLY = Authorization(owner="synthetic-unit-test", reference="FAKE-NOT-CONSENT")


def _decision(value: str, declared_host: str = _HOST):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset((declared_host,)),
    ).decide(Target(value, authorization=_SYNTHETIC_ONLY))


class TerminalDotCurrentMainSourceRed(unittest.TestCase):
    """Installed-source deny expectations; every XFAIL is an UNFIXED defect."""

    @unittest.expectedFailure
    def test_double_terminal_dot_target_must_not_inherit_explicit_host(self):
        decision = _decision(_HOST + "..")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_triple_terminal_dot_target_must_not_inherit_explicit_host(self):
        decision = _decision(_HOST + "...")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_double_terminal_dot_policy_must_not_authorize_plain_target(self):
        decision = _decision(_HOST, _HOST + "..")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_triple_terminal_dot_policy_must_not_authorize_rooted_target(self):
        decision = _decision(_HOST + ".", _HOST + "...")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_double_terminal_dot_localhost_must_not_inherit_loopback(self):
        decision = ScopePolicy().decide(Target("localhost.."))
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.LOOPBACK)

    @unittest.expectedFailure
    def test_triple_terminal_dot_localhost_must_not_inherit_loopback(self):
        decision = ScopePolicy().decide(Target("LOCALHOST..."))
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.LOOPBACK)


_RED_NAMES = (
    "test_double_terminal_dot_target_must_not_inherit_explicit_host",
    "test_triple_terminal_dot_target_must_not_inherit_explicit_host",
    "test_double_terminal_dot_policy_must_not_authorize_plain_target",
    "test_triple_terminal_dot_policy_must_not_authorize_rooted_target",
    "test_double_terminal_dot_localhost_must_not_inherit_loopback",
    "test_triple_terminal_dot_localhost_must_not_inherit_loopback",
)


class TerminalDotCurrentMainControls(unittest.TestCase):
    """Independent green controls + witness integrity (no false RED masking)."""

    def test_canonical_explicit_host_remains_exact(self):
        self.assertEqual(_decision(_HOST).reason, ScopeReason.EXPLICIT_HOST)
        self.assertTrue(_decision(_HOST).allowed)
        self.assertEqual(_decision(_HOST + ".").reason, ScopeReason.EXPLICIT_HOST)
        self.assertTrue(_decision(_HOST + ".").allowed)

    def test_case_fold_with_single_root_dot_stays_equivalent(self):
        decision = _decision(_HOST.upper() + ".")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, _HOST)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_plain_localhost_and_single_root_dot_only(self):
        for name in ("localhost", "localhost.", "LOCALHOST."):
            with self.subTest(host=name):
                decision = ScopePolicy().decide(Target(name))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_unlisted_public_host_denied(self):
        for name in ("other.example.test", "other.example.test."):
            with self.subTest(host=name):
                decision = _decision(name)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_original_source_witnesses_are_real_assertions_not_errors(self):
        # @expectedFailure also catches accidental TypeError and ValueError.
        # An independent TestResult must observe exactly six AssertionError
        # failures, not silently accept an unrelated crash or unexpected green.
        for name in _RED_NAMES:
            with self.subTest(case=name):
                result = unittest.TestResult()
                TerminalDotCurrentMainSourceRed(name).run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertFalse(result.errors)
                self.assertFalse(result.failures)
                self.assertFalse(result.unexpectedSuccesses)
                self.assertEqual(len(result.expectedFailures), 1)
                error_type, _, _ = result.expectedFailures[0][1]
                self.assertIs(error_type, AssertionError)

    def test_entire_source_contract_avoids_network_and_dns(self):
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network attempted")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS attempted")),
            patch.object(socket, "create_connection", side_effect=AssertionError("connect attempted")),
        ):
            for name in _RED_NAMES:
                result = unittest.TestResult()
                TerminalDotCurrentMainSourceRed(name).run(result)
                self.assertEqual(len(result.expectedFailures), 1, name)
            self.assertTrue(_decision(_HOST).allowed)
            self.assertFalse(_decision("unlisted.example.test").allowed)

    def test_policy_collections_and_synthetic_authorization_unchanged(self):
        policy = ScopePolicy(explicit_hosts=frozenset((_HOST,)))
        original = policy.explicit_hosts
        auth = _SYNTHETIC_ONLY
        decision = policy.decide(Target(_HOST + ".", authorization=auth))
        self.assertTrue(decision.allowed)
        self.assertEqual(original, policy.explicit_hosts)
        self.assertEqual(auth.reference, "FAKE-NOT-CONSENT")


if __name__ == "__main__":
    unittest.main()
