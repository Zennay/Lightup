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

    @unittest.expectedFailure
    def test_matrix_32_malformed_target_dot_counts_and_url_forms_must_deny(self):
        # Materialize *all* decisions before the assertion: no early exit
        # silently truncates the 64-case input matrix.
        targets = tuple(
            target
            for count in range(2, 34)
            for target in (
                _HOST + "." * count,
                "https://" + _HOST + "." * count + "/synthetic-only",
            )
        )
        decisions = tuple(_decision(target) for target in targets)
        self.assertEqual(len(decisions), 64)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_matrix_32_malformed_config_dot_counts_and_targets_must_deny(self):
        # The bad *configured* hostname must not gain authority from a
        # plain or singly rooted input target (distinct from target parser).
        pairs = tuple(
            (target, _HOST + "." * count)
            for count in range(2, 34)
            for target in (_HOST, _HOST + ".")
        )
        decisions = tuple(_decision(target, declaration) for target, declaration in pairs)
        self.assertEqual(len(decisions), 64)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_matrix_32_malformed_localhost_dot_counts_and_url_forms_must_deny(self):
        # No synthetic Authorization is supplied: loopback trust alone is
        # enough to reproduce the installed source bypass.
        targets = tuple(
            target
            for count in range(2, 34)
            for target in (
                "LOCALHOST" + "." * count,
                "http://localhost" + "." * count + "/synthetic-only",
            )
        )
        decisions = tuple(ScopePolicy(allow_private_lab=False).decide(Target(target))
                          for target in targets)
        self.assertEqual(len(decisions), 64)
        self.assertFalse(any(decision.allowed for decision in decisions))


_RED_NAMES = (
    "test_double_terminal_dot_target_must_not_inherit_explicit_host",
    "test_triple_terminal_dot_target_must_not_inherit_explicit_host",
    "test_double_terminal_dot_policy_must_not_authorize_plain_target",
    "test_triple_terminal_dot_policy_must_not_authorize_rooted_target",
    "test_double_terminal_dot_localhost_must_not_inherit_loopback",
    "test_triple_terminal_dot_localhost_must_not_inherit_loopback",
    "test_matrix_32_malformed_target_dot_counts_and_url_forms_must_deny",
    "test_matrix_32_malformed_config_dot_counts_and_targets_must_deny",
    "test_matrix_32_malformed_localhost_dot_counts_and_url_forms_must_deny",
)


class _AssertionWitnessResult(unittest.TestResult):
    """Record actual exception types, not TestResult's formatted tracebacks."""

    def __init__(self):
        super().__init__()
        self.real_expected_types = []

    def addExpectedFailure(self, test, err):
        self.real_expected_types.append((err[0], str(err[1])))
        super().addExpectedFailure(test, err)


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
        # An independent TestResult must observe exactly nine AssertionError
        # failures, not silently accept an unrelated crash or unexpected green.
        for name in _RED_NAMES:
            with self.subTest(case=name):
                result = _AssertionWitnessResult()
                TerminalDotCurrentMainSourceRed(name).run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertFalse(result.errors)
                self.assertFalse(result.failures)
                self.assertFalse(result.unexpectedSuccesses)
                self.assertEqual(len(result.expectedFailures), 1)
                self.assertEqual(
                    result.real_expected_types,
                    [(AssertionError, "True is not false")],
                )

    def test_entire_source_contract_avoids_network_and_dns(self):
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network attempted")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS attempted")),
            patch.object(socket, "create_connection", side_effect=AssertionError("connect attempted")),
        ):
            for name in _RED_NAMES:
                result = _AssertionWitnessResult()
                TerminalDotCurrentMainSourceRed(name).run(result)
                self.assertEqual(len(result.expectedFailures), 1, name)
                self.assertEqual(
                    result.real_expected_types,
                    [(AssertionError, "True is not false")],
                )
            self.assertTrue(_decision(_HOST).allowed)
            self.assertFalse(_decision("unlisted.example.test").allowed)

    def test_policy_side_url_decorations_cannot_grant_embedded_hostname(self):
        policy_entries = (
            "https://" + _HOST,
            "http://operator@" + _HOST,
            _HOST + ":443",
            _HOST + "/synthetic-path",
            _HOST + "?synthetic-query=1",
            _HOST + "#synthetic-fragment",
            "//" + _HOST,
        )
        for entry in policy_entries:
            with self.subTest(policy_entry=entry):
                decision = _decision(_HOST, entry)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_policy_side_whitespace_decorations_cannot_grant_host(self):
        policy_entries = (
            " " + _HOST,
            _HOST + " ",
            "\t" + _HOST,
            _HOST + "\n",
            "\r" + _HOST,
            _HOST + "\u00a0",
        )
        for entry in policy_entries:
            with self.subTest(repr_entry=repr(entry)):
                decision = _decision(_HOST, entry)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_policy_side_wildcard_leading_dot_and_suffix_never_expand_scope(self):
        entries = (
            "*.example.test",
            ".example.test",
            "example.test",
            _HOST + ".attacker.test",
            "terminal-dot.example",
        )
        for entry in entries:
            with self.subTest(policy_entry=entry):
                decision = _decision(_HOST, entry)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_canonical_target_url_and_whitespace_still_match_exact_policy(self):
        targets = (
            "https://" + _HOST + "/synthetic-only",
            "https://" + _HOST.upper() + ":443/synthetic-only?q=1",
            "\t" + _HOST + " ",
            _HOST + ".",
        )
        for target in targets:
            with self.subTest(target=target):
                decision = _decision(target)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
                self.assertEqual(decision.normalized_host, _HOST)

    def test_single_root_dot_policy_entry_remains_canonical(self):
        for policy_entry in (_HOST + ".", _HOST.upper() + "."):
            for target in (_HOST, _HOST.upper() + "."):
                with self.subTest(config=policy_entry, target=target):
                    decision = _decision(target, policy_entry)
                    self.assertTrue(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_masked_runtime_error_cannot_masquerade_as_source_red(self):
        # A plain @expectedFailure would swallow this unrelated exception.
        # Our independent witness must *recognize* and reject this outcome.
        with patch(f"{__name__}._decision", side_effect=TypeError("synthetic masking")):
            result = _AssertionWitnessResult()
            TerminalDotCurrentMainSourceRed(
                "test_double_terminal_dot_target_must_not_inherit_explicit_host"
            ).run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertEqual(result.real_expected_types, [(TypeError, "synthetic masking")])
        self.assertNotEqual(result.real_expected_types, [(AssertionError, "True is not false")])

    def test_untrusted_fixture_is_not_authenticated_customer_approval(self):
        # Genuine customer/operator provenance is intentionally unavailable.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset((_HOST,)),
        )
        for value in (_HOST, _HOST + ".", _HOST + ".."):
            with self.subTest(value=value):
                decision = policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_exact_positive_controls_stay_disjoint(self):
        # A malformed other hostname must not gain membership just because
        # the test fixture's own canonical host was explicitly configured.
        for value in ("not-" + _HOST, "x." + _HOST, _HOST + ".evil.test"):
            decision = _decision(value)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

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
