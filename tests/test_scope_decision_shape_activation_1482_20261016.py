"""#1482: synthetic, offline installed ActivationGate decision-integrity contract.

This file does not activate adapters or call real targets. Source contract REDs
are intentional and must not be silently converted to green without a fix.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.activation_decision_shape_review_1482 import review_decision_shape
from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


class ForgedScopePolicy:
    """Only for a constructed in-process trust-boundary witness."""

    def decide(self, _target):
        return ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK)


def lab_gate(policy):
    return ActivationGate(
        policy,
        ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="SYNTHETIC-LAB"),
    )


class OriginalSourceAcceptance(unittest.TestCase):
    def test_normal_lab_loopback_still_issues(self):
        permit = lab_gate(ScopePolicy()).issue(Target("127.0.0.1"), "offline-canary")
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.target, "127.0.0.1")

    def test_public_explicit_host_still_denied_in_lab_mode(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"public.example.test"}))
        target = Target(
            "public.example.test",
            Authorization("fictional-owner", "fictional-reference"),
        )
        with self.assertRaises(PermissionError):
            lab_gate(policy).issue(target, "offline-canary")

    def test_plan_only_still_denies(self):
        gate = ActivationGate(ScopePolicy(), ActivationPolicy())
        with self.assertRaises(PermissionError):
            gate.issue(Target("localhost"), "offline-canary")

    @unittest.expectedFailure
    def test_source_red_rejects_noncanonical_constructor_policy(self):
        """Original accepts a policy duck-type that can forge LAB/loopback."""
        with self.assertRaises(TypeError):
            lab_gate(ForgedScopePolicy())

    @unittest.expectedFailure
    def test_source_red_rejects_truthy_nonboolean_allowed(self):
        """Original treats 'yes' as an allow boolean."""
        fake_decision = ScopeDecision("yes", "127.0.0.1", ScopeReason.LOOPBACK)
        with patch.object(ScopePolicy, "decide", return_value=fake_decision):
            with self.assertRaises(PermissionError):
                lab_gate(ScopePolicy()).issue(Target("127.0.0.1"), "offline-canary")

    @unittest.expectedFailure
    def test_source_red_rejects_target_to_decision_host_substitution(self):
        """Original stamps returned normalized_host without identity binding."""
        fake_decision = ScopeDecision(True, "other.example.test", ScopeReason.LOOPBACK)
        with patch.object(ScopePolicy, "decide", return_value=fake_decision):
            with self.assertRaises(PermissionError):
                lab_gate(ScopePolicy()).issue(Target("127.0.0.1"), "offline-canary")


class ShapeReviewerTests(unittest.TestCase):
    def test_real_normal_lab_decision_is_review_only(self):
        policy = ScopePolicy()
        target = Target("127.0.0.1")
        verdict = review_decision_shape(policy, target, policy.decide(target))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertFalse(verdict.authorizes_execution)
        self.assertFalse(verdict.authorizes_release)

    def test_real_out_of_scope_denial_is_review_only_not_authorization(self):
        policy = ScopePolicy()
        target = Target("public.example.test")
        verdict = review_decision_shape(policy, target, policy.decide(target))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertFalse(verdict.authorizes_execution)

    def test_noncanonical_policy_is_hold_without_running_decide(self):
        fake = ForgedScopePolicy()
        with patch.object(fake, "decide", side_effect=AssertionError("must not invoke")):
            verdict = review_decision_shape(
                fake, Target("public.example.test"),
                ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK),
            )
        self.assertEqual(verdict.status, "HOLD")

    def test_truthy_string_allowed_is_hold(self):
        verdict = review_decision_shape(
            ScopePolicy(), Target("localhost"),
            ScopeDecision("yes", "localhost", ScopeReason.LOOPBACK),
        )
        self.assertEqual(verdict.reason, "noncanonical_decision_fields")

    def test_wrong_host_is_hold(self):
        verdict = review_decision_shape(
            ScopePolicy(), Target("localhost"),
            ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK),
        )
        self.assertEqual(verdict.reason, "host_mismatch")

    def test_public_loopback_claim_is_hold(self):
        verdict = review_decision_shape(
            ScopePolicy(), Target("public.example.test"),
            ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK),
        )
        self.assertEqual(verdict.reason, "invalid_loopback_claim")

    def test_false_allowed_and_loopback_reason_is_hold(self):
        verdict = review_decision_shape(
            ScopePolicy(), Target("localhost"),
            ScopeDecision(False, "localhost", ScopeReason.LOOPBACK),
        )
        self.assertEqual(verdict.reason, "inconsistent_decision")

    def test_bogus_decision_object_is_hold(self):
        verdict = review_decision_shape(ScopePolicy(), Target("localhost"), object())
        self.assertEqual(verdict.reason, "noncanonical_envelope")

    def test_oversized_input_is_hold_without_parser(self):
        with patch.object(
            ScopePolicy, "normalize_host",
            side_effect=AssertionError("oversized input must not parse"),
        ):
            verdict = review_decision_shape(
                ScopePolicy(), Target("x" * 513),
                ScopeDecision(True, "x" * 513, ScopeReason.EXPLICIT_HOST),
            )
        self.assertEqual(verdict.reason, "invalid_target_value")

    def test_fake_target_subclass_is_hold(self):
        class TargetChild(Target):
            pass
        verdict = review_decision_shape(
            ScopePolicy(), TargetChild("localhost"),
            ScopeDecision(True, "localhost", ScopeReason.LOOPBACK),
        )
        self.assertEqual(verdict.reason, "noncanonical_envelope")

    def test_verdict_is_not_modifiable_to_grant(self):
        verdict = review_decision_shape(
            ScopePolicy(), Target("localhost"),
            ScopeDecision(True, "localhost", ScopeReason.LOOPBACK),
        )
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(verdict, "authorizes_execution", True)
        self.assertFalse(verdict.authorizes_execution)

    def test_exact_review_is_network_free(self):
        import socket
        with patch.object(socket, "socket", side_effect=AssertionError("no sockets")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("no DNS")):
            verdict = review_decision_shape(
                ScopePolicy(), Target("localhost"),
                ScopeDecision(True, "localhost", ScopeReason.LOOPBACK),
            )
        self.assertEqual(verdict.status, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
