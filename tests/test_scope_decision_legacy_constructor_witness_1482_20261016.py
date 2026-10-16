"""#1482 independently proves constructed legacy scope-policy behavior offline.

The permit objects below are only in-memory synthetic records. They are NEVER
submitted to a handler/adapter. This intentionally source-pinned witness MUST be
retired/replaced when the trusted constructor boundary is fixed.
"""
import os
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.activation_decision_shape_review_1482 import review_decision_shape
from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


class SyntheticDecider:
    def __init__(self):
        self.calls = 0

    def decide(self, _target):
        self.calls += 1
        return ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK)


class ConstructedScopeProvenanceWitness(unittest.TestCase):
    def setUp(self):
        self.socket_guard = patch.object(
            socket, "socket", side_effect=AssertionError("no real sockets")
        )
        self.dns_guard = patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("no real DNS")
        )
        self.socket_guard.start()
        self.dns_guard.start()
        self.addCleanup(self.socket_guard.stop)
        self.addCleanup(self.dns_guard.stop)

    @staticmethod
    def policy(mode):
        return ActivationPolicy(mode=mode, activation_reference="FICTIONAL-ONLY")

    def test_current_legacy_canary_synthetic_policy_can_stamp_lab_record(self):
        injected = SyntheticDecider()
        gate = ActivationGate(injected, self.policy(ActivationMode.LAB_ONLY))
        fake_record = gate.issue(Target("public.example.test"), "no-handler")
        self.assertEqual(fake_record.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(fake_record.target, "public.example.test")
        self.assertEqual(fake_record.capability_id, "no-handler")
        self.assertEqual(injected.calls, 1)

    def test_same_fictional_public_target_denied_by_actual_scope_policy(self):
        gate = ActivationGate(ScopePolicy(), self.policy(ActivationMode.LAB_ONLY))
        with self.assertRaises(PermissionError):
            gate.issue(Target("public.example.test"), "no-handler")

    def test_offline_reviewer_refuses_forged_decider_without_invocation(self):
        injected = SyntheticDecider()
        decision = injected.decide(Target("public.example.test"))
        calls = injected.calls
        report = review_decision_shape(
            injected, Target("public.example.test"), decision
        )
        self.assertEqual(report.status, "HOLD")
        self.assertEqual(report.reason, "noncanonical_policy")
        self.assertEqual(injected.calls, calls)
        self.assertFalse(report.authorizes_execution)
        self.assertFalse(report.authorizes_release)

    def test_even_forged_scope_cannot_override_plan_only_mode(self):
        gate = ActivationGate(SyntheticDecider(), ActivationPolicy())
        with self.assertRaises(PermissionError):
            gate.issue(Target("public.example.test"), "no-handler")

    def test_valid_actual_loopback_remains_provenance_distinct(self):
        real_policy = ScopePolicy()
        target = Target("localhost")
        decision = real_policy.decide(target)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)
        review = review_decision_shape(real_policy, target, decision)
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertFalse(review.authorizes_execution)


if __name__ == "__main__":
    unittest.main()
