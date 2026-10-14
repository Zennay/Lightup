"""Offline regression for the immutable scope decision boundary (issue #349).

No network, DNS, scanning, or target execution is performed.
"""
import unittest
from dataclasses import FrozenInstanceError

from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


class ScopeDecisionImmutabilityAcceptance(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy()

    def _assert_cannot_reassign(self, decision):
        original = (decision.allowed, decision.normalized_host, decision.reason)
        for field, candidate in (
            ("allowed", not decision.allowed),
            ("normalized_host", "attacker.example.test"),
            ("reason", ScopeReason.LOOPBACK),
        ):
            with self.subTest(field=field):
                with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                    setattr(decision, field, candidate)
                self.assertEqual(
                    (decision.allowed, decision.normalized_host, decision.reason),
                    original,
                )

    def test_denied_decision_is_immutable(self):
        decision = self.policy.decide(Target("outside.example.test"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        self._assert_cannot_reassign(decision)

    def test_allowed_loopback_decision_is_immutable(self):
        decision = self.policy.decide(Target("localhost"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)
        self._assert_cannot_reassign(decision)

    def test_independent_decisions_survive_failed_mutation(self):
        first = self.policy.decide(Target("outside.example.test"))
        second = self.policy.decide(Target("outside.example.test"))
        self.assertIsNot(first, second)
        self._assert_cannot_reassign(first)
        self.assertEqual(second, first)
        self.assertEqual(self.policy.decide(Target("outside.example.test")), second)

    def test_decision_is_a_value_object_not_an_authority_token(self):
        denied = self.policy.decide(Target("outside.example.test"))
        forged = ScopeDecision(True, denied.normalized_host, ScopeReason.LOOPBACK)
        self.assertTrue(forged.allowed)
        self.assertFalse(self.policy.decide(Target("outside.example.test")).allowed)
        self.assertFalse(denied.allowed)


if __name__ == "__main__":
    unittest.main()
