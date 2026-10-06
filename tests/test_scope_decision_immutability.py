import unittest
from dataclasses import FrozenInstanceError

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeDecisionImmutabilityTest(unittest.TestCase):
    def assertFrozen(self, decision):
        before = (decision.allowed, decision.normalized_host, decision.reason)

        with self.assertRaises(FrozenInstanceError):
            decision.allowed = not decision.allowed
        with self.assertRaises(FrozenInstanceError):
            decision.normalized_host = "forged.example.test"
        with self.assertRaises(FrozenInstanceError):
            decision.reason = ScopeReason.LOOPBACK

        self.assertEqual(
            (decision.allowed, decision.normalized_host, decision.reason),
            before,
        )

    def test_denied_decision_cannot_be_widened_in_place(self):
        decision = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(),
            explicit_networks=(),
        ).decide(Target("unknown.example.test"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertFrozen(decision)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_allowed_decision_cannot_be_rewritten_after_evaluation(self):
        decision = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(),
            explicit_networks=(),
        ).decide(Target("localhost"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)
        self.assertFrozen(decision)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_repeated_decisions_are_equal_but_independent_immutable_values(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=False,
        )
        target = Target("https://SECURITY.EXAMPLE.TEST./health")

        first = policy.decide(target)
        second = policy.decide(target)

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertFrozen(first)
        self.assertFrozen(second)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
