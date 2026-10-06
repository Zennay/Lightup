import os
import sys
import unittest
from dataclasses import FrozenInstanceError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeDecisionImmutabilityTests(unittest.TestCase):
    def _assert_fields_are_frozen(self, decision):
        original = decision

        for field, value in (
            ("allowed", not decision.allowed),
            ("normalized_host", "forged.example.test"),
            ("reason", ScopeReason.LOOPBACK),
        ):
            with self.subTest(field=field):
                with self.assertRaises(FrozenInstanceError):
                    setattr(decision, field, value)
                self.assertEqual(decision, original)

    def test_denied_scope_decision_cannot_be_widened_in_place(self):
        decision = ScopePolicy().decide(Target("public.example.test"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        self._assert_fields_are_frozen(decision)

    def test_allowed_scope_decision_cannot_be_rewritten_in_place(self):
        decision = ScopePolicy().decide(Target("127.0.0.1"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)
        self._assert_fields_are_frozen(decision)

    def test_repeated_decisions_are_equal_but_independent_values(self):
        policy = ScopePolicy()
        target = Target("unlisted.example.test")

        first = policy.decide(target)
        second = policy.decide(target)

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self._assert_fields_are_frozen(first)
        self.assertEqual(second, policy.decide(target))


if __name__ == "__main__":
    unittest.main()
