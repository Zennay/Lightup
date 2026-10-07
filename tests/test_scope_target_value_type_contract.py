import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class _SpoofingTargetValue(str):
    def strip(self):
        return "127.0.0.1"


class ScopeTargetValueTypeContractTests(unittest.TestCase):
    def test_non_string_target_values_fail_closed_as_invalid_target(self):
        policy = ScopePolicy()
        malformed_values = (
            None,
            False,
            0,
            1,
            b"8.8.8.8",
            bytearray(b"8.8.8.8"),
            ("8.8.8.8",),
            {"host": "8.8.8.8"},
        )

        for value in malformed_values:
            with self.subTest(value=repr(value), value_type=type(value).__name__):
                decision = policy.decide(Target(value=value))  # type: ignore[arg-type]

                self.assertFalse(decision.allowed)
                self.assertIsNone(decision.normalized_host)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_string_subclass_cannot_spoof_a_different_scope_identity(self):
        policy = ScopePolicy()
        value = _SpoofingTargetValue("8.8.8.8")

        decision = policy.decide(Target(value=value))

        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_blank_string_remains_invalid_target(self):
        decision = ScopePolicy().decide(Target(value="   "))

        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_canonical_string_behavior_is_unchanged(self):
        loopback = ScopePolicy().decide(Target(value="127.0.0.1"))
        private_lab = ScopePolicy().decide(Target(value="10.20.30.40"))
        public = ScopePolicy().decide(Target(value="8.8.8.8"))

        self.assertTrue(loopback.allowed)
        self.assertEqual(loopback.reason, ScopeReason.LOOPBACK)

        self.assertTrue(private_lab.allowed)
        self.assertEqual(private_lab.reason, ScopeReason.PRIVATE_LAB)

        self.assertFalse(public.allowed)
        self.assertEqual(public.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
