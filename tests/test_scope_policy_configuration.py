import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyConfigurationTests(unittest.TestCase):
    def test_truthy_string_cannot_enable_private_lab(self):
        with self.assertRaisesRegex(TypeError, "allow_private_lab must be a bool"):
            ScopePolicy(allow_private_lab="false")  # type: ignore[arg-type]

    def test_falsy_string_cannot_disable_public_authorization(self):
        with self.assertRaisesRegex(
            TypeError, "require_authorization_for_public must be a bool"
        ):
            ScopePolicy(require_authorization_for_public="")  # type: ignore[arg-type]

    def test_exact_false_keeps_private_lab_disabled(self):
        decision = ScopePolicy(allow_private_lab=False).decide(Target("10.20.30.40"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_true_keeps_explicit_private_lab_opt_in(self):
        decision = ScopePolicy(allow_private_lab=True).decide(Target("10.20.30.40"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.PRIVATE_LAB)

    def test_exact_public_authorization_switches_construct(self):
        self.assertTrue(ScopePolicy(require_authorization_for_public=True).require_authorization_for_public)
        self.assertFalse(
            ScopePolicy(require_authorization_for_public=False).require_authorization_for_public
        )


if __name__ == "__main__":
    unittest.main()
