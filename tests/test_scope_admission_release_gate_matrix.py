"""Offline scope-decision precedence regression matrix.

Non-networked guards only; deliberately does not assert which positive
authorization fields the active execution-policy owner must require.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAdmissionMatrixTests(unittest.TestCase):
    def test_undeclared_hosts_and_networks_never_get_membership(self):
        candidates = (
            "unlisted.example.test",
            "https://unlisted.example.test/path",
            "8.8.4.4",
            "https://8.8.4.4/path",
            "2001:4860:4860::8888",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset({"listed.example.test"}),
                    explicit_networks=("8.8.8.0/24",),
                    require_authorization_for_public=False,
                )
                decision = policy.decide(Target(candidate))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_membership_is_not_implicit_public_approval(self):
        cases = (
            (ScopePolicy(explicit_hosts=frozenset({"listed.example.test"})),
             "listed.example.test", ScopeReason.AUTHORIZATION_MISSING),
            (ScopePolicy(explicit_networks=("8.8.8.0/24",)),
             "8.8.8.8", ScopeReason.AUTHORIZATION_MISSING),
        )
        for policy, value, expected in cases:
            with self.subTest(target=value):
                result = policy.decide(Target(value))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, expected)

    def test_disabling_lab_scope_does_not_change_loopback_boundary(self):
        policy = ScopePolicy(allow_private_lab=False)
        for value in ("localhost", "127.0.0.1", "::1"):
            with self.subTest(value=value):
                result = policy.decide(Target(value))
                self.assertTrue(result.allowed)
                self.assertEqual(result.reason, ScopeReason.LOOPBACK)
        result = policy.decide(Target("10.10.10.10"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
