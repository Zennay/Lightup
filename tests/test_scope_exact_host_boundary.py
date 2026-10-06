import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeExactHostBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.auth = Authorization(owner="example-owner", reference="AUTH-HOST-001")

    def test_parent_host_does_not_authorize_subdomain(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"example.test"}))

        decision = policy.decide(
            Target("api.example.test", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "api.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_wildcard_text_does_not_authorize_concrete_subdomain(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"*.example.test"}))

        decision = policy.decide(
            Target("api.example.test", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_leading_dot_text_does_not_authorize_subdomain(self):
        policy = ScopePolicy(explicit_hosts=frozenset({".example.test"}))

        decision = policy.decide(
            Target("api.example.test", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_suffix_lookalike_does_not_inherit_authority(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"})
        )

        decision = policy.decide(
            Target(
                "security.example.test.attacker.test",
                authorization=self.auth,
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.normalized_host,
            "security.example.test.attacker.test",
        )
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_host_keeps_case_and_trailing_dot_normalization(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"})
        )

        decision = policy.decide(
            Target(
                "https://SECURITY.EXAMPLE.TEST./status",
                authorization=self.auth,
            )
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)


if __name__ == "__main__":
    unittest.main()
