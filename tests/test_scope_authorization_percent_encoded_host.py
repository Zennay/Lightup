import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationPercentEncodedHostTests(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization(
            owner="example-owner",
            reference="AUTH-PERCENT-HOST",
        )

    def test_percent_encoded_dot_does_not_match_explicit_host(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"})
        )

        decision = policy.decide(
            Target(
                "https://security%2eexample%2etest/assessment",
                authorization=self.authorization,
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.normalized_host, "security%2eexample%2etest"
        )
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_percent_encoded_suffix_cannot_inherit_allowlisted_prefix(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"})
        )

        decision = policy.decide(
            Target(
                "https://security.example.test%2eattacker.test/",
                authorization=self.authorization,
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.normalized_host,
            "security.example.test%2eattacker.test",
        )
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_percent_encoded_localhost_dot_does_not_gain_loopback_trust(self):
        decision = ScopePolicy().decide(Target("https://localhost%2e/"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "localhost%2e")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_percent_encoded_loopback_ipv4_does_not_gain_loopback_trust(self):
        decision = ScopePolicy().decide(
            Target("https://127%2e0%2e0%2e1/")
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "127%2e0%2e0%2e1")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_percent_encoded_ipv4_does_not_match_explicit_network(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))

        decision = policy.decide(
            Target(
                "https://8%2e8%2e8%2e8/",
                authorization=self.authorization,
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "8%2e8%2e8%2e8")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_percent_encoded_ipv4_digits_do_not_gain_loopback_trust(self):
        decision = ScopePolicy().decide(
            Target("https://%31%32%37.0.0.1/")
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "%31%32%37.0.0.1")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_canonical_host_remains_explicitly_authorizable(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"})
        )

        decision = policy.decide(
            Target(
                "https://security.example.test/assessment",
                authorization=self.authorization,
            )
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_canonical_ipv4_remains_on_explicit_network_path(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))

        decision = policy.decide(
            Target("8.8.8.8", authorization=self.authorization)
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "8.8.8.8")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
