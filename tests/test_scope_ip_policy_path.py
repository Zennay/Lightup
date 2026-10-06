import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeIpPolicyPathTests(unittest.TestCase):
    def setUp(self):
        self.auth = Authorization(owner="example-owner", reference="AUTH-IP-PATH-001")

    def test_public_ipv4_in_explicit_hosts_does_not_authorize_ip(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"8.8.8.8"}))

        decision = policy.decide(Target("8.8.8.8", authorization=self.auth))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "8.8.8.8")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_public_ipv4_cannot_fall_through_to_host_when_auth_requirement_disabled(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"8.8.8.8"}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(Target("8.8.8.8"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_public_ipv4_network_uses_network_authorization_path(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.8/32",),
        )

        decision = policy.decide(Target("8.8.8.8", authorization=self.auth))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "8.8.8.8")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_public_ipv4_network_still_requires_authorization(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.8/32",),
        )

        decision = policy.decide(Target("8.8.8.8"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_loopback_classification_precedes_explicit_host_text(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"127.0.0.1"}))

        decision = policy.decide(Target("127.0.0.1"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "127.0.0.1")
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)


if __name__ == "__main__":
    unittest.main()
