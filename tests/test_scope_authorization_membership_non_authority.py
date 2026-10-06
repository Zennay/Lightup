import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationMembershipNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization(
            owner="example-owner",
            reference="AUTH-MEMBERSHIP-001",
        )

    def test_current_authorization_cannot_mint_explicit_host_membership(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"allowed.example.test"}),
            require_authorization_for_public=True,
        )

        decision = policy.decide(
            Target("blocked.example.test", authorization=self.authorization)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "blocked.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_current_authorization_cannot_mint_explicit_network_membership(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )

        decision = policy.decide(Target("8.8.4.4", authorization=self.authorization))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "8.8.4.4")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_disabling_public_authorization_requirement_does_not_create_membership(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"allowed.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=False,
        )

        host_decision = policy.decide(
            Target("blocked.example.test", authorization=self.authorization)
        )
        network_decision = policy.decide(
            Target("8.8.4.4", authorization=self.authorization)
        )

        self.assertFalse(host_decision.allowed)
        self.assertEqual(host_decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertFalse(network_decision.allowed)
        self.assertEqual(network_decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_authorization_cannot_rescue_invalid_target_identity(self):
        decision = ScopePolicy(
            explicit_hosts=frozenset({"allowed.example.test"})
        ).decide(Target("   ", authorization=self.authorization))

        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_declared_membership_still_requires_and_accepts_current_authorization(self):
        host_policy = ScopePolicy(
            explicit_hosts=frozenset({"allowed.example.test"})
        )
        network_policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
        )

        host_decision = host_policy.decide(
            Target("allowed.example.test", authorization=self.authorization)
        )
        network_decision = network_policy.decide(
            Target("8.8.8.8", authorization=self.authorization)
        )

        self.assertTrue(host_decision.allowed)
        self.assertEqual(host_decision.reason, ScopeReason.EXPLICIT_HOST)
        self.assertTrue(network_decision.allowed)
        self.assertEqual(network_decision.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
