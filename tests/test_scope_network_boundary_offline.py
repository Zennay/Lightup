"""Offline CIDR-bound authorization tests; no network I/O."""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeNetworkBoundaryTests(unittest.TestCase):
    def test_authorization_is_not_a_substitute_for_cidr_membership(self):
        grant = Authorization(owner="lab", reference="CIDR-APPROVED")
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("8.8.8.0/24",))
        for value in ("8.8.7.255", "8.8.9.0", "1.1.1.1"):
            with self.subTest(target=value):
                decision = policy.decide(Target(value, authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_authorized_public_cidr_is_only_allowed_with_current_grant(self):
        now = datetime.now(timezone.utc)
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("8.8.8.0/24",))
        grants = (
            (None, ScopeReason.AUTHORIZATION_MISSING),
            (Authorization(owner="lab", reference="OLD", valid_until=now - timedelta(days=1)),
             ScopeReason.AUTHORIZATION_EXPIRED),
            (Authorization(owner="lab", reference="FUTURE", valid_from=now + timedelta(days=1)),
             ScopeReason.AUTHORIZATION_EXPIRED),
        )
        for grant, reason in grants:
            with self.subTest(reason=reason, grant=grant):
                result = policy.decide(Target("8.8.8.8", authorization=grant))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, reason)

    def test_unrelated_current_grant_is_not_considered_cidr_proof(self):
        # This model checks *presence/currentness*, not matching digital grant scope.
        # Document this limitation rather than asserting it enforces grant-target binding.
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("8.8.8.0/24",))
        unrelated_grant = Authorization(owner="unrelated-owner", reference="OTHER-ASSET")
        result = policy.decide(Target("8.8.8.8", authorization=unrelated_grant))
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
