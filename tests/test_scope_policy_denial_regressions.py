"""Offline regression coverage for ScopePolicy authorization denial boundaries.

No network requests, target interaction or active assessment execution.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyDenialRegressions(unittest.TestCase):
    def test_expired_explicit_network_grant_is_denied(self):
        expired = Authorization(
            owner="lab-owner",
            reference="expired-net",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        decision = policy.decide(Target("8.8.8.8", authorization=expired))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_future_explicit_host_grant_is_denied(self):
        future = Authorization(
            owner="lab-owner",
            reference="future-host",
            valid_from=datetime.now(timezone.utc) + timedelta(days=1),
        )
        policy = ScopePolicy(explicit_hosts=frozenset({"example.test"}))
        decision = policy.decide(Target("https://EXAMPLE.TEST./path", authorization=future))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "example.test")
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_private_lab_switch_denies_private_address(self):
        policy = ScopePolicy(allow_private_lab=False)
        decision = policy.decide(Target("10.20.30.40"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_ipv6_explicit_network_without_grant_is_denied(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("2001:4860:4860::/48",),
        )
        decision = policy.decide(Target("[2001:4860:4860::8888]"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_unlisted_host_remains_denied_despite_valid_grant(self):
        current = Authorization(owner="lab-owner", reference="other-host")
        policy = ScopePolicy(explicit_hosts=frozenset({"allowed.example.test"}))
        decision = policy.decide(Target("other.example.test", authorization=current))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
