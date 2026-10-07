"""Offline scope-admission matrix: unauthorized public assets must never activate.

This file deliberately owns no production source and performs no network I/O.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationMatrixTests(unittest.TestCase):
    def test_unknown_public_addresses_are_denied_even_with_grant(self):
        grant = Authorization(owner="fixture", reference="OFFLINE-ONLY")
        for address in ("8.8.8.8", "2001:4860:4860::8888", "outside.example.test"):
            with self.subTest(address=address):
                decision = ScopePolicy().decide(Target(address, authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_private_lab_opt_out_denies_unlisted_private_addresses(self):
        policy = ScopePolicy(allow_private_lab=False)
        for address in ("10.3.4.5", "192.168.7.8", "169.254.10.11"):
            with self.subTest(address=address):
                self.assertFalse(policy.decide(Target(address)).allowed)

    def test_public_explicit_host_requires_current_grant(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"authorized.example.test"}))
        now = datetime.now(timezone.utc)
        grants = (
            (None, ScopeReason.AUTHORIZATION_MISSING),
            (Authorization("fixture", "FUTURE", valid_from=now + timedelta(days=2)), ScopeReason.AUTHORIZATION_EXPIRED),
            (Authorization("fixture", "EXPIRED", valid_until=now - timedelta(days=2)), ScopeReason.AUTHORIZATION_EXPIRED),
        )
        for grant, reason in grants:
            with self.subTest(reason=reason, grant=grant):
                decision = policy.decide(Target("authorized.example.test", authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, reason)

    def test_public_explicit_network_does_not_authorize_other_members(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        grant = Authorization(owner="fixture", reference="OFFLINE-ONLY")
        allowed = policy.decide(Target("8.8.8.8", authorization=grant))
        denied = policy.decide(Target("8.8.4.4", authorization=grant))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
