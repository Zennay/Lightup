"""Offline scope-gate regression for IPv4-mapped IPv6 address literals.

These tests never resolve DNS or connect to a target.
"""
import unittest
from datetime import datetime, timedelta, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class MappedIPv4ScopeBoundaryTests(unittest.TestCase):
    def test_public_mapped_address_has_no_implicit_authority(self):
        policy = ScopePolicy(allow_private_lab=False)
        result = policy.decide(Target("http://[::ffff:8.8.8.8]/"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_mapped_private_address_cannot_bypass_lab_opt_out(self):
        policy = ScopePolicy(allow_private_lab=False)
        result = policy.decide(Target("http://[::ffff:192.168.1.10]/"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_mapped_loopback_cannot_inherit_ipv6_loopback_exemption(self):
        # IPv4-mapped loopback is not the native ::1 loopback identity.
        policy = ScopePolicy(allow_private_lab=False)
        result = policy.decide(Target("http://[::ffff:127.0.0.1]/"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_mapped_private_address_does_not_inherit_ipv4_cidr_grant(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("192.168.1.0/24",),
            require_authorization_for_public=False,
        )
        result = policy.decide(Target("http://[::ffff:192.168.1.10]/"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_unrelated_ipv4_network_does_not_admit_mapped_public_address(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=False,
        )
        result = policy.decide(Target("http://[::ffff:8.8.8.8]/"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_mapped_ipv6_network_requires_current_authorization(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("::ffff:8.8.8.0/120",),
        )
        result = policy.decide(Target("http://[::ffff:8.8.8.8]/"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_expired_mapped_network_authorization_denied(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("::ffff:8.8.8.0/120",),
        )
        expired = Authorization(
            owner="offline-test",
            reference="expired-fixture",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        result = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=expired))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_future_mapped_network_authorization_denied(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("::ffff:8.8.8.0/120",),
        )
        future = Authorization(
            owner="offline-test",
            reference="future-fixture",
            valid_from=datetime.now(timezone.utc) + timedelta(days=1),
        )
        result = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=future))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_exact_mapped_network_and_authorization_permit_only_the_network(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("::ffff:8.8.8.0/120",),
        )
        grant = Authorization(owner="offline-test", reference="fixture-only")
        allowed = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=grant))
        denied = policy.decide(Target("http://[::ffff:9.9.9.9]/", authorization=grant))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertFalse(denied.allowed)


if __name__ == "__main__":
    unittest.main()
