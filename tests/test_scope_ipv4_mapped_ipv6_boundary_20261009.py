"""Offline IPv4-mapped IPv6 scope identity regression, synthetic addresses only.

No socket, DNS, HTTP client, or live authorization provenance is involved.
"""
import unittest
from unittest.mock import patch

from datetime import datetime, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class IPv4MappedIPv6ScopeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.grant = Authorization(owner="synthetic-test-owner", reference="TEST-ONLY")

    def test_ipv4_allowlist_does_not_implicitly_authorize_mapped_ipv6_literal(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"8.8.8.8"}))
        decision = policy.decide(Target("[::ffff:8.8.8.8]", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_ipv4_cidr_does_not_implicitly_authorize_mapped_ipv6(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        decision = policy.decide(Target("[::ffff:8.8.8.8]", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_mapped_ipv6_literal_is_not_equivalent_to_ipv4_hostname(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"::ffff:8.8.8.8"}))
        decision = policy.decide(Target("8.8.8.8", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_mapped_ipv6_explicit_network_requires_grant(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.8/128",))
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_mapped_ipv6_explicit_network_with_synthetic_grant_is_legacy_scope_only(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.8/128",))
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=self.grant))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_explicit_mapped_ipv6_network_does_not_authorize_other_ipv4(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.0/120",))
        decision = policy.decide(Target("8.8.8.8", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_mapped_ipv6_network_rejects_neighbor_outside_prefix(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.0/120",))
        decision = policy.decide(Target("http://[::ffff:8.8.9.8]/", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_mapped_ipv6_network_requires_grant_on_in_prefix_literal(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.0/120",))
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_explicit_mapped_ipv6_prefix_accepts_only_synthetic_in_prefix_grant(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.0/120",))
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=self.grant))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_unmapped_ipv6_does_not_inherit_ipv4_mapped_prefix(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.0/120",))
        decision = policy.decide(Target("http://[2001:db8::1]/", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_expired_mapped_ipv6_grant_fails_closed(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.8/128",))
        expired = Authorization(
            owner="synthetic-test-owner",
            reference="EXPIRED-TEST-ONLY",
            valid_until=datetime(2000, 1, 1, tzinfo=timezone.utc),
        )
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=expired))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_future_mapped_ipv6_grant_fails_closed(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.8/128",))
        not_yet_valid = Authorization(
            owner="synthetic-test-owner",
            reference="FUTURE-TEST-ONLY",
            valid_from=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=not_yet_valid))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_unlisted_mapped_ipv6_never_calls_network_or_dns(self):
        policy = ScopePolicy()
        with patch("socket.create_connection", side_effect=AssertionError("network call")), patch(
            "socket.getaddrinfo", side_effect=AssertionError("DNS call")
        ):
            decision = policy.decide(Target("http://[::ffff:8.8.8.8]/", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
