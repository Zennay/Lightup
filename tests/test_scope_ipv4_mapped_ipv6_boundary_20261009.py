"""Offline IPv4-mapped IPv6 scope identity regression, synthetic addresses only.

No socket, DNS, HTTP client, or live authorization provenance is involved.
"""
import unittest
from unittest.mock import patch

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

    def test_mapped_ipv6_can_be_explicitly_listed_but_requires_grant(self):
        policy = ScopePolicy(explicit_networks=("::ffff:8.8.8.8/128",))
        decision = policy.decide(Target("http://[::ffff:8.8.8.8]/"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_mapped_ipv6_explicit_host_with_synthetic_grant_is_legacy_scope_only(self):
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
