import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeExplicitNetworkSetSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization(owner="scope-test-owner", reference="AUTH-NET-SET")

    def test_cidr_edges_are_exact_and_adjacent_addresses_stay_out_of_scope(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.8/30",))

        for address in ("8.8.8.8", "8.8.8.11"):
            with self.subTest(address=address):
                decision = policy.decide(Target(address, authorization=self.authorization))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

        for address in ("8.8.8.7", "8.8.8.12"):
            with self.subTest(address=address):
                decision = policy.decide(Target(address, authorization=self.authorization))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_duplicate_network_entries_do_not_bypass_authorization(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24", "8.8.8.0/24"))

        denied = policy.decide(Target("8.8.8.8"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.AUTHORIZATION_MISSING)

        allowed = policy.decide(Target("8.8.8.8", authorization=self.authorization))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_network_order_does_not_change_scope_decision(self):
        first = ScopePolicy(explicit_networks=("1.1.1.0/24", "8.8.8.0/24"))
        second = ScopePolicy(explicit_networks=("8.8.8.0/24", "1.1.1.0/24"))

        for address in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            with self.subTest(address=address):
                target = Target(address, authorization=self.authorization)
                self.assertEqual(first.decide(target), second.decide(target))

    def test_overlapping_networks_still_require_current_authorization(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24", "8.8.8.8/32"))

        denied = policy.decide(Target("8.8.8.8"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.AUTHORIZATION_MISSING)

        allowed = policy.decide(Target("8.8.8.8", authorization=self.authorization))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_ipv4_and_ipv6_network_families_do_not_cross_match(self):
        ipv6_only = ScopePolicy(explicit_networks=("2606:4700:4700::/48",))
        ipv4_decision = ipv6_only.decide(Target("8.8.8.8", authorization=self.authorization))
        self.assertFalse(ipv4_decision.allowed)
        self.assertEqual(ipv4_decision.reason, ScopeReason.OUT_OF_SCOPE)

        ipv4_only = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        ipv6_decision = ipv4_only.decide(
            Target("[2606:4700:4700::1111]", authorization=self.authorization)
        )
        self.assertFalse(ipv6_decision.allowed)
        self.assertEqual(ipv6_decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_ipv6_in_network_target_uses_explicit_network_path(self):
        policy = ScopePolicy(explicit_networks=("2606:4700:4700::/48",))

        denied = policy.decide(Target("[2606:4700:4700::1111]"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.AUTHORIZATION_MISSING)

        allowed = policy.decide(
            Target("2606:4700:4700::1111", authorization=self.authorization)
        )
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
