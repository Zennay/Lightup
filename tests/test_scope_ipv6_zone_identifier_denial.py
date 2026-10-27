"""Offline fail-closed acceptance: IPv6 scoped zone identifiers are not authority."""
import unittest

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class IPv6ZoneIdentifierScopeContract(unittest.TestCase):
    def test_zone_id_cannot_inherit_private_lab_permission(self):
        policy = ScopePolicy(allow_private_lab=True)
        for value in ("[fe80::1%eth0]", "http://[fe80::1%25eth0]/", "[::1%lo]"):
            with self.subTest(value=value):
                decision = policy.decide(Target(value=value))
                self.assertFalse(decision.allowed, value)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_zone_id_cannot_inherit_explicit_network_permission(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("fe80::/10", "::1/128"),
            require_authorization_for_public=False,
        )
        for value in ("[fe80::1%eth0]", "[::1%lo]"):
            with self.subTest(value=value):
                decision = policy.decide(Target(value=value))
                self.assertFalse(decision.allowed, value)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_unscoped_ipv6_control_preserves_loopback(self):
        decision = ScopePolicy().decide(Target(value="[::1]"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)


if __name__ == "__main__":
    unittest.main()
