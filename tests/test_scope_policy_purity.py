"""Offline purity regressions for scope policy decisions (no DNS/network)."""

from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyPurityTests(unittest.TestCase):
    def test_decision_does_not_rewrite_policy_configuration(self):
        hosts = frozenset({"EXAMPLE.COM.", "outside.example"})
        networks = ("203.0.113.0/24", "2001:db8::/32")
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=hosts,
            explicit_networks=networks,
        )
        before = (policy.explicit_hosts, policy.explicit_networks,
                  policy.allow_private_lab, policy.require_authorization_for_public)
        for name in ("example.com", "203.0.113.15", "outside.example", "unknown.example"):
            policy.decide(Target(value=name))
        self.assertEqual(before, (policy.explicit_hosts, policy.explicit_networks,
                                  policy.allow_private_lab,
                                  policy.require_authorization_for_public))
        self.assertIs(policy.explicit_hosts, hosts)
        self.assertIs(policy.explicit_networks, networks)

    def test_repeated_denied_decision_has_no_cached_authority(self):
        policy = ScopePolicy(allow_private_lab=False,
                             explicit_hosts=frozenset({"example.com"}))
        target = Target(value="example.com")
        decisions = [policy.decide(target) for _ in range(3)]
        self.assertTrue(all(not decision.allowed for decision in decisions))
        self.assertTrue(all(decision.reason is ScopeReason.AUTHORIZATION_MISSING
                            for decision in decisions))
        self.assertEqual(decisions, [decisions[0]] * 3)

    def test_explicit_network_configuration_remains_frozen(self):
        policy = ScopePolicy(allow_private_lab=False,
                             explicit_networks=("203.0.113.0/24",))
        with self.assertRaises(FrozenInstanceError):
            policy.explicit_networks = ("0.0.0.0/0",)
        denied = policy.decide(Target(value="203.0.113.4"))
        self.assertFalse(denied.allowed)
        self.assertIs(denied.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_scope_decisions_never_require_dns(self):
        policy = ScopePolicy(allow_private_lab=False,
                             explicit_hosts=frozenset({"example.com"}))
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS attempted")):
            self.assertEqual(policy.decide(Target(value="unknown.example")).reason,
                             ScopeReason.OUT_OF_SCOPE)
            self.assertEqual(policy.decide(Target(value="example.com")).reason,
                             ScopeReason.AUTHORIZATION_MISSING)


    def test_distinct_policies_cannot_share_explicit_host_authority(self):
        restrictive = ScopePolicy(allow_private_lab=False)
        configured = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"example.test"}),
        )
        target = Target(value="example.test")
        self.assertIs(configured.decide(target).reason,
                      ScopeReason.AUTHORIZATION_MISSING)
        self.assertIs(restrictive.decide(target).reason,
                      ScopeReason.OUT_OF_SCOPE)
        self.assertIs(configured.decide(target).reason,
                      ScopeReason.AUTHORIZATION_MISSING)

    def test_same_policy_unknown_host_remains_denied_after_matching_host(self):
        policy = ScopePolicy(allow_private_lab=False,
                             explicit_hosts=frozenset({"approved.example.test"}))
        matched = Target(value="approved.example.test")
        unknown = Target(value="other.example.test")
        self.assertIs(policy.decide(matched).reason,
                      ScopeReason.AUTHORIZATION_MISSING)
        self.assertIs(policy.decide(unknown).reason,
                      ScopeReason.OUT_OF_SCOPE)
        self.assertIs(policy.decide(matched).reason,
                      ScopeReason.AUTHORIZATION_MISSING)
        self.assertIs(policy.decide(unknown).reason,
                      ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
