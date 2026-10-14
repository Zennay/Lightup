"""Out-of-scope decisions must not invoke untrusted authorization callbacks.

This module is deliberately limited to offline ScopePolicy precedence. The
source owners of ScopePolicy and Authorization remain responsible for repairs.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ExplodingAuthorization:
    """If evaluated, this untrusted authorization callback fails the test."""

    def is_current(self):
        raise AssertionError("authorization evaluated before scope membership")

    def is_revoked(self):
        raise AssertionError("revocation evaluated before scope membership")

    def allows_asset(self, *args, **kwargs):
        raise AssertionError("asset authorization evaluated before scope membership")


class ScopeAuthorizationCallbackIsolationTests(unittest.TestCase):
    def test_unknown_public_host_never_consults_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"allowed.example.test"}))
        decision = policy.decide(Target("unknown.example.test", authorization=ExplodingAuthorization()))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_unknown_public_address_never_consults_authorization(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        decision = policy.decide(Target("1.1.1.1", authorization=ExplodingAuthorization()))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_invalid_target_never_consults_authorization(self):
        decision = ScopePolicy().decide(Target("", authorization=ExplodingAuthorization()))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_authorization_requirement_disabled_does_not_mint_membership(self):
        policy = ScopePolicy(
            require_authorization_for_public=False,
            explicit_hosts=frozenset({"allowed.example.test"}),
        )
        decision = policy.decide(Target("outside.example.test", authorization=ExplodingAuthorization()))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_loopback_membership_does_not_consult_public_authorization(self):
        decision = ScopePolicy().decide(
            Target("127.0.0.1", authorization=ExplodingAuthorization())
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_private_lab_membership_does_not_consult_public_authorization(self):
        decision = ScopePolicy().decide(
            Target("10.20.30.40", authorization=ExplodingAuthorization())
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.PRIVATE_LAB)

    def test_private_address_with_lab_disabled_stays_out_of_scope(self):
        policy = ScopePolicy(allow_private_lab=False)
        decision = policy.decide(
            Target("10.20.30.40", authorization=ExplodingAuthorization())
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_undeclared_ipv6_never_consults_authorization(self):
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("2001:db8:1::/64",))
        decision = policy.decide(
            Target("https://[2001:db8:2::1]/", authorization=ExplodingAuthorization())
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

if __name__ == "__main__":
    unittest.main()
