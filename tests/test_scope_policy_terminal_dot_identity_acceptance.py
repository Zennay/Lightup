from __future__ import annotations

import unittest

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyTerminalDotIdentityAcceptanceTest(unittest.TestCase):
    def test_single_dns_root_dot_remains_equivalent_for_explicit_host(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"Example.Test"}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(Target("  EXAMPLE.TEST.  "))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_multiple_terminal_dots_do_not_inherit_explicit_host_scope(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"example.test"}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(Target("example.test.."))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_malformed_policy_entry_does_not_authorize_canonical_target(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"example.test.."}),
            require_authorization_for_public=False,
        )

        canonical = policy.decide(Target("example.test"))
        rooted = policy.decide(Target("example.test."))

        self.assertFalse(canonical.allowed)
        self.assertEqual(canonical.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertFalse(rooted.allowed)
        self.assertEqual(rooted.reason, ScopeReason.OUT_OF_SCOPE)

    def test_single_root_dot_localhost_remains_loopback(self):
        decision = ScopePolicy().decide(Target("localhost."))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "localhost")
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_multiple_terminal_dots_do_not_mint_loopback_scope(self):
        decision = ScopePolicy().decide(Target("localhost.."))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
