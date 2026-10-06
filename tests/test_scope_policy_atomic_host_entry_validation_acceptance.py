from __future__ import annotations

import unittest

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyAtomicHostEntryValidationAcceptanceTest(unittest.TestCase):
    def test_non_string_explicit_host_cannot_be_bypassed_by_network_path(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({123}),  # type: ignore[arg-type]
            explicit_networks=("8.8.8.8/32",),
            require_authorization_for_public=False,
        )

        with self.assertRaises((TypeError, ValueError)):
            policy.decide(Target("8.8.8.8"))

    def test_canonical_host_and_network_policy_keeps_network_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.8/32",),
            require_authorization_for_public=False,
        )
        decision = policy.decide(Target("8.8.8.8"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
