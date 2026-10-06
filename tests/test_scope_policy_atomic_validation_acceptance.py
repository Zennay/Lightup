from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyAtomicValidationAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _authorization() -> Authorization:
        return Authorization(
            owner="scope-policy-atomic",
            reference="scope-policy-atomic-ref",
        )

    def test_malformed_network_cannot_be_bypassed_by_authorized_host_path(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("not-a-cidr",),
            require_authorization_for_public=True,
        )

        with self.assertRaises(ValueError):
            policy.decide(
                Target(
                    "security.example.test",
                    authorization=self._authorization(),
                )
            )

    def test_malformed_network_cannot_be_bypassed_when_public_auth_gate_is_disabled(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("not-a-cidr",),
            require_authorization_for_public=False,
        )

        with self.assertRaises(ValueError):
            policy.decide(Target("security.example.test"))

    def test_canonical_host_and_network_policy_keeps_existing_host_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(
                "security.example.test",
                authorization=self._authorization(),
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_canonical_host_and_network_policy_keeps_existing_network_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(
                "8.8.8.8",
                authorization=self._authorization(),
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
