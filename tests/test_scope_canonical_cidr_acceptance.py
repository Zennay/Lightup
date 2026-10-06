from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeCanonicalCidrAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _authorization() -> Authorization:
        return Authorization(
            owner="scope-cidr-regression",
            reference="scope-cidr-regression-ref",
        )

    def test_ipv4_host_bits_cannot_silently_expand_scope(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.8/24",),
            require_authorization_for_public=True,
        )
        with self.assertRaises(ValueError):
            policy.decide(Target("8.8.8.9", authorization=self._authorization()))

    def test_ipv6_host_bits_cannot_silently_expand_scope(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("2001:4860:4860::8888/64",),
            require_authorization_for_public=True,
        )
        with self.assertRaises(ValueError):
            policy.decide(
                Target(
                    "[2001:4860:4860::8844]",
                    authorization=self._authorization(),
                )
            )

    def test_canonical_ipv4_network_keeps_existing_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target("8.8.8.9", authorization=self._authorization())
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_exact_ipv4_single_host_intent_remains_available(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.8/32",),
            require_authorization_for_public=True,
        )
        inside = policy.decide(
            Target("8.8.8.8", authorization=self._authorization())
        )
        outside = policy.decide(
            Target("8.8.8.9", authorization=self._authorization())
        )
        self.assertTrue(inside.allowed)
        self.assertEqual(inside.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertFalse(outside.allowed)
        self.assertEqual(outside.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_ipv6_single_host_intent_remains_available(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("2001:4860:4860::8888/128",),
            require_authorization_for_public=True,
        )
        inside = policy.decide(
            Target(
                "[2001:4860:4860::8888]",
                authorization=self._authorization(),
            )
        )
        outside = policy.decide(
            Target(
                "[2001:4860:4860::8844]",
                authorization=self._authorization(),
            )
        )
        self.assertTrue(inside.allowed)
        self.assertEqual(inside.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertFalse(outside.allowed)
        self.assertEqual(outside.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
