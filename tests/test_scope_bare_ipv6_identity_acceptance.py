from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeBareIpv6IdentityAcceptanceTest(unittest.TestCase):
    IPV6 = "2606:4700:4700::1111"

    @staticmethod
    def _authorization() -> Authorization:
        return Authorization(
            owner="scope-ipv6-regression",
            reference="scope-ipv6-regression-ref",
        )

    def test_bare_ipv6_is_never_exposed_as_a_truncated_host_identity(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("2606:4700:4700::1111/128",),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(self.IPV6, authorization=self._authorization())
        )

        if decision.normalized_host not in (None, self.IPV6):
            self.fail("bare IPv6 identity was truncated")

        if decision.normalized_host is None:
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        else:
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_truncated_prefix_cannot_authorize_bare_ipv6_as_explicit_host(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2606"}),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(self.IPV6, authorization=self._authorization())
        )
        if decision.allowed:
            self.fail("truncated IPv6 prefix minted explicit-host scope")

    def test_bracketed_ipv6_authority_keeps_existing_network_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("2606:4700:4700::1111/128",),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(
                "[2606:4700:4700::1111]",
                authorization=self._authorization(),
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, self.IPV6)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)


if __name__ == "__main__":
    unittest.main()
