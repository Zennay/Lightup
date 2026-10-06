from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class _DuckAuthorization:
    is_revoked = False
    reference = "duck-auth-ref"

    def is_current(self) -> bool:
        return True

    def allows_asset(self, asset: str) -> bool:
        return True


class LegacyAuthorizationExactTypeAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _assert_duck_authorization_rejected(policy: ScopePolicy, target_value: str) -> None:
        target = Target(
            target_value,
            authorization=_DuckAuthorization(),  # type: ignore[arg-type]
        )
        try:
            decision = policy.decide(target)
        except (AttributeError, TypeError, ValueError):
            return
        if decision.allowed:
            raise AssertionError("duck-typed legacy authorization was accepted")

    def test_duck_authorization_cannot_authorize_explicit_public_host(self):
        self._assert_duck_authorization_rejected(
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"security.example.test"}),
                require_authorization_for_public=True,
            ),
            "security.example.test",
        )

    def test_duck_authorization_cannot_authorize_explicit_public_network(self):
        self._assert_duck_authorization_rejected(
            ScopePolicy(
                allow_private_lab=False,
                explicit_networks=("8.8.8.8/32",),
                require_authorization_for_public=True,
            ),
            "8.8.8.8",
        )

    def test_canonical_authorization_keeps_public_host_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(
                "security.example.test",
                authorization=Authorization(
                    owner="client-owner",
                    reference="client-auth-ref",
                    assets=("security.example.test",),
                ),
            )
        )
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
