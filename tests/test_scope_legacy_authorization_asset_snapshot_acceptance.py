from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class LegacyAuthorizationAssetSnapshotAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _policy(*hosts: str) -> ScopePolicy:
        return ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(hosts),
            require_authorization_for_public=True,
        )

    def test_mutable_asset_input_is_snapshotted_to_immutable_tuple(self):
        caller_assets = ["alpha.example.test"]
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=caller_assets,  # type: ignore[arg-type]
        )
        if not isinstance(authorization.assets, tuple):
            self.fail("legacy authorization assets were not snapshotted")

    def test_external_mutation_cannot_widen_existing_authorization(self):
        caller_assets = ["alpha.example.test"]
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=caller_assets,  # type: ignore[arg-type]
        )
        policy = self._policy("alpha.example.test", "beta.example.test")

        before = policy.decide(Target("beta.example.test", authorization=authorization))
        self.assertFalse(before.allowed)
        self.assertEqual(before.reason, ScopeReason.AUTHORIZATION_ASSET_MISMATCH)

        caller_assets.append("beta.example.test")
        after = policy.decide(Target("beta.example.test", authorization=authorization))
        if after.allowed:
            self.fail("external asset mutation widened legacy authorization")

    def test_external_mutation_cannot_narrow_existing_authorization(self):
        caller_assets = ["alpha.example.test"]
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=caller_assets,  # type: ignore[arg-type]
        )
        policy = self._policy("alpha.example.test")

        before = policy.decide(Target("alpha.example.test", authorization=authorization))
        self.assertTrue(before.allowed)

        caller_assets.clear()
        after = policy.decide(Target("alpha.example.test", authorization=authorization))
        if not after.allowed:
            self.fail("external asset mutation narrowed legacy authorization")

    def test_canonical_tuple_asset_scope_keeps_existing_behavior(self):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("alpha.example.test",),
        )
        decision = self._policy("alpha.example.test").decide(
            Target("alpha.example.test", authorization=authorization)
        )
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
