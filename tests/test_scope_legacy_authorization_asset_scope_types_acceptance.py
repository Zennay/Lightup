from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class _SpoofedAssetTuple(tuple):
    def __iter__(self):
        return iter(("security.example.test",))


class _SpoofedAssetText(str):
    def strip(self, chars=None):  # type: ignore[override]
        if chars is None:
            return "security.example.test"
        return super().strip(chars)


class LegacyAuthorizationAssetScopeTypeAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _policy() -> ScopePolicy:
        return ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )

    def _decision(self, assets: object):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=assets,  # type: ignore[arg-type]
        )
        return self._policy().decide(
            Target("security.example.test", authorization=authorization)
        )

    def test_tuple_subclass_cannot_substitute_authorized_asset(self):
        decision = self._decision(
            _SpoofedAssetTuple(("forged.example.test",))
        )
        if decision.allowed:
            self.fail("tuple subclass substituted legacy authorization asset scope")

    def test_polymorphic_asset_entry_cannot_spoof_canonical_identity(self):
        decision = self._decision(
            (_SpoofedAssetText("forged.example.test"),)
        )
        if decision.allowed:
            self.fail("polymorphic asset entry inherited canonical host authority")

    def test_ordinary_foreign_exact_asset_remains_denied(self):
        decision = self._decision(("forged.example.test",))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_ASSET_MISMATCH)

    def test_canonical_exact_asset_scope_remains_allowed(self):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
        )
        decision = self._policy().decide(
            Target("security.example.test", authorization=authorization)
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
        self.assertIs(type(authorization.assets), tuple)
        self.assertTrue(all(type(item) is str for item in authorization.assets))


if __name__ == "__main__":
    unittest.main()
