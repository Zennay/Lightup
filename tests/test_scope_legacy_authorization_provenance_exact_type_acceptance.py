from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class _SpoofedText(str):
    def __new__(cls, stored: str, canonical_strip: str):
        obj = super().__new__(cls, stored)
        obj._canonical_strip = canonical_strip
        return obj

    def strip(self, chars=None):  # type: ignore[override]
        if chars is None:
            return self._canonical_strip
        return super().strip(chars)


class LegacyAuthorizationProvenanceExactTypeAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _policy() -> ScopePolicy:
        return ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )

    def _assert_noncanonical_provenance_fails_closed(
        self,
        *,
        owner: object = "client-owner",
        reference: object = "client-auth-ref",
    ) -> None:
        authorization = Authorization(
            owner=owner,  # type: ignore[arg-type]
            reference=reference,  # type: ignore[arg-type]
            assets=("security.example.test",),
        )
        try:
            decision = self._policy().decide(
                Target("security.example.test", authorization=authorization)
            )
        except (TypeError, ValueError):
            return
        if decision.allowed:
            self.fail("polymorphic legacy authorization provenance was accepted")

    def test_polymorphic_owner_identity_fails_closed(self):
        self._assert_noncanonical_provenance_fails_closed(
            owner=_SpoofedText("forged-owner", "client-owner")
        )

    def test_polymorphic_reference_identity_fails_closed(self):
        self._assert_noncanonical_provenance_fails_closed(
            reference=_SpoofedText("forged-reference", "client-auth-ref")
        )

    def test_canonical_exact_provenance_keeps_public_host_authorized(self):
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
        self.assertIs(type(authorization.owner), str)
        self.assertIs(type(authorization.reference), str)


if __name__ == "__main__":
    unittest.main()
