from __future__ import annotations

from datetime import datetime, timezone
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class LegacyAuthorizationRevocationCoherenceAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _policy() -> ScopePolicy:
        return ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )

    def _assert_stale_revocation_provenance_fails_closed(
        self,
        *,
        revoked_by: str | None,
        revocation_reason: str | None,
    ) -> None:
        try:
            authorization = Authorization(
                owner="client-owner",
                reference="client-auth-ref",
                assets=("security.example.test",),
                revoked_by=revoked_by,
                revocation_reason=revocation_reason,
            )
            decision = self._policy().decide(
                Target("security.example.test", authorization=authorization)
            )
        except (TypeError, ValueError):
            return
        if decision.allowed:
            self.fail("stale legacy revocation provenance retained public authority")

    def test_revoked_actor_without_timestamp_fails_closed(self):
        self._assert_stale_revocation_provenance_fails_closed(
            revoked_by="operator-1",
            revocation_reason=None,
        )

    def test_revocation_reason_without_timestamp_fails_closed(self):
        self._assert_stale_revocation_provenance_fails_closed(
            revoked_by=None,
            revocation_reason="scope withdrawn",
        )

    def test_revocation_actor_and_reason_without_timestamp_fail_closed(self):
        self._assert_stale_revocation_provenance_fails_closed(
            revoked_by="operator-1",
            revocation_reason="scope withdrawn",
        )

    def test_canonical_unrevoked_authorization_remains_allowed(self):
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

    def test_canonical_revoked_authorization_remains_denied(self):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
            revoked_at=datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc),
            revoked_by="operator-1",
            revocation_reason="scope withdrawn",
        )
        decision = self._policy().decide(
            Target("security.example.test", authorization=authorization)
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_REVOKED)


if __name__ == "__main__":
    unittest.main()
