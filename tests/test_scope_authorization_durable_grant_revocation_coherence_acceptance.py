from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def _grant(
    *,
    revoked_at: datetime | None = None,
    revoked_by: str | None = None,
    revocation_reason: str | None = None,
) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-revocation-coherence",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-REVOCATION-COHERENCE",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(hours=1),
        revoked_at=revoked_at,
        revoked_by=revoked_by,
        revocation_reason=revocation_reason,
    )


class DurableGrantRevocationCoherenceAcceptanceTests(unittest.TestCase):
    def test_canonical_unrevoked_grant_remains_current(self) -> None:
        grant = _grant()
        self.assertTrue(grant.is_current(NOW))

    def test_canonical_revoked_grant_is_not_current(self) -> None:
        grant = _grant(
            revoked_at=NOW - timedelta(minutes=5),
            revoked_by="operator-1",
            revocation_reason="authorization withdrawn",
        )
        self.assertFalse(grant.is_current(NOW))

    def test_revoked_by_without_revoked_at_fails_closed(self) -> None:
        grant = _grant(revoked_by="operator-1")
        before = (grant.revoked_at, grant.revoked_by, grant.revocation_reason)
        self.assertFalse(grant.is_current(NOW))
        self.assertEqual(before, (grant.revoked_at, grant.revoked_by, grant.revocation_reason))

    def test_revocation_reason_without_revoked_at_fails_closed(self) -> None:
        grant = _grant(revocation_reason="authorization withdrawn")
        before = (grant.revoked_at, grant.revoked_by, grant.revocation_reason)
        self.assertFalse(grant.is_current(NOW))
        self.assertEqual(before, (grant.revoked_at, grant.revoked_by, grant.revocation_reason))

    def test_actor_and_reason_without_revoked_at_fail_closed(self) -> None:
        grant = _grant(
            revoked_by="operator-1",
            revocation_reason="authorization withdrawn",
        )
        before = (grant.revoked_at, grant.revoked_by, grant.revocation_reason)
        self.assertFalse(grant.is_current(NOW))
        self.assertEqual(before, (grant.revoked_at, grant.revoked_by, grant.revocation_reason))


if __name__ == "__main__":
    unittest.main()
