from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class _ClosedLikeStatus:
    value = EngagementStatus.CLOSED.value


class EngagementClosureTypeSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-closure-type", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Closure Type Safety Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Closure Type Safety"
        )
        self.store.set_engagement_status(
            self.operator, self.engagement.engagement_id, EngagementStatus.AUTHORIZED
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Closure",
            "AUTH-CLOSURE-001",
            ScopeDefinition(
                assets=("app.closure.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _durable_state(self) -> tuple[str, str | None, str | None, str | None]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT e.status,g.revoked_at,g.revoked_by,g.revocation_reason "
                "FROM engagements AS e "
                "JOIN authorization_grants AS g ON g.engagement_id=e.engagement_id "
                "WHERE e.engagement_id=? AND g.grant_id=?",
                (self.engagement.engagement_id, self.grant.grant_id),
            ).fetchone()
        assert row is not None
        return (
            row["status"],
            row["revoked_at"],
            row["revoked_by"],
            row["revocation_reason"],
        )

    def test_noncanonical_closed_like_status_is_rejected_before_mutation(self) -> None:
        before = self._durable_state()
        self.assertEqual(before[0], EngagementStatus.AUTHORIZED.value)
        self.assertIsNone(before[1])
        self.assertIsNotNone(
            self.store.resolve_authorization_for_execution(self.grant),
            "green control requires a live canonical authorization before the mutation",
        )

        with self.assertRaises(
            ValueError,
            msg="engagement lifecycle mutation must require a canonical EngagementStatus",
        ):
            self.store.set_engagement_status(
                self.operator,
                self.engagement.engagement_id,
                _ClosedLikeStatus(),
            )

        self.assertEqual(
            self._durable_state(),
            before,
            "rejected lifecycle input must leave engagement and grant rows untouched",
        )
        self.assertIsNotNone(
            self.store.resolve_authorization_for_execution(self.grant),
            "a rejected fake closure must not alter live authorization state",
        )

    def test_canonical_closure_revokes_and_reopen_does_not_resurrect_grant(self) -> None:
        closed = self.store.set_engagement_status(
            self.operator,
            self.engagement.engagement_id,
            EngagementStatus.CLOSED,
        )
        self.assertIs(closed.status, EngagementStatus.CLOSED)

        status, revoked_at, revoked_by, revocation_reason = self._durable_state()
        self.assertEqual(status, EngagementStatus.CLOSED.value)
        self.assertIsNotNone(revoked_at)
        self.assertEqual(revoked_by, self.operator.user_id)
        self.assertEqual(revocation_reason, "engagement closed")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

        reopened = self.store.set_engagement_status(
            self.operator,
            self.engagement.engagement_id,
            EngagementStatus.AUTHORIZED,
        )
        self.assertIs(reopened.status, EngagementStatus.AUTHORIZED)
        self.assertIsNone(
            self.store.resolve_authorization_for_execution(self.grant),
            "reopening lifecycle must not resurrect a grant revoked by canonical closure",
        )


if __name__ == "__main__":
    unittest.main()
