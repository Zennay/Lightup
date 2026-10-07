from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class PreAuthorizationEngagementLifecycleExecutionAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-preauth-lifecycle", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Pre-authorization Lifecycle Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Pre-authorization execution boundary",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Lifecycle",
            "AUTH-PREAUTH-LIFECYCLE-001",
            ScopeDefinition(
                assets=("app.preauth.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_status(self, status: EngagementStatus) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE engagements SET status=? WHERE engagement_id=?",
                (status.value, self.engagement.engagement_id),
            )

    def _status(self) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT status FROM engagements WHERE engagement_id=?",
                (self.engagement.engagement_id,),
            ).fetchone()
        assert row is not None
        return row["status"]

    def _grant_row(self) -> tuple[str, str, str | None]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT reference, approved_by, revoked_at "
                "FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        assert row is not None
        return row["reference"], row["approved_by"], row["revoked_at"]

    def test_draft_engagement_is_non_executable_without_mutation(self) -> None:
        self._set_status(EngagementStatus.DRAFT)
        before = self._grant_row()

        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

        self.assertEqual(self._status(), EngagementStatus.DRAFT.value)
        self.assertEqual(self._grant_row(), before)

    def test_authorization_pending_engagement_is_non_executable_without_mutation(self) -> None:
        self._set_status(EngagementStatus.AUTHORIZATION_PENDING)
        before = self._grant_row()

        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

        self.assertEqual(self._status(), EngagementStatus.AUTHORIZATION_PENDING.value)
        self.assertEqual(self._grant_row(), before)

    def test_authorized_and_running_engagements_remain_executable(self) -> None:
        for status in (EngagementStatus.AUTHORIZED, EngagementStatus.RUNNING):
            with self.subTest(status=status):
                self._set_status(status)
                live = self.store.resolve_authorization_for_execution(self.grant)
                self.assertIsNotNone(live)
                assert live is not None
                self.assertEqual(live.grant_id, self.grant.grant_id)
                self.assertEqual(self._status(), status.value)

    def test_closed_engagement_remains_non_executable(self) -> None:
        self._set_status(EngagementStatus.CLOSED)
        before = self._grant_row()

        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

        self.assertEqual(self._status(), EngagementStatus.CLOSED.value)
        self.assertEqual(self._grant_row(), before)


if __name__ == "__main__":
    unittest.main()
