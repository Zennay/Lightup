from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class PersistedEngagementLifecycleIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-engagement-lifecycle", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Engagement Lifecycle Integrity Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Execution resolver lifecycle integrity",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Lifecycle",
            "AUTH-LIFECYCLE-001",
            ScopeDefinition(
                assets=("app.lifecycle.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_persisted_status(self, value: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE engagements SET status=? WHERE engagement_id=?",
                (value, self.engagement.engagement_id),
            )

    def _get_persisted_status(self) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT status FROM engagements WHERE engagement_id=?",
                (self.engagement.engagement_id,),
            ).fetchone()
        assert row is not None
        return row["status"]

    def test_canonical_non_closed_status_remains_executable(self) -> None:
        self.assertEqual(self._get_persisted_status(), EngagementStatus.DRAFT.value)
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, self.grant.grant_id)

    def test_closed_status_remains_non_executable_without_mutation(self) -> None:
        self._set_persisted_status(EngagementStatus.CLOSED.value)
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))
        self.assertEqual(
            self._get_persisted_status(),
            EngagementStatus.CLOSED.value,
            "execution resolution must not normalize durable lifecycle state",
        )

    def test_corrupted_statuses_fail_closed_without_exception_or_rewrite(self) -> None:
        corrupt_values = (
            "",
            "future_state",
            "AUTHORIZED",
            " draft ",
        )
        for value in corrupt_values:
            with self.subTest(value=value):
                self._set_persisted_status(value)
                self.assertIsNone(
                    self.store.resolve_authorization_for_execution(self.grant),
                    "unknown persisted lifecycle state must mint no execution authority",
                )
                self.assertEqual(
                    self._get_persisted_status(),
                    value,
                    "execution resolution must not repair or normalize durable state",
                )

                self._set_persisted_status(EngagementStatus.DRAFT.value)
                self.assertIsNotNone(
                    self.store.resolve_authorization_for_execution(self.grant),
                    "restoring canonical durable state should restore normal resolution",
                )


if __name__ == "__main__":
    unittest.main()
