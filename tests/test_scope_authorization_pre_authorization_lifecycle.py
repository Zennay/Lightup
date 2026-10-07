from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class PreAuthorizationEngagementLifecycleTest(unittest.TestCase):
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
            "CISO Preauth",
            "AUTH-PREAUTH-001",
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

    def _get_status(self) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT status FROM engagements WHERE engagement_id=?",
                (self.engagement.engagement_id,),
            ).fetchone()
        assert row is not None
        return row["status"]

    def test_pre_authorization_states_mint_no_execution_authority(self) -> None:
        for status in (
            EngagementStatus.DRAFT,
            EngagementStatus.AUTHORIZATION_PENDING,
        ):
            with self.subTest(status=status.value):
                self._set_status(status)
                self.assertIsNone(
                    self.store.resolve_authorization_for_execution(self.grant),
                    "pre-authorization lifecycle state must not resolve target-active authority",
                )
                self.assertEqual(
                    self._get_status(),
                    status.value,
                    "execution resolution must not mutate durable lifecycle state",
                )

    def test_authorized_and_running_states_remain_resolvable(self) -> None:
        for status in (
            EngagementStatus.AUTHORIZED,
            EngagementStatus.RUNNING,
        ):
            with self.subTest(status=status.value):
                self._set_status(status)
                live = self.store.resolve_authorization_for_execution(self.grant)
                self.assertIsNotNone(live)
                assert live is not None
                self.assertEqual(live.grant_id, self.grant.grant_id)
                self.assertEqual(self._get_status(), status.value)

    def test_closed_state_remains_non_executable(self) -> None:
        self._set_status(EngagementStatus.CLOSED)
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))
        self.assertEqual(self._get_status(), EngagementStatus.CLOSED.value)


if __name__ == "__main__":
    unittest.main()
