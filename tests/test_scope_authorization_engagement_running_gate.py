from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class EngagementRunningAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-running-gate", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Running Gate Client")

    def _engagement(self, name: str):
        return self.store.create_engagement(
            self.operator,
            self.client.client_id,
            name,
        )

    def _grant(self, engagement_id: str):
        now = datetime.now(timezone.utc)
        return self.store.record_authorization_grant(
            self.operator,
            engagement_id,
            approved_by="security-owner@example.test",
            reference="AUTH-RUNNING-1",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(days=1),
        )

    def test_draft_cannot_enter_running_without_current_grant(self):
        engagement = self._engagement("draft-no-grant")

        with self.assertRaises((PermissionError, ValueError)):
            self.store.set_engagement_status(
                self.operator,
                engagement.engagement_id,
                EngagementStatus.RUNNING,
            )

        persisted = self.store.get_engagement(
            self.operator,
            engagement.engagement_id,
        )
        self.assertIs(persisted.status, EngagementStatus.DRAFT)

    def test_authorization_pending_cannot_enter_running_without_current_grant(self):
        engagement = self._engagement("pending-no-grant")
        self.store.set_engagement_status(
            self.operator,
            engagement.engagement_id,
            EngagementStatus.AUTHORIZATION_PENDING,
        )

        with self.assertRaises((PermissionError, ValueError)):
            self.store.set_engagement_status(
                self.operator,
                engagement.engagement_id,
                EngagementStatus.RUNNING,
            )

        persisted = self.store.get_engagement(
            self.operator,
            engagement.engagement_id,
        )
        self.assertIs(
            persisted.status,
            EngagementStatus.AUTHORIZATION_PENDING,
        )

    def test_authorized_engagement_with_current_grant_can_enter_running(self):
        engagement = self._engagement("authorized-current")
        self._grant(engagement.engagement_id)
        self.store.set_engagement_status(
            self.operator,
            engagement.engagement_id,
            EngagementStatus.AUTHORIZED,
        )

        running = self.store.set_engagement_status(
            self.operator,
            engagement.engagement_id,
            EngagementStatus.RUNNING,
        )

        self.assertIs(running.status, EngagementStatus.RUNNING)

    def test_revoked_historical_grant_cannot_power_reopened_running_state(self):
        engagement = self._engagement("closed-reopened")
        grant = self._grant(engagement.engagement_id)
        self.store.set_engagement_status(
            self.operator,
            engagement.engagement_id,
            EngagementStatus.AUTHORIZED,
        )
        self.store.set_engagement_status(
            self.operator,
            engagement.engagement_id,
            EngagementStatus.CLOSED,
        )

        current = self.store.get_current_grant(
            self.operator,
            engagement.engagement_id,
        )
        self.assertIsNone(current)

        self.store.set_engagement_status(
            self.operator,
            engagement.engagement_id,
            EngagementStatus.DRAFT,
        )

        with self.assertRaises((PermissionError, ValueError)):
            self.store.set_engagement_status(
                self.operator,
                engagement.engagement_id,
                EngagementStatus.RUNNING,
            )

        persisted = self.store.get_engagement(
            self.operator,
            engagement.engagement_id,
        )
        self.assertIs(persisted.status, EngagementStatus.DRAFT)

        grants = self.store.list_authorization_grants(
            self.operator,
            engagement.engagement_id,
        )
        stored = next(item for item in grants if item.grant_id == grant.grant_id)
        self.assertTrue(stored.is_revoked)


if __name__ == "__main__":
    unittest.main()
