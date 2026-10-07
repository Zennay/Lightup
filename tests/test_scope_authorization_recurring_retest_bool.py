from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


def _grant_window() -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return now - timedelta(hours=1), now + timedelta(days=30)


class RecurringRetestGrantAuthorityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-recurring-retest", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Recurring Retest Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Recurring Retest Contract"
        )
        self.scope = ScopeDefinition(
            assets=("app.example.test",),
            max_risk=RiskLevel.STANDARD,
        )
        self.valid_from, self.valid_until = _grant_window()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _record(self, recurring_retest_allowed: object):
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "Security Owner",
            "AUTH-RECURRING-RETEST",
            self.scope,
            self.valid_from,
            self.valid_until,
            recurring_retest_allowed=recurring_retest_allowed,  # type: ignore[arg-type]
        )

    def test_exact_booleans_round_trip_without_coercion(self) -> None:
        disabled = self._record(False)
        enabled = self._record(True)

        self.assertIs(disabled.recurring_retest_allowed, False)
        self.assertIs(enabled.recurring_retest_allowed, True)

        persisted = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )
        self.assertEqual(len(persisted), 2)
        self.assertIs(persisted[0].recurring_retest_allowed, True)
        self.assertIs(persisted[1].recurring_retest_allowed, False)

    def test_truthy_non_boolean_cannot_mint_recurring_retest_authority(self) -> None:
        before = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )

        with self.assertRaises(ValueError):
            self._record("false")

        after = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )
        self.assertEqual(after, before)

    def test_falsy_non_boolean_cannot_be_silently_normalized(self) -> None:
        before = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )

        with self.assertRaises(ValueError):
            self._record(0)

        after = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
