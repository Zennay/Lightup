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


class PersistedRecurringRetestAuthorityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-persisted-retest", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Persisted Retest Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Persisted Retest Contract"
        )
        scope = ScopeDefinition(
            assets=("app.example.test",),
            max_risk=RiskLevel.STANDARD,
        )
        valid_from, valid_until = _grant_window()
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "Security Owner",
            "AUTH-PERSISTED-RETEST",
            scope,
            valid_from,
            valid_until,
            recurring_retest_allowed=False,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_persisted_flag(self, value: object) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE authorization_grants "
                "SET recurring_retest_allowed=? WHERE grant_id=?",
                (value, self.grant.grant_id),
            )

    def test_canonical_zero_and_one_reconstruct_as_exact_booleans(self) -> None:
        self._set_persisted_flag(0)
        disabled = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )[0]
        self.assertIs(disabled.recurring_retest_allowed, False)

        self._set_persisted_flag(1)
        enabled = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )[0]
        self.assertIs(enabled.recurring_retest_allowed, True)

    def test_noncanonical_integer_cannot_mint_recurring_retest_authority(self) -> None:
        self._set_persisted_flag(2)

        with self.assertRaises(ValueError):
            self.store.list_authorization_grants(
                self.operator, self.engagement.engagement_id
            )

        with self.store._connect() as con:
            stored = con.execute(
                "SELECT recurring_retest_allowed FROM authorization_grants "
                "WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()[0]
        self.assertEqual(stored, 2)

    def test_noncanonical_text_cannot_be_truthiness_normalized(self) -> None:
        self._set_persisted_flag("false")

        with self.assertRaises(ValueError):
            self.store.list_authorization_grants(
                self.operator, self.engagement.engagement_id
            )

        with self.store._connect() as con:
            stored = con.execute(
                "SELECT recurring_retest_allowed FROM authorization_grants "
                "WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()[0]
        self.assertEqual(stored, "false")


if __name__ == "__main__":
    unittest.main()
