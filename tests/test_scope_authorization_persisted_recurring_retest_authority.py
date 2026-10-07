from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedRecurringRetestAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-recurring-read", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Recurring Read Client")
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Recurring read",
        )

    def _grant(self, recurring: bool):
        now = datetime.now(timezone.utc)
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            approved_by="security-owner@example.test",
            reference=f"AUTH-RECUR-{int(recurring)}",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(days=1),
            recurring_retest_allowed=recurring,
        )

    def _set_raw(self, grant_id: str, value: object) -> object:
        with self.store._connect() as con:
            con.execute(
                "UPDATE authorization_grants "
                "SET recurring_retest_allowed=? WHERE grant_id=?",
                (value, grant_id),
            )
            row = con.execute(
                "SELECT recurring_retest_allowed "
                "FROM authorization_grants WHERE grant_id=?",
                (grant_id,),
            ).fetchone()
        assert row is not None
        return row["recurring_retest_allowed"]

    def _get_raw(self, grant_id: str) -> object:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT recurring_retest_allowed "
                "FROM authorization_grants WHERE grant_id=?",
                (grant_id,),
            ).fetchone()
        assert row is not None
        return row["recurring_retest_allowed"]

    def test_canonical_zero_and_one_round_trip_exactly(self):
        false_grant = self._grant(False)
        false_loaded = next(
            grant
            for grant in self.store.list_authorization_grants(
                self.operator,
                self.engagement.engagement_id,
            )
            if grant.grant_id == false_grant.grant_id
        )
        self.assertIs(false_loaded.recurring_retest_allowed, False)

        true_grant = self._grant(True)
        true_loaded = next(
            grant
            for grant in self.store.list_authorization_grants(
                self.operator,
                self.engagement.engagement_id,
            )
            if grant.grant_id == true_grant.grant_id
        )
        self.assertIs(true_loaded.recurring_retest_allowed, True)

    def test_noncanonical_persisted_values_fail_closed_without_repair(self):
        invalid_values = (
            2,
            -1,
            "true",
            sqlite3.Binary(b"\x01"),
        )

        for value in invalid_values:
            with self.subTest(value=value, value_type=type(value).__name__):
                grant = self._grant(False)
                stored = self._set_raw(grant.grant_id, value)

                with self.assertRaises((TypeError, ValueError)):
                    self.store.list_authorization_grants(
                        self.operator,
                        self.engagement.engagement_id,
                    )

                self.assertEqual(self._get_raw(grant.grant_id), stored)


if __name__ == "__main__":
    unittest.main()
