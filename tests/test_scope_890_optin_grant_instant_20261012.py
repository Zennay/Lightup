"""#890: actual disposable SQLite grant-selector tests plus opt-in strict adapter.

All data are synthetic .test values. The three expected-failure tests are
unfixed default DomainStore behavior, not an authorization bypass claim.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from lightup.current_grant_instant_optin import checked_current_grant_at
from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.engagements import RiskLevel, ScopeDefinition


class DatetimeSubclass(datetime):
    pass


class CurrentGrantInstantIssue890(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "scope890.db"
        self.store = DomainStore(self.path)
        self.operator = AccessContext("synthetic-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic client A")
        other = self.store.create_client(self.operator, "Synthetic client B")
        self.client = AccessContext("synthetic-user-a", Role.CLIENT_ADMIN, client.client_id)
        self.foreign = AccessContext("synthetic-user-b", Role.CLIENT_ADMIN, other.client_id)
        engagement = self.store.create_engagement(self.operator, client.client_id, "Synthetic Q4")
        self.engagement_id = engagement.engagement_id
        self.now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator, self.engagement_id, "Synthetic operator", "LAB-890",
            ScopeDefinition(("scope890.example.test",), RiskLevel.PASSIVE),
            self.now - timedelta(hours=2), self.now + timedelta(hours=2),
        )

    def snapshot(self):
        with sqlite3.connect(self.path) as connection:
            return connection.execute(
                "SELECT grant_id,client_id,engagement_id,valid_from,valid_until "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall()

    @unittest.expectedFailure
    def test_red_default_selector_false_must_not_mean_omitted_instant(self):
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.client, self.engagement_id, now=False)

    @unittest.expectedFailure
    def test_red_default_selector_zero_must_not_mean_omitted_instant(self):
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.client, self.engagement_id, now=0)

    @unittest.expectedFailure
    def test_red_default_selector_empty_string_must_not_mean_omitted_instant(self):
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.client, self.engagement_id, now="")

    def test_optin_denies_all_falsy_and_polymorphic_instants_before_store(self):
        sentinel = Mock()
        for value in (False, 0, "", 0.0, [], {}, b"", date.today(),
                      DatetimeSubclass(2026, 10, 12, tzinfo=timezone.utc)):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    checked_current_grant_at(sentinel, self.client, self.engagement_id, now=value)
        sentinel.get_current_grant.assert_not_called()

    def test_optin_naive_datetime_refused_before_store(self):
        sentinel = Mock()
        with self.assertRaises(ValueError):
            checked_current_grant_at(
                sentinel, self.client, self.engagement_id,
                now=datetime(2026, 10, 12, 12, 30),
            )
        sentinel.get_current_grant.assert_not_called()

    def test_optin_explicit_none_selects_existing_persisted_grant(self):
        found = checked_current_grant_at(self.store, self.client, self.engagement_id, now=None)
        self.assertIsNotNone(found)
        self.assertEqual(found.grant_id, self.grant.grant_id)

    def test_optin_aware_utc_datetime_selects_existing_grant(self):
        found = checked_current_grant_at(self.store, self.client, self.engagement_id, now=self.now)
        self.assertIsNotNone(found)
        self.assertEqual(found.grant_id, self.grant.grant_id)

    def test_optin_aware_non_utc_offset_selects_same_grant(self):
        instant = self.now.astimezone(timezone(timedelta(hours=5, minutes=30)))
        found = checked_current_grant_at(self.store, self.client, self.engagement_id, now=instant)
        self.assertEqual(found.grant_id, self.grant.grant_id)

    def test_optin_expired_time_returns_none_never_extends_grant(self):
        late = self.now + timedelta(days=3)
        self.assertIsNone(checked_current_grant_at(
            self.store, self.client, self.engagement_id, now=late
        ))

    def test_optin_before_valid_from_returns_none(self):
        early = self.now - timedelta(days=3)
        self.assertIsNone(checked_current_grant_at(
            self.store, self.client, self.engagement_id, now=early
        ))

    def test_optin_invalid_types_never_mutate_durable_grant_rows(self):
        before = self.snapshot()
        for value in (False, 0, "", [], {}, datetime(2026, 10, 12)):
            with self.subTest(value=str(type(value))):
                with self.assertRaises((TypeError, ValueError)):
                    checked_current_grant_at(self.store, self.client, self.engagement_id, now=value)
                self.assertEqual(self.snapshot(), before)

    def test_optin_foreign_client_does_not_obtain_other_tenant_grant(self):
        with self.assertRaises(TenantIsolationError):
            checked_current_grant_at(
                self.store, self.foreign, self.engagement_id, now=self.now
            )

    def test_optin_omission_creates_exact_aware_instant(self):
        spy = Mock()
        spy.get_current_grant.return_value = None
        self.assertIsNone(checked_current_grant_at(spy, self.client, self.engagement_id))
        positional = spy.get_current_grant.call_args
        supplied = positional.kwargs["now"]
        self.assertIs(type(supplied), datetime)
        self.assertIsNotNone(supplied.tzinfo)
        self.assertIsNotNone(supplied.utcoffset())

    def test_default_selector_unchanged_for_normal_inputs(self):
        direct = self.store.get_current_grant(
            self.client, self.engagement_id, now=self.now
        )
        optin = checked_current_grant_at(
            self.store, self.client, self.engagement_id, now=self.now
        )
        self.assertEqual(direct.grant_id, optin.grant_id)


if __name__ == "__main__":
    unittest.main()
