"""#890 W2: strict current-grant evaluation time with real SQLite snapshots.

The intentional REDs exercise unmodified DomainStore.get_current_grant.
The optional adapter remains uninstalled/non-authorizing. Synthetic only.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from unittest.mock import Mock

from lightup.current_grant_instant_optin import checked_current_grant_at
from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.engagements import RiskLevel, ScopeDefinition


class PoisonDatetime(datetime):
    def utcoffset(self):
        raise AssertionError("polymorphic datetime must not run")


class NaiveTz(tzinfo):
    def utcoffset(self, value):
        return None


class GrantCurrentInstantW2(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "scope890w2.db"
        self.store = DomainStore(self.db)
        self.operator = AccessContext("test-operator", Role.OPERATOR)
        a = self.store.create_client(self.operator, "Synthetic 890 A")
        b = self.store.create_client(self.operator, "Synthetic 890 B")
        self.a = AccessContext("test-a", Role.CLIENT_ADMIN, a.client_id)
        self.b = AccessContext("test-b", Role.CLIENT_ADMIN, b.client_id)
        self.one = self.store.create_engagement(self.operator, a.client_id, "Valid")
        self.empty = self.store.create_engagement(self.operator, a.client_id, "No grants")
        self.foreign = self.store.create_engagement(self.operator, b.client_id, "Other tenant")
        self.now = datetime.now(timezone.utc)
        self.start = self.now - timedelta(hours=1)
        self.end = self.now + timedelta(hours=1)
        self.grant = self._grant(self.one.engagement_id, self.start, self.end)

    def _grant(self, engagement_id, start, end):
        return self.store.record_authorization_grant(
            self.operator, engagement_id, "Synthetic reviewer", "LAB-890-W2",
            ScopeDefinition(("time890.example.test",), RiskLevel.PASSIVE),
            start, end,
        )

    def snapshot(self):
        with sqlite3.connect(self.db) as connection:
            return connection.execute(
                "SELECT grant_id,client_id,engagement_id,valid_from,valid_until "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall()

    @unittest.expectedFailure
    def test_red_default_explicit_false_cannot_be_omitted_without_grant(self):
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.a, self.empty.engagement_id, now=False)

    @unittest.expectedFailure
    def test_red_default_explicit_zero_cannot_be_omitted_when_expired(self):
        self._grant(
            self.empty.engagement_id,
            self.now - timedelta(days=3), self.now - timedelta(days=2),
        )
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.a, self.empty.engagement_id, now=0)

    @unittest.expectedFailure
    def test_red_default_empty_string_cannot_be_omitted_when_not_yet_valid(self):
        self._grant(
            self.empty.engagement_id,
            self.now + timedelta(days=2), self.now + timedelta(days=3),
        )
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.a, self.empty.engagement_id, now="")

    @unittest.expectedFailure
    def test_red_default_empty_bytes_cannot_be_reinterpreted_as_now(self):
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.a, self.one.engagement_id, now=b"")

    @unittest.expectedFailure
    def test_red_default_empty_list_cannot_be_reinterpreted_as_now(self):
        with self.assertRaises((TypeError, ValueError)):
            self.store.get_current_grant(self.a, self.one.engagement_id, now=[])

    def test_canonical_exact_start_time_is_inclusive(self):
        result = checked_current_grant_at(
            self.store, self.a, self.one.engagement_id, now=self.start,
        )
        self.assertEqual(result.grant_id, self.grant.grant_id)

    def test_canonical_exact_end_time_is_inclusive(self):
        result = checked_current_grant_at(
            self.store, self.a, self.one.engagement_id, now=self.end,
        )
        self.assertEqual(result.grant_id, self.grant.grant_id)

    def test_explicit_before_window_is_none(self):
        result = checked_current_grant_at(
            self.store, self.a, self.one.engagement_id,
            now=self.start - timedelta(microseconds=1),
        )
        self.assertIsNone(result)

    def test_explicit_after_window_is_none(self):
        result = checked_current_grant_at(
            self.store, self.a, self.one.engagement_id,
            now=self.end + timedelta(microseconds=1),
        )
        self.assertIsNone(result)

    def test_non_utc_offset_selects_same_grant(self):
        offset = timezone(timedelta(hours=-7))
        other_zone = self.now.astimezone(offset)
        result = checked_current_grant_at(
            self.store, self.a, self.one.engagement_id, now=other_zone,
        )
        self.assertEqual(result.grant_id, self.grant.grant_id)

    def test_type_confusion_rejected_before_any_store_call(self):
        fake = Mock()
        for bad in (False, 0, "", b"", [], {}, (), 0.0):
            with self.subTest(type=type(bad).__name__), self.assertRaises(TypeError):
                checked_current_grant_at(fake, self.a, self.one.engagement_id, now=bad)
        fake.get_current_grant.assert_not_called()

    def test_polymorphic_datetime_never_evaluates_its_offset(self):
        instant = PoisonDatetime(2026, 10, 12, tzinfo=timezone.utc)
        fake = Mock()
        with self.assertRaises(TypeError):
            checked_current_grant_at(fake, self.a, self.one.engagement_id, now=instant)
        fake.get_current_grant.assert_not_called()

    def test_naive_timezone_proxy_refused_before_store(self):
        fake = Mock()
        instant = datetime(2026, 10, 12, tzinfo=NaiveTz())
        with self.assertRaises(ValueError):
            checked_current_grant_at(fake, self.a, self.one.engagement_id, now=instant)
        fake.get_current_grant.assert_not_called()

    def test_canonical_exact_instant_delegates_original_object_once(self):
        fake = Mock()
        token = object()
        fake.get_current_grant.return_value = token
        result = checked_current_grant_at(fake, self.a, self.one.engagement_id, now=self.now)
        self.assertIs(result, token)
        fake.get_current_grant.assert_called_once_with(
            self.a, self.one.engagement_id, now=self.now,
        )

    def test_invalid_instants_leave_entire_persisted_grant_table_unchanged(self):
        before = self.snapshot()
        for bad in (False, 0, "", b"", [], {}, PoisonDatetime(2026, 10, 12)):
            with self.subTest(type=type(bad).__name__), self.assertRaises((TypeError, ValueError)):
                checked_current_grant_at(self.store, self.a, self.one.engagement_id, now=bad)
            self.assertEqual(self.snapshot(), before)

    def test_foreign_tenant_never_obtains_other_client_grant(self):
        with self.assertRaises(TenantIsolationError):
            checked_current_grant_at(self.store, self.b, self.one.engagement_id, now=self.now)

    def test_exact_aware_time_cannot_borrow_grant_for_other_engagement(self):
        self.assertIsNone(checked_current_grant_at(
            self.store, self.a, self.empty.engagement_id, now=self.now
        ))

    def test_none_is_the_only_supported_omission_sentinel(self):
        returned = checked_current_grant_at(
            self.store, self.a, self.one.engagement_id, now=None,
        )
        self.assertEqual(returned.grant_id, self.grant.grant_id)


if __name__ == "__main__":
    unittest.main()
