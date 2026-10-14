"""Genuine disposable SQLite acceptance for the opt-in #647 UTC snapshot on main.

The original DomainStore source remains untouched. Only fictional test-owned
grant rows are ever persisted under a TemporaryDirectory, with no target I/O.
This verifies the safe path, NOT production authorization-enforcement.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.grant_issuance_window_snapshot_647 import (
    WindowRejected, snapshot_grant_issuance_window,
)


class _HostileDatetime(datetime):
    touched = False

    def isoformat(self, *args, **kwargs):
        type(self).touched = True
        return "2999-01-01T00:00:00+00:00"

    def __le__(self, other):
        type(self).touched = True
        return True


class _HostileTimezone(tzinfo):
    touched = False

    def utcoffset(self, value):
        self.touched = True
        raise AssertionError("no custom timezone hooks")

    def dst(self, value):
        self.touched = True
        raise AssertionError("no custom timezone hooks")


def _spoof(ordinary):
    return _HostileDatetime(
        ordinary.year, ordinary.month, ordinary.day, ordinary.hour,
        ordinary.minute, ordinary.second, ordinary.microsecond,
        tzinfo=ordinary.tzinfo,
    )


class MainlineSnapshotSQLiteAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-snapshot-test-")
        self.addCleanup(self.temp.cleanup)
        self.db_file = Path(self.temp.name) / "non_customer_temp.sqlite"
        self.store = DomainStore(self.db_file)
        self.operator = AccessContext("fictional-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional Tenant Only")
        self.eng = self.store.create_engagement(
            self.operator, client.client_id, "Synthetic Engagement"
        )
        self.scope = ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        )
        self.start = datetime.now(timezone.utc) - timedelta(minutes=15)
        self.end = datetime.now(timezone.utc) + timedelta(minutes=15)
        _HostileDatetime.touched = False

    def _row_count(self):
        with self.store._connect() as con:
            return con.execute(
                "SELECT COUNT(*) FROM authorization_grants"
            ).fetchone()[0]

    def _rows(self):
        with self.store._connect() as con:
            return con.execute(
                "SELECT grant_id, valid_from, valid_until "
                "FROM authorization_grants ORDER BY created_at"
            ).fetchall()

    def _issue_after_snapshot(self, start, end):
        window = snapshot_grant_issuance_window(start, end)
        return self.store.record_authorization_grant(
            self.operator,
            self.eng.engagement_id,
            "Synthetic Operator — Not Customer Consent",
            "FICTIONAL-NOT-CONSENT",
            self.scope,
            window.starts_at_utc,
            window.expires_at_utc,
        )

    def test_valid_builtin_utc_issuance_persists_same_instants(self):
        issued = self._issue_after_snapshot(self.start, self.end)
        self.assertEqual(self._row_count(), 1)
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["grant_id"], issued.grant_id)
        self.assertEqual(rows[0]["valid_from"], self.start.isoformat())
        self.assertEqual(rows[0]["valid_until"], self.end.isoformat())

    def test_both_non_utc_builtin_offsets_persist_as_utc(self):
        west = timezone(timedelta(hours=-7))
        east = timezone(timedelta(hours=5, minutes=30))
        issued = self._issue_after_snapshot(
            self.start.astimezone(east), self.end.astimezone(west)
        )
        row = self._rows()[0]
        self.assertEqual(row["grant_id"], issued.grant_id)
        self.assertEqual(row["valid_from"], self.start.isoformat())
        self.assertEqual(row["valid_until"], self.end.isoformat())

    def test_subclassed_start_is_denied_before_any_row_or_polymorphic_hook(self):
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(_spoof(self.start), self.end)
        self.assertFalse(_HostileDatetime.touched)
        self.assertEqual(self._row_count(), 0)

    def test_subclassed_end_is_denied_before_any_row_or_polymorphic_hook(self):
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(self.start, _spoof(self.end))
        self.assertFalse(_HostileDatetime.touched)
        self.assertEqual(self._row_count(), 0)

    def test_bad_datetime_type_is_denied_before_any_row(self):
        for wrong in (False, 0, "", None, (), {}, []):
            with self.subTest(value=repr(wrong)):
                with self.assertRaises(WindowRejected):
                    self._issue_after_snapshot(self.start, wrong)
                self.assertEqual(self._row_count(), 0)

    def test_naive_datetime_denied_before_any_row(self):
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(self.start.replace(tzinfo=None), self.end)
        self.assertEqual(self._row_count(), 0)

    def test_equal_bounds_denied_before_any_row(self):
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(self.start, self.start)
        self.assertEqual(self._row_count(), 0)

    def test_reverse_bounds_denied_before_any_row(self):
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(self.end, self.start)
        self.assertEqual(self._row_count(), 0)

    def test_custom_timezone_denied_without_invoking_utc_offset(self):
        tz = _HostileTimezone()
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(
                datetime(2026, 10, 14, 12, tzinfo=tz), self.end
            )
        self.assertFalse(tz.touched)
        self.assertEqual(self._row_count(), 0)

    def test_valid_then_denied_attempt_preserves_original_row_unchanged(self):
        self._issue_after_snapshot(self.start, self.end)
        before = [(r["grant_id"], r["valid_from"], r["valid_until"]) for r in self._rows()]
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(self.start, _spoof(self.end))
        after = [(r["grant_id"], r["valid_from"], r["valid_until"]) for r in self._rows()]
        self.assertEqual(before, after)
        self.assertEqual(self._row_count(), 1)
        self.assertFalse(_HostileDatetime.touched)

    def test_both_subclassed_fields_denied_before_any_row(self):
        with self.assertRaises(WindowRejected):
            self._issue_after_snapshot(_spoof(self.start), _spoof(self.end))
        self.assertFalse(_HostileDatetime.touched)
        self.assertEqual(self._row_count(), 0)

    def test_no_external_sockets_used_by_snapshot_plus_disposable_sqlite(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("socket.socket", side_effect=AssertionError("network")):
            grant = self._issue_after_snapshot(self.start, self.end)
            self.assertEqual(self._row_count(), 1)
            self.assertEqual(grant.reference, "FICTIONAL-NOT-CONSENT")

    def test_utc_snapshot_does_not_issue_any_grant_by_itself(self):
        snap = snapshot_grant_issuance_window(self.start, self.end)
        self.assertIs(type(snap.starts_at_utc), datetime)
        self.assertEqual(self._row_count(), 0)
        self.assertFalse(hasattr(snap, "permit_issued"))
        self.assertFalse(hasattr(snap, "authorization_verified"))


if __name__ == "__main__":
    unittest.main()
