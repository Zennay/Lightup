"""Ordinary passing tests for the new uninstalled #647 issuance-time snapshot.

Synthetic disposable SQLite is exercised only by positive test-owned helper
calls. Original DomainStore source is never patched or activated by this file.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.grant_issuance_window_snapshot_647 import (
    CanonicalIssueWindow, WindowRejected, snapshot_grant_issuance_window
)
from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition

NOW = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)


class _SerializerSpoof(datetime):
    invoked = False

    def __le__(self, other):
        type(self).invoked = True
        return True

    def isoformat(self, *args, **kwargs):
        type(self).invoked = True
        return "2999-01-01T00:00:00+00:00"


class _BombTimezone(tzinfo):
    invoked = False

    def utcoffset(self, value):
        self.invoked = True
        raise AssertionError("untrusted timezone method must not run")

    def dst(self, value):
        self.invoked = True
        raise AssertionError("untrusted timezone method must not run")


def _subclassed(value):
    return _SerializerSpoof(
        value.year, value.month, value.day, value.hour, value.minute,
        value.second, value.microsecond, tzinfo=value.tzinfo
    )


class GrantIssuanceWindowSnapshotTests(unittest.TestCase):
    def setUp(self):
        _SerializerSpoof.invoked = False

    def test_exact_utc_snapshot(self):
        pair = snapshot_grant_issuance_window(NOW - timedelta(hours=1),
                                              NOW + timedelta(hours=1))
        self.assertIs(type(pair), CanonicalIssueWindow)
        self.assertIs(type(pair.starts_at_utc), datetime)
        self.assertIs(type(pair.expires_at_utc), datetime)
        self.assertIs(pair.starts_at_utc.tzinfo, timezone.utc)
        self.assertIs(pair.expires_at_utc.tzinfo, timezone.utc)

    def test_different_exact_timezone_offsets_normalize_to_same_utc_instants(self):
        plus = timezone(timedelta(hours=5, minutes=30))
        minus = timezone(timedelta(hours=-3))
        start = (NOW - timedelta(minutes=1)).astimezone(plus)
        until = (NOW + timedelta(minutes=1)).astimezone(minus)
        pair = snapshot_grant_issuance_window(start, until)
        self.assertEqual(pair.starts_at_utc, NOW - timedelta(minutes=1))
        self.assertEqual(pair.expires_at_utc, NOW + timedelta(minutes=1))

    def test_same_instant_through_different_offsets_is_invalid(self):
        start = NOW.astimezone(timezone(timedelta(hours=3)))
        until = NOW.astimezone(timezone(timedelta(hours=-5)))
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(start, until)

    def test_empty_and_reversed_bounds_reject(self):
        for starts, ends in ((NOW, NOW), (NOW + timedelta(seconds=1), NOW)):
            with self.subTest(starts=starts, ends=ends):
                with self.assertRaises(WindowRejected):
                    snapshot_grant_issuance_window(starts, ends)

    def test_rejects_all_nondatetime_types(self):
        invalid = (None, 0, False, "", (), {}, [])
        for v in invalid:
            with self.subTest(value=repr(v)):
                with self.assertRaises(WindowRejected):
                    snapshot_grant_issuance_window(v, NOW + timedelta(hours=1))
                with self.assertRaises(WindowRejected):
                    snapshot_grant_issuance_window(NOW, v)

    def test_naive_start_or_expiry_refused(self):
        naive = NOW.replace(tzinfo=None)
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(naive, NOW + timedelta(hours=1))
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(NOW, naive)

    def test_overridden_start_serializer_refused_before_method_call(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(_subclassed(NOW), NOW + timedelta(hours=1))
        self.assertFalse(_SerializerSpoof.invoked)

    def test_overridden_expiry_serializer_refused_before_method_call(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(NOW, _subclassed(NOW + timedelta(hours=1)))
        self.assertFalse(_SerializerSpoof.invoked)

    def test_custom_tzinfo_rejected_without_invocation(self):
        tz = _BombTimezone()
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                datetime(2026, 10, 14, 12, tzinfo=tz),
                NOW + timedelta(hours=1)
            )
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                NOW, datetime(2026, 10, 14, 13, tzinfo=tz)
            )
        self.assertFalse(tz.invoked)

    def test_time_conversion_outside_supported_datetime_year_rejected(self):
        start = datetime.min.replace(tzinfo=timezone(timedelta(hours=1)))
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(start, NOW)
        until = datetime.max.replace(tzinfo=timezone(timedelta(hours=-1)))
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(NOW, until)

    def test_never_uses_implicit_now_or_current_time(self):
        with patch("lightup.grant_issuance_window_snapshot_647.datetime") as fake_dt:
            fake_dt.now.side_effect = AssertionError("no current clock")
            # Inputs do not match patched datetime identity; denial remains safe.
            with self.assertRaises(WindowRejected):
                snapshot_grant_issuance_window(NOW, NOW + timedelta(hours=1))
            fake_dt.now.assert_not_called()

    def test_input_object_is_unchanged(self):
        starts, until = NOW, NOW + timedelta(hours=1)
        before = repr((starts, until))
        snapshot_grant_issuance_window(starts, until)
        self.assertEqual(repr((starts, until)), before)

    def test_snapshot_result_is_immutable(self):
        pair = snapshot_grant_issuance_window(NOW, NOW + timedelta(hours=1))
        with self.assertRaises(AttributeError):
            pair.starts_at_utc = NOW - timedelta(days=1)

    def test_no_network_or_state_side_effects(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("socket.socket", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("database")):
            snapshot_grant_issuance_window(NOW, NOW + timedelta(hours=1))

    def test_normalized_utc_isoformat_has_no_subclass_hook(self):
        pair = snapshot_grant_issuance_window(
            NOW.astimezone(timezone(timedelta(hours=4))),
            (NOW + timedelta(hours=1)).astimezone(timezone(timedelta(hours=-4))),
        )
        self.assertEqual(pair.starts_at_utc.isoformat(), NOW.isoformat())
        self.assertFalse(_SerializerSpoof.invoked)


class DisposableSQLitePreIssuanceAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "lab-only.sqlite")
        self.operator = AccessContext("fixture-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional Tenant")
        self.eng = self.store.create_engagement(self.operator, client.client_id,
                                                "Fictional Engagement")
        self.scope = ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",)
        )
        self.start = datetime.now(timezone.utc) - timedelta(minutes=10)
        self.until = datetime.now(timezone.utc) + timedelta(minutes=10)

    def _count_grants(self):
        with self.store._connect() as con:
            return con.execute("SELECT count(*) FROM authorization_grants").fetchone()[0]

    def _issue_only_after_snapshot(self, start, until):
        safe = snapshot_grant_issuance_window(start, until)
        return self.store.record_authorization_grant(
            self.operator, self.eng.engagement_id, "Synthetic Operator",
            "NOT_REAL_CONSENT", self.scope,
            safe.starts_at_utc, safe.expires_at_utc
        )

    def test_bad_subclass_never_calls_real_issuance_or_writes_sqlite(self):
        for which in ("start", "until"):
            start, until = self.start, self.until
            if which == "start":
                start = _subclassed(start)
            else:
                until = _subclassed(until)
            with self.subTest(which=which):
                with self.assertRaises(WindowRejected):
                    self._issue_only_after_snapshot(start, until)
                self.assertEqual(self._count_grants(), 0)
                self.assertFalse(_SerializerSpoof.invoked)

    def test_good_fixed_offset_is_persisted_as_exact_utc_without_widening(self):
        start = self.start.astimezone(timezone(timedelta(hours=3)))
        until = self.until.astimezone(timezone(timedelta(hours=-4)))
        issued = self._issue_only_after_snapshot(start, until)
        with self.store._connect() as con:
            row = con.execute(
                "SELECT valid_from, valid_until FROM authorization_grants WHERE grant_id=?",
                (issued.grant_id,),
            ).fetchone()
        self.assertEqual(row["valid_from"], self.start.isoformat())
        self.assertEqual(row["valid_until"], self.until.isoformat())
        self.assertEqual(self._count_grants(), 1)

    def test_invalid_types_do_not_create_partial_persisted_grants(self):
        for value in (0, False, "", None):
            with self.subTest(value=value):
                with self.assertRaises(WindowRejected):
                    self._issue_only_after_snapshot(self.start, value)
                self.assertEqual(self._count_grants(), 0)


if __name__ == "__main__":
    unittest.main()
