"""Offline source-independent acceptance for LightUp's non-authorizing #647 snapshot.

This module deliberately uses NO DomainStore, ToolExecutor, activation gate,
customer authorization, network targets, or source-owner branch dependencies.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.grant_issuance_window_snapshot_647 import (
    CanonicalIssueWindow, WindowRejected, snapshot_grant_issuance_window,
)

FIXED_NOW = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)


class _SpoofDatetime(datetime):
    """Illegal input must be refused before any attacker-overridable hook."""

    touched = False

    def __le__(self, other):
        type(self).touched = True
        return True

    def __gt__(self, other):
        type(self).touched = True
        return False

    def isoformat(self, *args, **kwargs):
        type(self).touched = True
        return "2999-12-31T23:59:59+00:00"

    def astimezone(self, *args, **kwargs):
        type(self).touched = True
        return FIXED_NOW


class _BombTimezone(tzinfo):
    touched = False

    def utcoffset(self, value):
        self.touched = True
        raise AssertionError("custom timezone must not execute")

    def dst(self, value):
        self.touched = True
        raise AssertionError("custom timezone must not execute")


def _subclassed(ordinary):
    return _SpoofDatetime(
        ordinary.year, ordinary.month, ordinary.day, ordinary.hour,
        ordinary.minute, ordinary.second, ordinary.microsecond,
        tzinfo=ordinary.tzinfo,
    )


class SnapshotMainlineTests(unittest.TestCase):
    def setUp(self):
        _SpoofDatetime.touched = False

    def test_normal_utc_produces_exact_builtins(self):
        result = snapshot_grant_issuance_window(
            FIXED_NOW, FIXED_NOW + timedelta(hours=1)
        )
        self.assertIs(type(result), CanonicalIssueWindow)
        self.assertIs(type(result.starts_at_utc), datetime)
        self.assertIs(type(result.expires_at_utc), datetime)
        self.assertIs(result.starts_at_utc.tzinfo, timezone.utc)
        self.assertIs(result.expires_at_utc.tzinfo, timezone.utc)

    def test_non_utc_exact_builtin_offset_produces_identical_utc_instants(self):
        start = FIXED_NOW.astimezone(timezone(timedelta(hours=5, minutes=45)))
        end = (FIXED_NOW + timedelta(hours=1)).astimezone(
            timezone(timedelta(hours=-7))
        )
        result = snapshot_grant_issuance_window(start, end)
        self.assertEqual(result.starts_at_utc, FIXED_NOW)
        self.assertEqual(result.expires_at_utc, FIXED_NOW + timedelta(hours=1))

    def test_cross_midnight_offsets_preserve_true_instant(self):
        late = datetime(2026, 10, 15, 0, 15, tzinfo=timezone(timedelta(hours=9)))
        end = (late + timedelta(minutes=5)).astimezone(timezone.utc)
        result = snapshot_grant_issuance_window(late, end)
        self.assertEqual(result.expires_at_utc - result.starts_at_utc,
                         timedelta(minutes=5))

    def test_narrow_valid_microsecond_interval_preserved(self):
        result = snapshot_grant_issuance_window(
            FIXED_NOW, FIXED_NOW + timedelta(microseconds=1)
        )
        self.assertEqual(result.expires_at_utc - result.starts_at_utc,
                         timedelta(microseconds=1))

    def test_same_instant_in_different_offsets_is_empty(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                FIXED_NOW.astimezone(timezone(timedelta(hours=5))),
                FIXED_NOW.astimezone(timezone(timedelta(hours=-3))),
            )

    def test_reversed_window_rejected(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                FIXED_NOW + timedelta(seconds=1), FIXED_NOW
            )

    def test_equal_window_rejected(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(FIXED_NOW, FIXED_NOW)

    def test_naive_start_and_expiry_refused(self):
        for index in (0, 1):
            args = [FIXED_NOW, FIXED_NOW + timedelta(hours=1)]
            args[index] = args[index].replace(tzinfo=None)
            with self.subTest(index=index), self.assertRaises(WindowRejected):
                snapshot_grant_issuance_window(*args)

    def test_type_confused_both_fields_refused(self):
        for field in (0, 1):
            for bad in (None, False, 0, "", b"", (), [], {}):
                args = [FIXED_NOW, FIXED_NOW + timedelta(minutes=1)]
                args[field] = bad
                with self.subTest(field=field, bad=repr(bad)):
                    with self.assertRaises(WindowRejected):
                        snapshot_grant_issuance_window(*args)

    def test_subclassed_start_denied_before_comparison_or_serializer(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                _subclassed(FIXED_NOW), FIXED_NOW + timedelta(minutes=1)
            )
        self.assertFalse(_SpoofDatetime.touched)

    def test_subclassed_expiry_denied_before_comparison_or_serializer(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                FIXED_NOW, _subclassed(FIXED_NOW + timedelta(minutes=1))
            )
        self.assertFalse(_SpoofDatetime.touched)

    def test_custom_timezone_start_denied_before_hook(self):
        tz = _BombTimezone()
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                datetime(2026, 10, 14, 11, tzinfo=tz),
                FIXED_NOW + timedelta(minutes=1),
            )
        self.assertFalse(tz.touched)

    def test_custom_timezone_expiry_denied_before_hook(self):
        tz = _BombTimezone()
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                FIXED_NOW,
                datetime(2026, 10, 14, 14, tzinfo=tz),
            )
        self.assertFalse(tz.touched)

    def test_underflow_normalization_denied(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                datetime.min.replace(tzinfo=timezone(timedelta(hours=1))),
                FIXED_NOW,
            )

    def test_overflow_normalization_denied(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                FIXED_NOW,
                datetime.max.replace(tzinfo=timezone(timedelta(hours=-1))),
            )

    def test_result_prevents_attribute_reassignment(self):
        result = snapshot_grant_issuance_window(
            FIXED_NOW, FIXED_NOW + timedelta(minutes=1)
        )
        with self.assertRaises(AttributeError):
            result.expires_at_utc = FIXED_NOW + timedelta(days=365)

    def test_result_isoformat_is_exact_and_cannot_call_spoof(self):
        result = snapshot_grant_issuance_window(
            FIXED_NOW.astimezone(timezone(timedelta(hours=3))),
            (FIXED_NOW + timedelta(minutes=1)).astimezone(
                timezone(timedelta(hours=-3))
            ),
        )
        self.assertEqual(result.expires_at_utc.isoformat(),
                         (FIXED_NOW + timedelta(minutes=1)).isoformat())
        self.assertFalse(_SpoofDatetime.touched)

    def test_caller_inputs_are_not_mutated(self):
        start = FIXED_NOW
        end = FIXED_NOW + timedelta(minutes=1)
        before = repr((start, end))
        snapshot_grant_issuance_window(start, end)
        self.assertEqual(repr((start, end)), before)

    def test_no_clock_network_or_database_side_effects(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("database")):
            result = snapshot_grant_issuance_window(
                FIXED_NOW, FIXED_NOW + timedelta(minutes=1)
            )
            self.assertEqual(result.starts_at_utc, FIXED_NOW)

    def test_no_authorization_or_permit_returned(self):
        result = snapshot_grant_issuance_window(
            FIXED_NOW, FIXED_NOW + timedelta(minutes=1)
        )
        self.assertEqual(result._fields, ("starts_at_utc", "expires_at_utc"))
        self.assertFalse(hasattr(result, "permit_issued"))
        self.assertFalse(hasattr(result, "authorization_verified"))
        self.assertFalse(hasattr(result, "approved_by"))


if __name__ == "__main__":
    unittest.main()
