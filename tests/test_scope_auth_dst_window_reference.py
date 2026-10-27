"""Offline reference: authorization windows are instants, not ambiguous wall clocks.

This file intentionally does NOT exercise the production executor or grant issuer.
"""
import datetime as dt
import unittest
from zoneinfo import ZoneInfo

UTC = dt.timezone.utc


def _instant(value):
    """Reference-only strict instant parsing, never an authorization API."""
    if type(value) is not dt.datetime or value.tzinfo is None:
        raise ValueError("aware exact datetime required")
    offset = value.utcoffset()
    if offset is None:
        raise ValueError("undefined UTC offset")
    return value.astimezone(UTC)


def reference_window_allows(start, end, observed):
    start_utc, end_utc, now_utc = map(_instant, (start, end, observed))
    return start_utc < end_utc and start_utc <= now_utc < end_utc


class ScopeAuthorizationDSTWindowReference(unittest.TestCase):
    def setUp(self):
        self.zone = ZoneInfo("Europe/London")

    def test_fall_back_repeated_wall_time_has_two_distinct_instants(self):
        wall = dt.datetime(2026, 10, 25, 1, 30)
        first = wall.replace(tzinfo=self.zone, fold=0)
        second = wall.replace(tzinfo=self.zone, fold=1)
        self.assertNotEqual(_instant(first), _instant(second))
        self.assertEqual((_instant(second) - _instant(first)).total_seconds(), 3600)

    def test_first_fold_window_does_not_authorize_second_fold(self):
        begin = dt.datetime(2026, 10, 25, 1, 10, tzinfo=self.zone, fold=0)
        end = dt.datetime(2026, 10, 25, 1, 50, tzinfo=self.zone, fold=0)
        observed = dt.datetime(2026, 10, 25, 1, 30, tzinfo=self.zone, fold=1)
        self.assertFalse(reference_window_allows(begin, end, observed))

    def test_second_fold_window_does_not_authorize_first_fold(self):
        begin = dt.datetime(2026, 10, 25, 1, 10, tzinfo=self.zone, fold=1)
        end = dt.datetime(2026, 10, 25, 1, 50, tzinfo=self.zone, fold=1)
        observed = dt.datetime(2026, 10, 25, 1, 30, tzinfo=self.zone, fold=0)
        self.assertFalse(reference_window_allows(begin, end, observed))

    def test_expiry_is_exclusive_across_fall_back(self):
        begin = dt.datetime(2026, 10, 25, 0, 50, tzinfo=UTC)
        end = dt.datetime(2026, 10, 25, 1, 30, tzinfo=UTC)
        self.assertTrue(reference_window_allows(begin, end, end - dt.timedelta(microseconds=1)))
        self.assertFalse(reference_window_allows(begin, end, end))

    def test_cross_offset_representation_of_same_instant(self):
        begin = dt.datetime(2026, 10, 25, 0, 0, tzinfo=UTC)
        end = dt.datetime(2026, 10, 25, 1, 0, tzinfo=UTC)
        observed = dt.datetime(2026, 10, 25, 1, 30, tzinfo=self.zone, fold=0)
        self.assertTrue(reference_window_allows(begin, end, observed))

    def test_naive_datetime_rejected(self):
        begin = dt.datetime(2026, 10, 25, 0, 0)
        end = dt.datetime(2026, 10, 25, 2, 0, tzinfo=UTC)
        with self.assertRaises(ValueError):
            reference_window_allows(begin, end, dt.datetime.now(UTC))

    def test_invalid_or_reversed_window_denied(self):
        start = dt.datetime(2026, 10, 25, 1, 0, tzinfo=UTC)
        end = start - dt.timedelta(seconds=1)
        self.assertFalse(reference_window_allows(start, end, start))
        self.assertFalse(reference_window_allows(start, start, start))

    def test_subclass_datetime_rejected(self):
        class SpoofedDatetime(dt.datetime):
            pass
        spoof = SpoofedDatetime(2026, 10, 25, tzinfo=UTC)
        with self.assertRaises(ValueError):
            reference_window_allows(spoof, dt.datetime(2026, 10, 26, tzinfo=UTC), dt.datetime.now(UTC))


if __name__ == "__main__":
    unittest.main()
