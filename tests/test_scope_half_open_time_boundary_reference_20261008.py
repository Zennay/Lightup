"""Offline acceptance reference for precision-safe scope approval windows.

This module deliberately does not import or alter runtime authorization code.
"""
from datetime import datetime, timedelta, timezone
import unittest


def eligible_window(start, end, now):
    """Reference-only predicate; NEVER an execution authorization."""
    if any(type(value) is not datetime for value in (start, end, now)):
        return False
    if any(value.tzinfo is None or value.utcoffset() is None for value in (start, end, now)):
        return False
    try:
        start_utc, end_utc, now_utc = (
            value.astimezone(timezone.utc) for value in (start, end, now)
        )
    except (OverflowError, ValueError, TypeError):
        return False
    return start_utc < end_utc and start_utc <= now_utc < end_utc


class HalfOpenWindowReferenceTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 10, 8, 10, 0, 0, tzinfo=timezone.utc)
        self.end = self.start + timedelta(microseconds=2)

    def test_exact_start_accepted(self):
        self.assertTrue(eligible_window(self.start, self.end, self.start))

    def test_microsecond_before_start_denied(self):
        self.assertFalse(eligible_window(self.start, self.end, self.start - timedelta(microseconds=1)))

    def test_last_microsecond_before_end_accepted(self):
        self.assertTrue(eligible_window(self.start, self.end, self.end - timedelta(microseconds=1)))

    def test_exact_end_denied(self):
        self.assertFalse(eligible_window(self.start, self.end, self.end))

    def test_microsecond_after_end_denied(self):
        self.assertFalse(eligible_window(self.start, self.end, self.end + timedelta(microseconds=1)))

    def test_zero_width_and_reverse_windows_denied(self):
        self.assertFalse(eligible_window(self.start, self.start, self.start))
        self.assertFalse(eligible_window(self.end, self.start, self.start))

    def test_offset_equivalent_instants(self):
        plus_two = timezone(timedelta(hours=2))
        convert = lambda dt: dt.astimezone(plus_two)
        self.assertTrue(eligible_window(convert(self.start), self.end, convert(self.start)))
        self.assertFalse(eligible_window(self.start, convert(self.end), convert(self.end)))

    def test_naive_datetime_denied_at_every_position(self):
        naive = self.start.replace(tzinfo=None)
        for values in ((naive, self.end, self.start),
                       (self.start, naive, self.start),
                       (self.start, self.end, naive)):
            with self.subTest(values=values):
                self.assertFalse(eligible_window(*values))

    def test_non_datetimes_and_bool_denied(self):
        for invalid in (None, "", 0, 1.0, True, {}, []):
            with self.subTest(invalid=invalid):
                self.assertFalse(eligible_window(invalid, self.end, self.start))
                self.assertFalse(eligible_window(self.start, invalid, self.start))
                self.assertFalse(eligible_window(self.start, self.end, invalid))

    def test_negative_offset_equivalence(self):
        minus_five = timezone(timedelta(hours=-5))
        now = (self.end - timedelta(microseconds=1)).astimezone(minus_five)
        self.assertTrue(eligible_window(self.start, self.end, now))


if __name__ == "__main__":
    unittest.main()
