"""Offline strict temporal validation reference for issue #1128.

This is deliberately NOT a production permission grant or dispatch gate.
No DNS, HTTP, sockets or real targets are used.
"""
from datetime import datetime, timedelta, timezone
import unittest


def strict_window_eligible(start, end, now):
    """Pure, fail-closed *temporal* predicate; consent must be checked elsewhere."""
    if type(now) is not datetime or now.tzinfo is None:
        return False
    try:
        if now.utcoffset() is None:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    if start is None or end is None:
        return False
    for bound in (start, end):
        if type(bound) is not datetime or bound.tzinfo is None:
            return False
        try:
            if bound.utcoffset() is None:
                return False
        except (TypeError, ValueError, OverflowError):
            return False
    try:
        return start < end and start <= now < end
    except (TypeError, ValueError, OverflowError):
        return False


class StrictWindowReferenceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.start = self.now - timedelta(minutes=5)
        self.end = self.now + timedelta(minutes=5)

    def test_valid_interior_is_temporally_eligible_only(self):
        self.assertTrue(strict_window_eligible(self.start, self.end, self.now))

    def test_start_inclusive_end_exclusive(self):
        self.assertTrue(strict_window_eligible(self.start, self.end, self.start))
        self.assertFalse(strict_window_eligible(self.start, self.end, self.end))

    def test_microsecond_before_and_after(self):
        self.assertFalse(strict_window_eligible(self.start, self.end, self.start-timedelta(microseconds=1)))
        self.assertFalse(strict_window_eligible(self.start, self.end, self.end+timedelta(microseconds=1)))

    def test_invalid_bounds_always_deny(self):
        for value in (0, False, "", "2026-10-09", 42, True, [], {}, 0.0):
            with self.subTest(value=repr(value)):
                self.assertFalse(strict_window_eligible(value, self.end, self.now))
                self.assertFalse(strict_window_eligible(self.start, value, self.now))

    def test_absent_bounds_always_deny(self):
        self.assertFalse(strict_window_eligible(None, self.end, self.now))
        self.assertFalse(strict_window_eligible(self.start, None, self.now))
        self.assertFalse(strict_window_eligible(None, None, self.now))

    def test_naive_datetimes_deny(self):
        naive = self.now.replace(tzinfo=None)
        self.assertFalse(strict_window_eligible(naive, self.end, self.now))
        self.assertFalse(strict_window_eligible(self.start, naive, self.now))
        self.assertFalse(strict_window_eligible(self.start, self.end, naive))

    def test_reversed_and_zero_duration_deny(self):
        self.assertFalse(strict_window_eligible(self.end, self.start, self.now))
        self.assertFalse(strict_window_eligible(self.now, self.now, self.now))

    def test_timezone_offset_equivalence(self):
        other = timezone(timedelta(hours=5, minutes=30))
        self.assertTrue(strict_window_eligible(self.start.astimezone(other), self.end, self.now))

    def test_broken_timezone_offset_fails_closed(self):
        from datetime import tzinfo

        class BrokenTimezone(tzinfo):
            def utcoffset(self, dt):
                raise ValueError("invalid timezone metadata")

            def dst(self, dt):
                return None

        broken = self.now.replace(tzinfo=BrokenTimezone())
        self.assertFalse(strict_window_eligible(self.start, self.end, broken))
        self.assertFalse(strict_window_eligible(broken, self.end, self.now))
        self.assertFalse(strict_window_eligible(self.start, broken, self.now))

    def test_subclass_datetimes_cannot_mint_temporal_eligibility(self):
        class ForgedDatetime(datetime):
            pass

        forged = ForgedDatetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.assertFalse(strict_window_eligible(self.start, self.end, forged))
        self.assertFalse(strict_window_eligible(forged, self.end, self.now))

    def test_invalid_now_types_deny(self):
        for bad in (None, "", 0, False, True, self.now.isoformat()):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(strict_window_eligible(self.start, self.end, bad))


if __name__ == "__main__":
    unittest.main()
