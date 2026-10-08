"""Offline trusted-clock boundary reference model; not production executor proof."""
import datetime as dt
import unittest

UTC = dt.timezone.utc


def clock_allows(read_clock, valid_from, valid_until, previous=None):
    """Reference semantics only; callers must separately enforce scope and tenant."""
    try:
        current = read_clock()
    except Exception:
        return False
    if type(current) is not dt.datetime or current.tzinfo is None:
        return False
    try:
        offset = current.utcoffset()
        if offset != dt.timedelta(0):
            return False
        if any(type(value) is not dt.datetime or value.tzinfo is None
               or value.utcoffset() != dt.timedelta(0)
               for value in (valid_from, valid_until)):
            return False
        if previous is not None:
            if type(previous) is not dt.datetime or previous.tzinfo is None:
                return False
            if previous.utcoffset() != dt.timedelta(0) or current < previous:
                return False
        return valid_from <= current < valid_until
    except (ValueError, TypeError, OverflowError):
        return False


class TrustedClockReferenceContract(unittest.TestCase):
    def setUp(self):
        self.start = dt.datetime(2026, 10, 8, 1, tzinfo=UTC)
        self.end = self.start + dt.timedelta(hours=1)

    def test_inside_window(self):
        self.assertTrue(clock_allows(lambda: self.start, self.start, self.end))

    def test_exclusive_expiry(self):
        self.assertFalse(clock_allows(lambda: self.end, self.start, self.end))

    def test_before_activation(self):
        self.assertFalse(clock_allows(
            lambda: self.start - dt.timedelta(microseconds=1), self.start, self.end))

    def test_source_unavailable(self):
        self.assertFalse(clock_allows(lambda: None, self.start, self.end))

    def test_source_throws(self):
        def failed():
            raise RuntimeError("clock unavailable")
        self.assertFalse(clock_allows(failed, self.start, self.end))

    def test_naive_clock(self):
        self.assertFalse(clock_allows(lambda: dt.datetime(2026, 10, 8), self.start, self.end))

    def test_string_and_numeric_clock(self):
        for value in ("2026-10-08T01:00:00Z", float("nan"), 0):
            with self.subTest(value=value):
                self.assertFalse(clock_allows(lambda: value, self.start, self.end))

    def test_backward_clock_step(self):
        self.assertFalse(clock_allows(
            lambda: self.start, self.start, self.end,
            previous=self.start + dt.timedelta(seconds=1)))

    def test_forward_monotonic_clock(self):
        self.assertTrue(clock_allows(
            lambda: self.start + dt.timedelta(seconds=1),
            self.start, self.end, previous=self.start))

    def test_snapshot_expiry_not_extended(self):
        live_end = self.end + dt.timedelta(days=1)
        self.assertTrue(live_end > self.end)
        self.assertFalse(clock_allows(lambda: self.end, self.start, self.end))

    def test_second_step_clock_lost(self):
        sequence = iter([self.start, None])
        read = lambda: next(sequence)
        self.assertTrue(clock_allows(read, self.start, self.end))
        self.assertFalse(clock_allows(read, self.start, self.end,
                                      previous=self.start))


if __name__ == "__main__":
    unittest.main()
