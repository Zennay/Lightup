"""Additional isolated edge regressions for the offline half-open-window model.

These tests never invoke a runtime executor, target, network or scan.
"""
from datetime import datetime, timedelta, timezone
import unittest

from test_scope_half_open_time_boundary_reference_20261008 import eligible_window


class ApprovalWindowEdgeTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)
        self.end = self.start + timedelta(days=1)

    def test_cross_midnight_full_day(self):
        self.assertTrue(eligible_window(self.start, self.end, self.start))
        self.assertTrue(eligible_window(self.start, self.end, self.end - timedelta(microseconds=1)))
        self.assertFalse(eligible_window(self.start, self.end, self.end))

    def test_dst_fold_instants_compared_in_utc(self):
        # Autumn DST overlap: the same local wall-clock hour contains two distinct instants.
        zone = timezone(timedelta(hours=1))
        before = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
        after = before + timedelta(hours=1)
        self.assertTrue(eligible_window(before, after, before.astimezone(zone)))
        self.assertFalse(eligible_window(before, after, after.astimezone(zone)))

    def test_one_microsecond_validity_window(self):
        end = self.start + timedelta(microseconds=1)
        self.assertTrue(eligible_window(self.start, end, self.start))
        self.assertFalse(eligible_window(self.start, end, end))

    def test_datetime_subclasses_not_trusted(self):
        class ClaimedDatetime(datetime):
            pass
        fake = ClaimedDatetime(2026, 10, 8, tzinfo=timezone.utc)
        for args in ((fake, self.end, self.start), (self.start, fake, self.start),
                     (self.start, self.end, fake)):
            with self.subTest(args=args):
                self.assertFalse(eligible_window(*args))

    def test_non_hour_timezone_offsets(self):
        offset = timezone(timedelta(hours=5, minutes=45))
        middle = (self.start + timedelta(hours=12)).astimezone(offset)
        self.assertTrue(eligible_window(self.start, self.end, middle))

    def test_near_datetime_max(self):
        top = datetime.max.replace(tzinfo=timezone.utc)
        prior = top - timedelta(microseconds=1)
        self.assertTrue(eligible_window(prior, top, prior))
        self.assertFalse(eligible_window(prior, top, top))


if __name__ == "__main__":
    unittest.main()
