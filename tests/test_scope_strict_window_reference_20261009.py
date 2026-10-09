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
    except Exception:
        return False
    if start is None or end is None:
        return False
    for bound in (start, end):
        if type(bound) is not datetime or bound.tzinfo is None:
            return False
        try:
            if bound.utcoffset() is None:
                return False
        except Exception:
            return False
    try:
        normalized_start = start.astimezone(timezone.utc)
        normalized_end = end.astimezone(timezone.utc)
        normalized_now = now.astimezone(timezone.utc)
        return normalized_start < normalized_end and normalized_start <= normalized_now < normalized_end
    except Exception:
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

    def test_folded_local_hour_compares_actual_utc_instants(self):
        from datetime import tzinfo

        class AmbiguousHour(tzinfo):
            def utcoffset(self, dt):
                return timedelta(hours=2 if dt.fold == 0 else 1)

            def dst(self, dt):
                return timedelta(0)

        zone = AmbiguousHour()
        first = datetime(2026, 10, 25, 2, 30, tzinfo=zone, fold=0)
        second = datetime(2026, 10, 25, 2, 30, tzinfo=zone, fold=1)
        self.assertTrue(strict_window_eligible(first, second, first))
        self.assertFalse(strict_window_eligible(first, second, second))
        self.assertFalse(strict_window_eligible(second, first, first))

    def test_utc_conversion_overflow_denies_safely(self):
        # Extreme aware dates can overflow when converted to UTC.
        extreme = datetime.min.replace(tzinfo=timezone(timedelta(hours=14)))
        self.assertFalse(strict_window_eligible(extreme, self.end, self.now))

    def test_equivalent_fold_values_from_distinct_zones(self):
        first = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
        end = first + timedelta(hours=1)
        local_first = first.astimezone(timezone(timedelta(hours=2)))
        local_end = end.astimezone(timezone(timedelta(hours=1)))
        self.assertTrue(strict_window_eligible(local_first, local_end, first))
        self.assertFalse(strict_window_eligible(local_first, local_end, end))

    def test_utc_conversion_overflow_of_current_clock_denies(self):
        # A valid window cannot turn a non-representable instant into approval.
        extreme_now = datetime.max.replace(
            tzinfo=timezone(timedelta(hours=-14)))
        self.assertFalse(strict_window_eligible(self.start, self.end, extreme_now))

    def test_utc_conversion_overflow_of_end_bound_denies(self):
        extreme_end = datetime.max.replace(
            tzinfo=timezone(timedelta(hours=-14)))
        self.assertFalse(strict_window_eligible(self.start, extreme_end, self.now))

    def test_temporal_matrix_respects_exclusive_end_in_utc(self):
        # Fixed matrix, no external clock or network: all tested instants
        # must satisfy start <= now < end, irrespective of wall-clock offset.
        start = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
        end = start + timedelta(hours=2)
        offsets = (timezone.utc, timezone(timedelta(hours=2)),
                   timezone(timedelta(hours=-5)))
        for offset in offsets:
            for minutes in (-1, 0, 1, 60, 119, 120, 121):
                candidate = (start + timedelta(minutes=minutes)).astimezone(offset)
                with self.subTest(offset=offset, minutes=minutes):
                    self.assertEqual(
                        strict_window_eligible(start, end, candidate),
                        0 <= minutes < 120)

    def test_arbitrary_timezone_provider_failure_denies_without_exception(self):
        from datetime import tzinfo

        class CrashingTimezone(tzinfo):
            def utcoffset(self, dt):
                raise RuntimeError("untrusted timezone backend failure")

            def dst(self, dt):
                return None

        broken = self.now.replace(tzinfo=CrashingTimezone())
        self.assertFalse(strict_window_eligible(broken, self.end, self.now))
        self.assertFalse(strict_window_eligible(self.start, broken, self.now))
        self.assertFalse(strict_window_eligible(self.start, self.end, broken))

    def test_comparison_fault_from_timezone_backend_denies(self):
        from datetime import tzinfo

        class FailsDuringConversion(tzinfo):
            def __init__(self):
                self.calls = 0

            def utcoffset(self, dt):
                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("timezone backend changed during UTC conversion")
                return timedelta(0)

            def dst(self, dt):
                return timedelta(0)

        for bad_position in ("start", "end", "now"):
            with self.subTest(bad_position=bad_position):
                faulty = self.now.replace(tzinfo=FailsDuringConversion())
                start, end, now = self.start, self.end, self.now
                if bad_position == "start":
                    start = faulty
                elif bad_position == "end":
                    end = faulty
                else:
                    now = faulty
                self.assertFalse(strict_window_eligible(start, end, now))

    def test_invalid_now_types_deny(self):
        for bad in (None, "", 0, False, True, self.now.isoformat()):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(strict_window_eligible(self.start, self.end, bad))


    def test_offset_encoded_reversed_interval_denies(self):
        # Wall-clock labels can appear increasing while UTC instants reverse.
        start = datetime(2026, 10, 9, 12, tzinfo=timezone(timedelta(hours=-5)))
        end = datetime(2026, 10, 9, 13, tzinfo=timezone(timedelta(hours=2)))
        self.assertFalse(strict_window_eligible(start, end, self.now))

    def test_microsecond_duration_window_respects_both_edges(self):
        start = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        end = start + timedelta(microseconds=1)
        self.assertTrue(strict_window_eligible(start, end, start))
        self.assertFalse(strict_window_eligible(start, end, end))
        self.assertFalse(strict_window_eligible(
            start, end, start - timedelta(microseconds=1)))

if __name__ == "__main__":
    unittest.main()
