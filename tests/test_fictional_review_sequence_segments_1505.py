"""Offline no-authority segmented handoff continuity contracts for #1505."""
from __future__ import annotations

from datetime import datetime, timedelta
import builtins
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.fictional_review_sequence_1505 import FictionalHandoff
from lightup.fictional_review_sequence_segments_1505 import (
    review_fictional_segment_join,
)


def history(n=6):
    base = datetime(2026, 1, 1, 12)
    return tuple(FictionalHandoff(
        "review-demo.example.test", i, f"{i:064x}",
        (base + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    ) for i in range(1, n + 1))


class TestFictionalSegments(unittest.TestCase):
    def assert_hold(self, sections, expected):
        result = review_fictional_segment_join(sections, expected)
        self.assertEqual((result.status, result.checked_records), ("HOLD", 0))
        self.assertNotIn("example.test", repr(result))
        self.assert_flags_false(result)

    def assert_flags_false(self, result):
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, key), False)

    def test_two_to_four_fragments_out_of_order_can_be_reviewed_only(self):
        for parts in ((history()[:2], history()[2:]),
                      (history()[4:], history()[:4]),
                      (history()[2:4], history()[:2], history()[4:]),
                      (history()[5:], history()[:2], history()[4:5], history()[2:4])):
            result = review_fictional_segment_join(parts, 6)
            self.assertEqual((result.status, result.checked_records), ("REVIEW_ONLY", 6))
            self.assert_flags_false(result)

    def test_boundary_minimum_and_maximum(self):
        rows = history(16)
        for segments, count in (((rows[:1], rows[1:]), 16),
                                ((rows[14:], rows[:3], rows[3:14]), 16),
                                ((rows[:1], rows[1:2]), 2)):
            result = review_fictional_segment_join(segments, count)
            self.assertEqual((result.status, result.checked_records), ("REVIEW_ONLY", count))
            self.assert_flags_false(result)

    def test_gap_or_overlapping_fragment_always_hold(self):
        h = history()
        for pieces in ((h[:2], h[3:]), (h[:3], h[2:]),
                       (h[:1], h[2:4], h[5:]),
                       (h[:2], h[2:5], h[4:])):
            self.assert_hold(pieces, 6)

    def test_internal_fragment_reordered_nonadjacent_or_duplicate_hold(self):
        h = history()
        for first in ((h[1], h[0]), (h[0], h[2]), (h[0], h[0]),
                      (h[0], h[1], h[1])):
            self.assert_hold((first, h[3:]), len(first) + 3)

    def test_invalid_expected_count_type_and_segment_container(self):
        h = history()
        canonical = (h[:3], h[3:])
        for expected in (True, 6.0, "6", None, -1, 1, 17, 5, 7):
            self.assert_hold(canonical, expected)
        for bad in ([], (), (h,), [h[:3], h[3:]], h,
                    (h[:2], list(h[2:])), ((), h), (h, h),
                    (h[:1], h[1:2], h[2:3], h[3:4], h[4:])):
            self.assert_hold(bad, 6)

    def test_cross_segment_digest_replay_and_case_mismatch(self):
        h = history()
        changed = list(h)
        changed[3] = FictionalHandoff(h[3].case_id, 4, h[0].packet_sha256, h[3].observed_at)
        self.assert_hold((h[:3], tuple(changed[3:])), 6)
        changed[3] = FictionalHandoff("review-other.example.test", 4,
                                      h[3].packet_sha256, h[3].observed_at)
        self.assert_hold((h[:3], tuple(changed[3:])), 6)

    def test_cross_segment_backwards_and_invalid_time_hold(self):
        h = history()
        for value in ("2026-01-01T12:00:00Z", "2026-02-30T12:04:00Z",
                      "2026-01-01T12:04:00+00:00"):
            altered = list(h)
            altered[3] = FictionalHandoff(h[3].case_id, 4, h[3].packet_sha256, value)
            self.assert_hold((h[:3], tuple(altered[3:])), 6)

    def test_custom_comparators_never_run(self):
        class PoisonStr(str):
            def __eq__(self, _other):
                raise AssertionError("alien string equality")
        class PoisonInt(int):
            def __lt__(self, _other):
                raise AssertionError("alien sorting")
        h = history()
        altered = list(h)
        altered[1] = FictionalHandoff(h[1].case_id, PoisonInt(2),
                                      h[1].packet_sha256, h[1].observed_at)
        self.assert_hold((tuple(altered[:3]), h[3:]), 6)
        altered[1] = FictionalHandoff(PoisonStr(h[1].case_id), 2,
                                      h[1].packet_sha256, h[1].observed_at)
        self.assert_hold((tuple(altered[:3]), h[3:]), 6)

    def test_observed_mutation_on_third_read_is_hold(self):
        h = history()
        target = h[2]
        original = FictionalHandoff.__getattribute__
        counter = [0]
        def attack(record, attribute):
            if record is target and attribute == "packet_sha256":
                counter[0] += 1
                if counter[0] == 3:
                    object.__setattr__(record, attribute, "f" * 64)
            return original(record, attribute)
        with patch.object(FictionalHandoff, "__getattribute__", attack):
            self.assert_hold((h[:3], h[3:]), 6)
        self.assertEqual(counter[0], 3)

    def test_does_not_write_files_db_network_or_process(self):
        h = history()
        def denied(*_a, **_kw):
            raise AssertionError("I/O in offline review")
        with patch.object(builtins, "open", denied), \
             patch.object(socket.socket, "connect", denied), \
             patch.object(sqlite3, "connect", denied), \
             patch.object(subprocess, "Popen", denied):
            value = review_fictional_segment_join((h[:3], h[3:]), 6)
        self.assertEqual(value.status, "REVIEW_ONLY")
        self.assert_flags_false(value)


if __name__ == "__main__":
    unittest.main()
