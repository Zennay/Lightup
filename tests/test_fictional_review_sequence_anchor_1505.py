"""Two-representation wholly fictional nonauthorizing comparison contracts."""
from __future__ import annotations

from datetime import datetime, timedelta
import builtins
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.fictional_review_sequence_1505 import FictionalHandoff
from lightup.fictional_review_sequence_anchor_1505 import (
    review_fictional_segments_against_capture,
)


def history(n=6):
    start = datetime(2026, 1, 1, 12)
    return tuple(FictionalHandoff(
        "review-demo.example.test", i, f"{i:064x}",
        (start+timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    ) for i in range(1, n+1))


def independent(rows):
    return tuple(FictionalHandoff(item.case_id, item.sequence,
                                  item.packet_sha256, item.observed_at)
                 for item in rows)


class TestSegmentAgainstIndependentCapture(unittest.TestCase):
    def check(self, pieces, n, baseline, expected):
        answer = review_fictional_segments_against_capture(pieces, n, baseline)
        self.assertEqual((answer.status, answer.checked_records),
                         (expected, n if expected == "REVIEW_ONLY" else 0))
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(answer, field), False)
        self.assertNotIn("example.test", repr(answer))

    def test_copied_fake_baseline_matches_reordered_fragments(self):
        for count in (2, 3, 6, 16):
            original = history(count)
            cut = count//2
            pieces = (original[cut:], original[:cut])
            self.check(pieces, count, independent(original), "REVIEW_ONLY")

    def test_baseline_must_not_share_same_python_record_objects(self):
        original = history()
        self.check((original[:3], original[3:]), 6, original, "HOLD")
        baseline = list(independent(original))
        baseline[4] = original[4]
        self.check((original[:3], original[3:]), 6, tuple(baseline), "HOLD")

    def test_changed_digest_even_when_each_side_still_valid_is_hold(self):
        original = history()
        baseline = list(independent(original))
        baseline[4] = FictionalHandoff(original[4].case_id, 5, "f"*64,
                                       original[4].observed_at)
        self.check((original[:3], original[3:]), 6, tuple(baseline), "HOLD")

    def test_changed_increasing_time_and_case_even_when_valid_is_hold(self):
        original = history()
        for alternate in (
            FictionalHandoff(original[2].case_id, 3, original[2].packet_sha256,
                             "2026-01-01T12:03:30Z"),
            FictionalHandoff("review-other.example.test", 3,
                             original[2].packet_sha256, original[2].observed_at),
        ):
            baseline = list(independent(original))
            baseline[2] = alternate
            self.check((original[:3], original[3:]), 6, tuple(baseline), "HOLD")

    def test_invalid_baseline_gap_and_repeat_rejected(self):
        original = history()
        for baseline in (independent(original)[:-1], independent(original)[1:],
                         tuple(reversed(independent(original))),
                         independent(original)[:-1] + independent(original)[:1]):
            self.check((original[:3], original[3:]), 6, baseline, "HOLD")

    def test_boolean_and_wrong_expected_type_no_untrusted_comparison(self):
        original = history()
        for expected in (True, 6.0, "6", None, 0, 17):
            self.check((original[:3], original[3:]), expected,
                       independent(original), "HOLD")

    def test_fake_jointly_modified_baseline_and_segments_never_authorizes(self):
        original = history()
        forged = tuple(FictionalHandoff(r.case_id, r.sequence,
                                       f"{r.sequence+1024:064x}", r.observed_at)
                       for r in original)
        self.check((forged[:3], forged[3:]), 6, independent(forged), "REVIEW_ONLY")

    def test_observed_baseline_mutation_is_hold(self):
        original = history()
        baseline = independent(original)
        target = baseline[2]
        access = FictionalHandoff.__getattribute__
        counter = [0]

        def mutate(record, field):
            if record is target and field == "packet_sha256":
                counter[0] += 1
                if counter[0] == 3:
                    object.__setattr__(record, field, "f"*64)
            return access(record, field)

        with patch.object(FictionalHandoff, "__getattribute__", mutate):
            self.check((original[:3], original[3:]), 6, baseline, "HOLD")
        self.assertGreaterEqual(counter[0], 3)

    def test_valid_comparison_no_file_db_network_or_process_io(self):
        original = history()
        def denied(*_args, **_kwargs):
            raise AssertionError("no I/O in pure fiction-only review")
        with patch.object(builtins, "open", denied), \
             patch.object(socket.socket, "connect", denied), \
             patch.object(sqlite3, "connect", denied), \
             patch.object(subprocess, "Popen", denied):
            self.check((original[:3], original[3:]), 6,
                       independent(original), "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
