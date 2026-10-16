"""Bounded exhaustive synthetic segmentation / gap/overlap property regressions."""
from __future__ import annotations

from datetime import datetime, timedelta
from itertools import combinations, permutations
import random
import unittest

from lightup.fictional_review_sequence_1505 import FictionalHandoff
from lightup.fictional_review_sequence_segments_1505 import review_fictional_segment_join


def sample(count):
    base = datetime(2026, 1, 1, 12)
    return tuple(
        FictionalHandoff(
            "review-demo.example.test", step, f"{step:064x}",
            (base + timedelta(seconds=step)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ) for step in range(1, count + 1)
    )


def status(fragments, count):
    review = review_fictional_segment_join(fragments, count)
    assert review.authorized is False
    assert review.consent_verified is False
    assert review.dispatch_allowed is False
    assert review.release_allowed is False
    return review.status


class TestSegmentPartitionMatrix(unittest.TestCase):
    def test_all_two_fragment_boundaries_both_delivery_orders(self):
        for n in range(2, 17):
            rows = sample(n)
            for cut in range(1, n):
                a, b = rows[:cut], rows[cut:]
                self.assertEqual(status((a, b), n), "REVIEW_ONLY", (n, cut))
                self.assertEqual(status((b, a), n), "REVIEW_ONLY", (n, cut))

    def test_all_three_fragment_cuts_and_permutations_to_ten_records(self):
        for n in range(3, 11):
            rows = sample(n)
            for x, y in combinations(range(1, n), 2):
                segments = (rows[:x], rows[x:y], rows[y:])
                for order in permutations(segments):
                    self.assertEqual(status(order, n), "REVIEW_ONLY", (n, x, y))

    def test_seeded_four_fragment_cuts_and_permutations_to_sixteen(self):
        rng = random.Random(1505)
        for n in range(4, 17):
            rows = sample(n)
            all_cuts = list(combinations(range(1, n), 3))
            rng.shuffle(all_cuts)
            for x, y, z in all_cuts[:24]:
                fragments = (rows[:x], rows[x:y], rows[y:z], rows[z:])
                for order in permutations(fragments):
                    self.assertEqual(status(order, n), "REVIEW_ONLY",
                                     (n, x, y, z))

    def test_all_two_segment_boundaries_reject_one_dropped_row(self):
        for n in range(3, 17):
            rows = sample(n)
            for cut in range(1, n):
                left, right = rows[:cut], rows[cut:]
                if len(left) >= 2:
                    dropped = (left[:-1], right)
                    self.assertEqual(status(dropped, n), "HOLD", (n, cut, "left"))
                if len(right) >= 2:
                    dropped = (left, right[1:])
                    self.assertEqual(status(dropped, n), "HOLD", (n, cut, "right"))

    def test_all_two_segment_boundaries_reject_one_replayed_row(self):
        for n in range(2, 16):
            rows = sample(n)
            for cut in range(1, n):
                left, right = rows[:cut], rows[cut:]
                self.assertEqual(status((left, (left[-1],) + right), n + 1),
                                 "HOLD", (n, cut, "overlap"))
                self.assertEqual(status((left + (right[0],), right), n + 1),
                                 "HOLD", (n, cut, "duplicate"))

    def test_all_cross_boundary_digest_replay_and_backward_clock(self):
        for n in range(3, 17):
            rows = sample(n)
            for cut in range(1, n):
                left, right = rows[:cut], list(rows[cut:])
                right[0] = FictionalHandoff(right[0].case_id,
                                            right[0].sequence,
                                            left[-1].packet_sha256,
                                            right[0].observed_at)
                self.assertEqual(status((left, tuple(right)), n), "HOLD")
                right[0] = FictionalHandoff(right[0].case_id,
                                            right[0].sequence,
                                            rows[cut].packet_sha256,
                                            left[-1].observed_at)
                self.assertEqual(status((left, tuple(right)), n), "HOLD")


if __name__ == "__main__":
    unittest.main()
