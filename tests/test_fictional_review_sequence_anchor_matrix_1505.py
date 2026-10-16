"""Independent deterministic anchor CLI partition and mismatch acceptance #1505."""
from __future__ import annotations

from itertools import combinations, permutations
import json
import random
import unittest

from lightup.fictional_review_sequence_anchor_cli_1505 import parse_fictional_anchor


def row(i):
    return {"case_id": "review-demo.example.test", "sequence": i,
            "packet_sha256": f"{i:064x}",
            "observed_at": f"2026-02-01T10:{i:02d}:00Z"}


def envelope(parts, complete):
    return json.dumps({
        "schema": "fictional_handoff_anchor_v1",
        "expected_records": len(complete),
        "segments": [{"records": [row(i) for i in piece]} for piece in parts],
        "capture": {"records": [row(i) for i in complete]},
    }, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class TestAnchorCLIPartitions(unittest.TestCase):
    def review(self, pieces, expected, outcome):
        result = parse_fictional_anchor(envelope(pieces, expected))
        self.assertEqual(result.status, outcome)
        self.assertEqual(result.checked_records, len(expected) if outcome == "REVIEW_ONLY" else 0)
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, field), False)

    def test_all_two_way_cut_permutations_across_16(self):
        for n in range(2, 17):
            records = tuple(range(1, n+1))
            for cut in range(1, n):
                left, right = records[:cut], records[cut:]
                self.review((left, right), records, "REVIEW_ONLY")
                self.review((right, left), records, "REVIEW_ONLY")

    def test_all_three_way_cuts_and_permutations_up_to_10(self):
        for n in range(3, 11):
            records = tuple(range(1, n+1))
            for a, b in combinations(range(1, n), 2):
                pieces = (records[:a], records[a:b], records[b:])
                for order in permutations(pieces):
                    self.review(order, records, "REVIEW_ONLY")

    def test_four_way_seeded_permutations_and_boundaries_to_16(self):
        rng = random.Random(1505)
        for n in range(4, 17):
            records = tuple(range(1, n+1))
            cuts = list(combinations(range(1, n), 3))
            rng.shuffle(cuts)
            for a, b, c in cuts[:10]:
                parts = (records[:a], records[a:b], records[b:c], records[c:])
                for order in permutations(parts):
                    self.review(order, records, "REVIEW_ONLY")

    def test_every_two_way_boundary_rejects_deleted_duplicate_or_displaced(self):
        for n in range(3, 17):
            records = tuple(range(1, n+1))
            for cut in range(1, n):
                l, r = records[:cut], records[cut:]
                self.review((l, r[:-1]), records, "HOLD")
                self.review((l, (l[-1],) + r), records, "HOLD")
                self.review((l, tuple(reversed(r))), records,
                            "REVIEW_ONLY" if len(r) <= 1 else "HOLD")
                self.review((l, r), records[::-1], "HOLD")

    def test_caller_fabricated_matching_16_step_history_never_consent(self):
        records = tuple(range(1, 17))
        payload = json.loads(envelope((records[:6], records[6:]), records))
        for group in (*payload["segments"], payload["capture"]):
            for item in group["records"]:
                item["packet_sha256"] = f"{item['sequence']+3500:064x}"
        parsed = parse_fictional_anchor(
            json.dumps(payload, separators=(",", ":")).encode("ascii")
        )
        self.assertEqual(parsed.status, "REVIEW_ONLY")
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(parsed, flag), False)


if __name__ == "__main__":
    unittest.main()
