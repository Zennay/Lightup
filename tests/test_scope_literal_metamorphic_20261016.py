"""Deterministic independent-oracle test of inert scope-review eligibility.

The reference uses a separate regex and batch model; it proves only the
conservative REVIEW_ONLY/HOLD presentation contract, never permission.
"""
from __future__ import annotations

import random
import re
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.scope_literal_control_review_20261016 import review_literals


BANNED = "%\\@?#"


def reference(candidates: object) -> str:
    if type(candidates) is not tuple or not 1 <= len(candidates) <= 64:
        return "HOLD"
    aliases = set()
    for value in candidates:
        if type(value) is not str or not 1 <= len(value) <= 512:
            return "HOLD"
        if re.fullmatch(r"[\x21-\x7e]+", value) is None:
            return "HOLD"
        if any(char in BANNED for char in value):
            return "HOLD"
        alias = value.casefold().rstrip(".")
        if alias in aliases:
            return "HOLD"
        aliases.add(alias)
    return "REVIEW_ONLY"


class SyntheticMetamorphicReviewTests(unittest.TestCase):
    def test_all_ascii_injections_at_all_positions_in_64_item_batch(self):
        baseline = tuple(f"fictional-{i}.test" for i in range(64))
        self.assertEqual(reference(baseline), "REVIEW_ONLY")
        self.assertEqual(review_literals(baseline).status, "REVIEW_ONLY")
        for index in (0, 31, 63):
            for code in range(128):
                for location in ("start", "middle", "end"):
                    value = baseline[index]
                    pivot = {"start": 0, "middle": len(value) // 2, "end": len(value)}[location]
                    mutated = value[:pivot] + chr(code) + value[pivot:]
                    trial = baseline[:index] + (mutated,) + baseline[index+1:]
                    got = review_literals(trial)
                    self.assertEqual(got.status, reference(trial), (index, code, location))
                    self.assertFalse(got.authorized)
                    self.assertFalse(got.consent_verified)
                    self.assertFalse(got.dispatch_allowed)
                    self.assertFalse(got.release_allowed)
        self.assertEqual(review_literals(baseline).status, "REVIEW_ONLY")

    def test_seeded_independent_batch_oracle_many_inputs(self):
        rng = random.Random(0xD15EA5E)
        pool = [
            f"fictional-{i}.test" for i in range(180)
        ] + [
            "LAB.EXAMPLE.TEST", "lab.example.test.", "local%0ahost",
            "http://fictional.test?mode=scan", "localhost#foo",
            "http://user@lab.test", "local\\nhost", "local\nhost",
            "example\u202etest", "", "z" * 513, "a" * 512,
        ]
        for batch_number in range(1200):
            count = rng.randint(1, 64)
            batch = tuple(rng.choice(pool) for _ in range(count))
            with self.subTest(batch_number=batch_number):
                result = review_literals(batch)
                self.assertEqual(result.status, reference(batch))
                self.assertNotIn("fictional-", repr(result))
                self.assertFalse(any((
                    result.authorized, result.consent_verified,
                    result.dispatch_allowed, result.release_allowed,
                )))

    def test_review_does_not_mutate_input_or_connect_to_network(self):
        packet = ("lab.example.test", "different.example.test")
        before = packet
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            for _ in range(100):
                reviewed = review_literals(packet)
                self.assertEqual(reviewed.status, "REVIEW_ONLY")
                self.assertIs(packet, before)
                self.assertEqual(packet, before)
                self.assertFalse(reviewed.authorized)


if __name__ == "__main__":
    unittest.main()
