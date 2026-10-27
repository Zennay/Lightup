"""Deterministic bounded hostile-input mutation matrix for isolated #1505 CLIs."""
from __future__ import annotations

from pathlib import Path
import random
import unittest

from lightup.fictional_review_sequence_cli_1505 import emit_review, parse_fictional_stdin
from lightup.fictional_review_sequence_pair_cli_1505 import parse_fictional_pair

EXAMPLES = Path(__file__).resolve().parents[1] / "docs" / "examples"


class TestFictionalReviewMutations(unittest.TestCase):
    def assert_non_authorizing(self, outcome):
        self.assertIn(outcome.status, ("HOLD", "REVIEW_ONLY"))
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(outcome, field), False)
        rendered = emit_review(outcome)
        self.assertNotIn("review-demo", rendered)
        self.assertNotIn("example.test", rendered)
        self.assertNotIn("token", rendered)

    def test_every_single_control_byte_corruption_is_atomic_hold(self):
        for filename, parser in (
            ("fictional-sequence-1505-valid.json", parse_fictional_stdin),
            ("fictional-pair-1505-matching.json", parse_fictional_pair),
        ):
            original = (EXAMPLES / filename).read_bytes()
            self.assertEqual(parser(original).status, "REVIEW_ONLY")
            for i in range(len(original)):
                corrupted = original[:i] + b"\x00" + original[i+1:]
                value = parser(corrupted)
                self.assertEqual((value.status, value.checked_records), ("HOLD", 0),
                                 (filename, i))
                self.assert_non_authorizing(value)

    def test_deterministic_bitflip_and_ascii_mutation_never_enable_authority(self):
        rng = random.Random(1505)
        for filename, parser in (
            ("fictional-sequence-1505-valid.json", parse_fictional_stdin),
            ("fictional-pair-1505-matching.json", parse_fictional_pair),
        ):
            original = (EXAMPLES / filename).read_bytes()
            for i in range(1024):
                index = rng.randrange(len(original))
                value = original[index] ^ (1 << rng.randrange(7))
                changed = original[:index] + bytes((value,)) + original[index+1:]
                outcome = parser(changed)
                self.assert_non_authorizing(outcome)

    def test_bytes_subclass_callbacks_never_run(self):
        class PoisonBytes(bytes):
            def isascii(self):
                raise AssertionError("poison subclass ascii callback")
            def decode(self, *_a, **_k):
                raise AssertionError("poison subclass decoder")
        for filename, parser in (
            ("fictional-sequence-1505-valid.json", parse_fictional_stdin),
            ("fictional-pair-1505-matching.json", parse_fictional_pair),
        ):
            original = (EXAMPLES / filename).read_bytes()
            result = parser(PoisonBytes(original))
            self.assertEqual((result.status, result.checked_records), ("HOLD", 0))
            self.assert_non_authorizing(result)

    def test_unicode_surrogate_escape_and_bidi_ambiguity_hold(self):
        for filename, parser in (
            ("fictional-sequence-1505-valid.json", parse_fictional_stdin),
            ("fictional-pair-1505-matching.json", parse_fictional_pair),
        ):
            original = (EXAMPLES / filename).read_bytes()
            for bad in (b"review-\\ud800", b"review-\\u202e", b"review-\\u0064emo"):
                changed = original.replace(b"review-demo", bad)
                value = parser(changed)
                self.assertEqual(value.status, "HOLD")
                self.assert_non_authorizing(value)

    def test_multiple_wrong_byte_lengths_are_generic_hold(self):
        for parser in (parse_fictional_stdin, parse_fictional_pair):
            for n in (0, 1, 8193, 10000, 20000):
                payload = b"x" * n
                value = parser(payload)
                self.assertEqual((value.status, value.checked_records), ("HOLD", 0))
                self.assert_non_authorizing(value)


if __name__ == "__main__":
    unittest.main()
