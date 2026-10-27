"""Adversarial all-byte segmented transport checks (fictional #1505 only)."""
from __future__ import annotations

import json
from pathlib import Path
import random
import unittest

from lightup.fictional_review_sequence_segments_cli_1505 import parse_fictional_segments

ROOT = Path(__file__).resolve().parents[1] / "docs" / "examples"


def assert_false_flags(test, outcome):
    for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        test.assertIs(getattr(outcome, name), False)


class TestSegmentedTransportAdversarial(unittest.TestCase):
    def test_every_byte_to_nul_is_generic_hold_on_both_committed_fixtures(self):
        for filename in ("fictional-segments-1505-valid.json",
                         "fictional-segments-1505-gap.json"):
            original = (ROOT / filename).read_bytes()
            for i in range(len(original)):
                result = parse_fictional_segments(original[:i] + b"\x00" + original[i+1:])
                self.assertEqual((result.status, result.checked_records), ("HOLD", 0),
                                 (filename, i))
                assert_false_flags(self, result)

    def test_seeded_mutation_matrix_never_grants_authority(self):
        original = (ROOT/"fictional-segments-1505-valid.json").read_bytes()
        rng = random.Random(1505)
        for i in range(1024):
            index = rng.randrange(len(original))
            altered = original[:index] + bytes([original[index] ^ (1 << rng.randrange(8))]) + original[index+1:]
            result = parse_fictional_segments(altered)
            self.assertIn(result.status, ("HOLD", "REVIEW_ONLY"), i)
            assert_false_flags(self, result)

    def test_nonbuiltin_bytes_poison_cannot_invoke_custom_code(self):
        class Poison(bytes):
            def decode(self, *_a, **_k):
                raise AssertionError("byte subclass decoding should never run")
            def isascii(self):
                raise AssertionError("byte subclass ascii should never run")
        original = (ROOT/"fictional-segments-1505-valid.json").read_bytes()
        result = parse_fictional_segments(Poison(original))
        self.assertEqual(result.status, "HOLD")
        assert_false_flags(self, result)

    def test_escaped_unicode_bidi_and_duplicate_nested_schema_hold(self):
        original = (ROOT/"fictional-segments-1505-valid.json").read_bytes()
        for invalid in (
            original.replace(b"review-demo", b"review-\\u0064emo"),
            original.replace(b"review-demo", b"review-\\ud800"),
            original.replace(b"review-demo", b"review-\\u202e"),
            original.replace(b'"sequence":5', b'"sequence":5,"sequence":5', 1),
            original.replace(b'"records":', b'"records":[],"records":', 1),
        ):
            result = parse_fictional_segments(invalid)
            self.assertEqual(result.status, "HOLD")
            assert_false_flags(self, result)

    def test_jointly_fabricated_consistent_fragment_history_is_not_consent(self):
        # An adversary may rewrite both chronology and digests and still have
        # a locally valid SYNTHETIC data structure: acceptance is not trust.
        source = json.loads((ROOT/"fictional-segments-1505-valid.json").read_text())
        for chunk in source["segments"]:
            for record in chunk["records"]:
                record["packet_sha256"] = f"{record['sequence'] + 1024:064x}"
        payload = json.dumps(source, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        result = parse_fictional_segments(payload)
        self.assertEqual(result.status, "REVIEW_ONLY")
        assert_false_flags(self, result)


if __name__ == "__main__":
    unittest.main()
