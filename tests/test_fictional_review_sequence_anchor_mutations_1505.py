"""Hostile but wholly fictional canonical anchored transport acceptance #1505."""
from __future__ import annotations

import json
from pathlib import Path
import random
import unittest

from lightup.fictional_review_sequence_anchor_cli_1505 import parse_fictional_anchor
from lightup.fictional_review_sequence_cli_1505 import emit_review


ROOT = Path(__file__).resolve().parents[1] / "docs" / "examples"


def check(test, outcome):
    for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        test.assertIs(getattr(outcome, key), False)
    rendered = emit_review(outcome)
    test.assertNotIn("review-demo", rendered)
    test.assertNotIn("example.test", rendered)


class TestAnchorTransportMutations(unittest.TestCase):
    def test_every_fixture_byte_replaced_with_null_yields_atomic_hold(self):
        for filename in ("fictional-anchor-1505-valid.json", "fictional-anchor-1505-drift.json"):
            original = (ROOT / filename).read_bytes()
            for index in range(len(original)):
                modified = original[:index] + b"\x00" + original[index + 1:]
                result = parse_fictional_anchor(modified)
                self.assertEqual((result.status, result.checked_records), ("HOLD", 0),
                                 (filename, index))
                check(self, result)

    def test_seeded_2048_single_bit_flips_never_become_authority(self):
        original = (ROOT / "fictional-anchor-1505-valid.json").read_bytes()
        rng = random.Random(1505)
        for iteration in range(2048):
            at = rng.randrange(len(original))
            changed = original[:at] + bytes((original[at] ^ (1 << rng.randrange(8)),)) + original[at + 1:]
            result = parse_fictional_anchor(changed)
            self.assertIn(result.status, ("HOLD", "REVIEW_ONLY"), iteration)
            check(self, result)

    def test_bad_utf8_surrogates_bidi_and_record_duplication_fail(self):
        original = (ROOT / "fictional-anchor-1505-valid.json").read_bytes()
        for payload in (
            original.replace(b"review-demo", b"review-\\ud800", 1),
            original.replace(b"review-demo", b"review-\\u202e", 1),
            original.replace(b"review-demo", b"review-\\u0064emo", 1),
            original.replace(b'"sequence":5', b'"sequence":5,"sequence":5', 1),
            original.replace(b'"records":', b'"records":[],"records":', 1),
            original + b" ",
            b" " + original,
            original + b"{}",
        ):
            result = parse_fictional_anchor(payload)
            self.assertEqual((result.status, result.checked_records), ("HOLD", 0))
            check(self, result)

    def test_hostile_bytes_subclass_does_not_trigger_dynamic_callbacks(self):
        class Poison(bytes):
            def decode(self, *_a, **_k):
                raise AssertionError("hostile subclass decoder must not run")
            def isascii(self):
                raise AssertionError("hostile subclass validator must not run")
        payload = (ROOT / "fictional-anchor-1505-valid.json").read_bytes()
        result = parse_fictional_anchor(Poison(payload))
        self.assertEqual((result.status, result.checked_records), ("HOLD", 0))
        check(self, result)

    def test_canonical_jointly_fabricated_history_is_review_only_without_consent(self):
        obj = json.loads((ROOT / "fictional-anchor-1505-valid.json").read_text())
        for group in (*obj["segments"], obj["capture"]):
            for item in group["records"]:
                item["packet_sha256"] = f"{5000 + item['sequence']:064x}"
        payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        result = parse_fictional_anchor(payload)
        self.assertEqual(result.status, "REVIEW_ONLY")
        check(self, result)


if __name__ == "__main__":
    unittest.main()
