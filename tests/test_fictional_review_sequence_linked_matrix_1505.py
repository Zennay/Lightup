"""Exhaustive bounded fictional predecessor-hint and hostile JSON cases (#1505)."""
from __future__ import annotations

import json
from pathlib import Path
import random
import unittest

from lightup.fictional_review_sequence_linked_1505 import (
    FictionalLinkedHandoff, review_fictional_parent_links,
)
from lightup.fictional_review_sequence_linked_cli_1505 import parse_fictional_links

DOCS = Path(__file__).resolve().parents[1] / "docs" / "examples"


def history(n):
    return tuple(FictionalLinkedHandoff(
        "review-demo.example.test", i, f"{i:064x}",
        f"2026-01-01T12:{i:02d}:00Z", f"{i-1:064x}",
    ) for i in range(1, n+1))


def altered(row, **changes):
    props = {key: getattr(row, key) for key in
             ("case_id", "sequence", "packet_sha256",
              "observed_at", "previous_packet_sha256")}
    props.update(changes)
    return FictionalLinkedHandoff(**props)


def no_authority(test, result):
    for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        test.assertIs(getattr(result, name), False)


class TestFictionalLinkExhaustive(unittest.TestCase):
    def test_every_parent_transition_and_genesis_through_sixteen(self):
        for n in range(2, 17):
            rows = history(n)
            accepted = review_fictional_parent_links(rows)
            self.assertEqual(accepted.status, "REVIEW_ONLY")
            no_authority(self, accepted)
            for idx in range(n):
                changed = list(rows)
                changed[idx] = altered(rows[idx], previous_packet_sha256="f"*64)
                reviewed = review_fictional_parent_links(tuple(changed))
                self.assertEqual((reviewed.status, reviewed.checked_records),
                                 ("HOLD", 0), (n, idx))
                no_authority(self, reviewed)

    def test_every_nonterminal_digest_tamper_breaks_the_next_pointer(self):
        for n in range(2, 17):
            rows = history(n)
            for idx in range(n-1):
                altered_rows = list(rows)
                altered_rows[idx] = altered(rows[idx], packet_sha256="f"*64)
                result = review_fictional_parent_links(tuple(altered_rows))
                self.assertEqual(result.status, "HOLD", (n, idx))
                no_authority(self, result)

    def test_terminal_digest_is_not_authenticated_by_a_future_link(self):
        # Important known limitation, not a bug fix: a rewritten last copy
        # hint can remain locally consistent absent a trusted external anchor.
        rows = list(history(3))
        rows[-1] = altered(rows[-1], packet_sha256="f"*64)
        result = review_fictional_parent_links(tuple(rows))
        self.assertEqual(result.status, "REVIEW_ONLY")
        no_authority(self, result)

    def test_every_valid_fixture_byte_replaced_with_nul_is_generic_hold(self):
        for filename in ("fictional-links-1505-valid.json",
                         "fictional-links-1505-broken.json"):
            data = (DOCS / filename).read_bytes()
            for offset in range(len(data)):
                result = parse_fictional_links(data[:offset] + b"\x00" + data[offset+1:])
                self.assertEqual((result.status, result.checked_records), ("HOLD", 0),
                                 (filename, offset))
                no_authority(self, result)

    def test_seeded_2048_bitflip_inputs_never_confers_authority(self):
        data = (DOCS / "fictional-links-1505-valid.json").read_bytes()
        generator = random.Random(1505)
        for _ in range(2048):
            where = generator.randrange(len(data))
            byte = data[where] ^ (1 << generator.randrange(8))
            result = parse_fictional_links(data[:where] + bytes([byte]) + data[where+1:])
            self.assertIn(result.status, ("HOLD", "REVIEW_ONLY"))
            no_authority(self, result)

    def test_coordinated_fictional_all_digest_tamper_never_consent(self):
        obj = json.loads((DOCS / "fictional-links-1505-valid.json").read_text())
        for row in obj["records"]:
            n = row["sequence"]
            row["packet_sha256"] = f"{9000+n:064x}"
            row["previous_packet_sha256"] = "0"*64 if n == 1 else f"{9000+n-1:064x}"
        result = parse_fictional_links(
            json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
        self.assertEqual(result.status, "REVIEW_ONLY")
        no_authority(self, result)

    def test_all_strict_encoded_aliases_fail_closed(self):
        original = (DOCS / "fictional-links-1505-valid.json").read_bytes()
        for invalid in (
            original.replace(b"review-demo", b"review-\\u0064emo", 1),
            original.replace(b"review-demo", b"review-\\u202e", 1),
            original.replace(b"review-demo", b"review-\\ud800", 1),
            original.replace(b'"previous_packet_sha256"', b'"previous_packet_sha256":"junk","previous_packet_sha256"', 1),
            original.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1),
            b" " + original, original + b"\n",
        ):
            outcome = parse_fictional_links(invalid)
            self.assertEqual(outcome.status, "HOLD")
            no_authority(self, outcome)


if __name__ == "__main__":
    unittest.main()
