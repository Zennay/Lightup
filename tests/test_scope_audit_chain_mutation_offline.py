"""Deterministic offline mutation matrix for #1556; no target/network I/O.

This is a negative-proof corpus, not evidence of trusted real-world authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import unittest

from lightup.scope_audit_chain_offline import (
    MAX_EVENTS, SCHEMA as CHAIN_SCHEMA, ZERO_HASH, compute_event_hash,
    verify_chain,
)
from lightup.scope_audit_chain_transition_offline import (
    SCHEMA as TRANSITION_SCHEMA, verify_transition,
)


def make_chain(count: int, *, scope: str = "a" * 64) -> tuple[dict, str]:
    assert count >= 1
    previous = ZERO_HASH
    rows = []
    for index in range(count):
        body = {
            "seq": index,
            "kind": "REVIEW_OPENED" if index == 0 else "REVIEW_NOTE",
            "at": (
                datetime(2026, 10, 17, 12) + timedelta(seconds=index * 10)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope_sha256": scope,
            "previous_sha256": previous,
        }
        previous = compute_event_hash(body)
        rows.append({**body, "sha256": previous})
    return {"schema": CHAIN_SCHEMA, "events": rows}, previous


def pack(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def rewrite_hashes(chain: dict) -> str:
    previous = ZERO_HASH
    for row in chain["events"]:
        row["previous_sha256"] = previous
        body = {key: value for key, value in row.items() if key != "sha256"}
        previous = compute_event_hash(body)
        row["sha256"] = previous
    return previous


def envelope(old: dict, new: dict) -> bytes:
    return pack({"schema": TRANSITION_SCHEMA, "before": old, "after": new})


class ScopeAuditMutationMatrixTests(unittest.TestCase):
    def test_full_capacity_64_events_review_only(self):
        chain, tip = make_chain(MAX_EVENTS)
        self.assertEqual("REVIEW_ONLY", verify_chain(pack(chain), tip)["status"])

    def test_exact_64_event_append_transition(self):
        before, old_tip = make_chain(MAX_EVENTS - 1)
        after, new_tip = make_chain(MAX_EVENTS)
        result = verify_transition(envelope(before, after), old_tip, new_tip)
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertEqual(1, result["new_records"])

    def test_65_events_fail_closed(self):
        candidate, tip = make_chain(MAX_EVENTS + 1)
        self.assertEqual("HOLD", verify_chain(pack(candidate), tip)["status"])
        before, old_tip = make_chain(MAX_EVENTS)
        self.assertEqual(
            "HOLD",
            verify_transition(envelope(before, candidate), old_tip, tip)["status"],
        )

    def test_every_position_hash_corruption_64_subcases(self):
        base, tip = make_chain(64)
        for index in range(64):
            with self.subTest(record=index):
                corrupt = json.loads(pack(base))
                corrupt["events"][index]["sha256"] = "f" * 64
                self.assertEqual("HOLD", verify_chain(pack(corrupt), tip)["status"])

    def test_every_position_prev_hash_corruption_64_subcases(self):
        base, tip = make_chain(64)
        for index in range(64):
            with self.subTest(record=index):
                corrupt = json.loads(pack(base))
                corrupt["events"][index]["previous_sha256"] = "f" * 64
                self.assertEqual("HOLD", verify_chain(pack(corrupt), tip)["status"])

    def test_every_position_seq_type_confusion_64_subcases(self):
        base, tip = make_chain(64)
        for index in range(64):
            for forged in (True, str(index), float(index)):
                with self.subTest(record=index, forged=repr(forged)):
                    corrupt = json.loads(pack(base))
                    corrupt["events"][index]["seq"] = forged
                    self.assertEqual("HOLD", verify_chain(pack(corrupt), tip)["status"])

    def test_every_position_forged_authorization_field_64_subcases(self):
        base, tip = make_chain(64)
        for index in range(64):
            with self.subTest(record=index):
                corrupt = json.loads(pack(base))
                corrupt["events"][index]["authorization_granted"] = True
                receipt = verify_chain(pack(corrupt), tip)
                self.assertEqual("HOLD", receipt["status"])
                self.assertIs(receipt["authorization_granted"], False)

    def test_every_position_unknown_kind_64_subcases(self):
        base, tip = make_chain(64)
        for index in range(64):
            with self.subTest(record=index):
                corrupt = json.loads(pack(base))
                corrupt["events"][index]["kind"] = "REAL_CLIENT_CONSENT"
                receipt = verify_chain(pack(corrupt), tip)
                self.assertEqual("HOLD", receipt["status"])
                self.assertIs(receipt["consent_verified"], False)

    def test_reanchored_rewritten_history_denied_at_each_position(self):
        before, old_tip = make_chain(20)
        for index in range(20):
            with self.subTest(rewritten_record=index):
                altered, _ = make_chain(21)
                old_at = datetime.strptime(
                    altered["events"][index]["at"], "%Y-%m-%dT%H:%M:%SZ"
                )
                altered["events"][index]["at"] = (
                    old_at + timedelta(seconds=1)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                candidate_tip = rewrite_hashes(altered)
                self.assertEqual(
                    "REVIEW_ONLY", verify_chain(pack(altered), candidate_tip)["status"]
                )
                self.assertEqual(
                    "HOLD",
                    verify_transition(
                        envelope(before, altered), old_tip, candidate_tip
                    )["status"],
                )

    def test_candidate_chain_not_writable_from_truncated_anchor(self):
        original, old_tip = make_chain(16)
        after, new_tip = make_chain(17)
        for trim in range(1, 16):
            with self.subTest(records_removed=trim):
                truncated, forged_old_tip = make_chain(16 - trim)
                self.assertEqual(
                    "HOLD",
                    verify_transition(
                        envelope(truncated, after), old_tip, new_tip
                    )["status"],
                )
                # Even a valid alternative old anchor is NOT the pinned old anchor.
                self.assertNotEqual(old_tip, forged_old_tip)
                self.assertEqual("REVIEW_ONLY", verify_chain(pack(original), old_tip)["status"])

    def test_duplicate_sha_field_inside_chain_holds(self):
        chain, tip = make_chain(1)
        raw = pack(chain)
        raw = raw.replace(b'"sha256":', b'"sha256":"' + b"0" * 64 + b'","sha256":', 1)
        self.assertEqual("HOLD", verify_chain(raw, tip)["status"])

    def test_deep_json_and_malformed_unicode_holds_without_crash(self):
        chain, tip = make_chain(1)
        for raw in (
            b"[" * 1050 + b"0" + b"]" * 1050,
            pack(chain) + b"\xed\xa0\x80",
            b'{"schema":"LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1","events":',
        ):
            with self.subTest(kind=raw[:15]):
                self.assertEqual("HOLD", verify_chain(raw, tip)["status"])

    def test_transition_deep_json_and_bad_utf8_holds(self):
        old, old_tip = make_chain(1)
        new, new_tip = make_chain(2)
        for raw in (
            b"[" * 1050 + b"0" + b"]" * 1050,
            envelope(old, new) + b"\xff",
        ):
            with self.subTest(kind=raw[:15]):
                receipt = verify_transition(raw, old_tip, new_tip)
                self.assertEqual("HOLD", receipt["status"])
                self.assertFalse(receipt["consent_verified"])
                self.assertFalse(receipt["authorization_granted"])
                self.assertFalse(receipt["release_approved"])


if __name__ == "__main__":
    unittest.main()
