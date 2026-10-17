"""Fail-closed lexical JSON numeric tests on all three fictional audit modes."""

from __future__ import annotations

import json
import unittest

from lightup.scope_audit_chain_offline import (
    SCHEMA as CHAIN_SCHEMA, ZERO_HASH, compute_event_hash, verify_chain,
)
from lightup.scope_audit_chain_transition_offline import (
    SCHEMA as TRANSITION_SCHEMA, verify_transition,
)
from lightup.scope_audit_chain_checkpoints_offline import (
    SCHEMA as CHECKPOINT_SCHEMA, verify_checkpoints,
)


def fixture():
    base = {
        "seq": 0, "kind": "REVIEW_OPENED",
        "at": "2026-10-17T12:00:00Z", "scope_sha256": "a" * 64,
        "previous_sha256": ZERO_HASH,
    }
    first_hash = compute_event_hash(base)
    extra = {
        "seq": 1, "kind": "REVIEW_NOTE",
        "at": "2026-10-17T12:00:01Z", "scope_sha256": "a" * 64,
        "previous_sha256": first_hash,
    }
    second_hash = compute_event_hash(extra)
    first = {"schema": CHAIN_SCHEMA, "events": [{**base, "sha256": first_hash}]}
    second = {
        "schema": CHAIN_SCHEMA,
        "events": [{**base, "sha256": first_hash}, {**extra, "sha256": second_hash}],
    }
    return first, second, first_hash, second_hash


def dump(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class LexicalIntAliasTests(unittest.TestCase):
    def test_original_canonical_numeric_zero_positive_control(self):
        first, second, old_tip, new_tip = fixture()
        self.assertEqual("REVIEW_ONLY", verify_chain(dump(first), old_tip)["status"])
        pair = {"schema": TRANSITION_SCHEMA, "before": first, "after": second}
        self.assertEqual(
            "REVIEW_ONLY", verify_transition(dump(pair), old_tip, new_tip)["status"]
        )
        packet = {"schema": CHECKPOINT_SCHEMA, "snapshots": [first, second]}
        self.assertEqual(
            "REVIEW_ONLY", verify_checkpoints(dump(packet), (old_tip, new_tip))["status"]
        )

    def test_negative_zero_alias_rejected_in_original_chain(self):
        first, _, old_tip, _ = fixture()
        raw = dump(first).replace(b'"seq":0', b'"seq":-0', 1)
        self.assertNotEqual(dump(first), raw)
        self.assertEqual("HOLD", verify_chain(raw, old_tip)["status"])

    def test_negative_zero_alias_rejected_in_pair(self):
        first, second, old_tip, new_tip = fixture()
        packet = {"schema": TRANSITION_SCHEMA, "before": first, "after": second}
        raw = dump(packet).replace(b'"seq":0', b'"seq":-0', 1)
        self.assertNotEqual(dump(packet), raw)
        self.assertEqual(
            "HOLD", verify_transition(raw, old_tip, new_tip)["status"]
        )

    def test_negative_zero_alias_rejected_in_multi_checkpoint(self):
        first, second, old_tip, new_tip = fixture()
        packet = {"schema": CHECKPOINT_SCHEMA, "snapshots": [first, second]}
        raw = dump(packet).replace(b'"seq":0', b'"seq":-0', 1)
        self.assertNotEqual(dump(packet), raw)
        self.assertEqual(
            "HOLD", verify_checkpoints(raw, (old_tip, new_tip))["status"]
        )

    def test_float_and_exponent_aliases_are_not_exact_integers(self):
        first, second, old_tip, new_tip = fixture()
        pair = {"schema": TRANSITION_SCHEMA, "before": first, "after": second}
        checkpoints = {"schema": CHECKPOINT_SCHEMA, "snapshots": [first, second]}
        for token in (b"-0.0", b"-0e0", b"0.0", b"0e0", b"true", b"null"):
            with self.subTest(token=token):
                self.assertEqual(
                    "HOLD",
                    verify_chain(
                        dump(first).replace(b'"seq":0', b'"seq":' + token, 1),
                        old_tip,
                    )["status"],
                )
                self.assertEqual(
                    "HOLD",
                    verify_transition(
                        dump(pair).replace(b'"seq":0', b'"seq":' + token, 1),
                        old_tip, new_tip,
                    )["status"],
                )
                self.assertEqual(
                    "HOLD",
                    verify_checkpoints(
                        dump(checkpoints).replace(b'"seq":0', b'"seq":' + token, 1),
                        (old_tip, new_tip),
                    )["status"],
                )

    def test_out_of_grammar_numeric_alias_is_denied(self):
        first, _, tip, _ = fixture()
        for token in (b"-00", b"00", b"+0", b"0x0", b"01", b"Infinity", b"NaN"):
            with self.subTest(token=token):
                raw = dump(first).replace(b'"seq":0', b'"seq":' + token, 1)
                self.assertEqual("HOLD", verify_chain(raw, tip)["status"])


if __name__ == "__main__":
    unittest.main()
