"""Positive and adversarial two-capture fictional chronology tests (#1505)."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import builtins
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.fictional_review_sequence_1505 import FictionalHandoff
from lightup.fictional_review_sequence_compare_1505 import review_matching_fictional_captures


def fake_history(count=3, case="review-demo.example.test"):
    return tuple(
        FictionalHandoff(case, n, f"{n:064x}", f"2026-02-01T10:{n:02d}:00Z")
        for n in range(1, count + 1)
    )


class TestMatchingFictionalCaptures(unittest.TestCase):
    def assert_hold(self, a, b):
        result = review_matching_fictional_captures(a, b)
        self.assertEqual((result.status, result.checked_records), ("HOLD", 0))
        self.assertNotIn("example.test", repr(result))
        for f in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, f), False)

    def test_identical_fictional_captures_only_review_not_permission(self):
        for n in (2, 3, 16):
            left = fake_history(n)
            right = tuple(FictionalHandoff(x.case_id, x.sequence,
                                          x.packet_sha256, x.observed_at) for x in left)
            result = review_matching_fictional_captures(left, right)
            self.assertEqual((result.status, result.checked_records), ("REVIEW_ONLY", n))
            for f in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
                self.assertIs(getattr(result, f), False)

    def test_changed_digest_in_valid_second_history_is_hold(self):
        a = fake_history()
        b = list(fake_history())
        b[1] = FictionalHandoff(b[1].case_id, 2, "f"*64, b[1].observed_at)
        self.assert_hold(a, tuple(b))

    def test_changed_timestamp_even_if_both_valid_is_hold(self):
        a = fake_history()
        b = list(fake_history())
        b[1] = FictionalHandoff(b[1].case_id, 2, b[1].packet_sha256,
                                "2026-02-01T10:02:10Z")
        self.assert_hold(a, tuple(b))

    def test_two_entirely_valid_different_fictional_cases_are_hold(self):
        self.assert_hold(fake_history(), fake_history(case="review-other.example.test"))

    def test_truncated_extended_duplicate_reordered_and_mismatched_counts(self):
        a = fake_history(3)
        for b in (fake_history(2), fake_history(4), a[:1], a + a[:1],
                  tuple(reversed(a)), (a[0], a[0], a[2])):
            self.assert_hold(a, b)

    def test_invalid_or_ambiguous_container_and_entry_types(self):
        a = fake_history()
        class AlienTuple(tuple):
            def __eq__(self, _other):
                raise AssertionError("unsafe container equality")
        class Alien(FictionalHandoff):
            def __eq__(self, _other):
                raise AssertionError("unsafe record equality")
        for left, right in ((AlienTuple(a), a), (a, AlienTuple(a)),
                            (None, a), (a, list(a)), (a, b"bad"), ((), a),
                            (a, (Alien(*tuple(getattr(a[0], f) for f in
                            ("case_id", "sequence", "packet_sha256", "observed_at"))), *a[1:]))):
            self.assert_hold(left, right)

    def test_invalid_matching_histories_cannot_become_review_only(self):
        valid = fake_history()
        for replacement in (
            FictionalHandoff("review-demo.example.test", 2, valid[0].packet_sha256,
                             valid[1].observed_at),
            FictionalHandoff("review-demo.example.test", 2, valid[1].packet_sha256,
                             valid[0].observed_at),
            FictionalHandoff("review-é.example.test", 2, valid[1].packet_sha256,
                             valid[1].observed_at),
            FictionalHandoff("review-demo.example.test", True, valid[1].packet_sha256,
                             valid[1].observed_at),
        ):
            bad = (valid[0], replacement, valid[2])
            self.assert_hold(bad, bad)

    def test_observed_between_copy_mutation_is_hold(self):
        original = fake_history()
        target = original[1]
        old_get = FictionalHandoff.__getattribute__
        counter = [0]
        def mutate_one_read(rec, name):
            if rec is target and name == "packet_sha256":
                counter[0] += 1
                if counter[0] == 2:
                    object.__setattr__(rec, name, "f"*64)
            return old_get(rec, name)
        with patch.object(FictionalHandoff, "__getattribute__", mutate_one_read):
            self.assert_hold(original, original)
        self.assertGreaterEqual(counter[0], 2)

    def test_reconciler_does_not_use_files_db_network_or_process(self):
        def denied(*_a, **_k):
            raise AssertionError("forbidden I/O")
        left = fake_history()
        with patch.object(builtins, "open", denied), \
             patch.object(socket.socket, "connect", denied), \
             patch.object(sqlite3, "connect", denied), \
             patch.object(subprocess, "Popen", denied):
            self.assertEqual(review_matching_fictional_captures(left, tuple(left)).status,
                             "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
