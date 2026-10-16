"""Offline non-authorizing bounded LAB reference reviewer tests (#1487)."""
import os
import random
import socket
import sqlite3
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.lab_reference_review_1487 import (
    LabReferenceReview,
    review_lab_reference_batch,
)


class StrangeString(str):
    def __hash__(self):
        raise AssertionError("no polymorphic hash allowed")

    def __eq__(self, other):
        raise AssertionError("no polymorphic comparison allowed")


class StrangeContainer(tuple):
    def __iter__(self):
        raise AssertionError("no polymorphic iteration allowed")


class LabReferenceReviewer1487(unittest.TestCase):
    def assert_denied_receipt(self, value, expected):
        self.assertIs(type(value), LabReferenceReview)
        self.assertEqual(value.status, expected)
        self.assertIs(value.grants_authority, False)
        self.assertIs(value.can_issue_permit, False)
        self.assertIs(value.can_dispatch, False)
        self.assertIs(value.can_release, False)
        self.assertEqual(repr(value).count("LAB-SESSION"), 0)

    def test_canonical_batch_is_only_review_only(self):
        self.assert_denied_receipt(
            review_lab_reference_batch(("LAB-SESSION-001", "LAB-SESSION-002")),
            "REVIEW_ONLY",
        )

    def test_canonical_minimum_and_maximum_lengths(self):
        for reference in ("LAB-ABCD", "LAB-" + "Z" * 124):
            with self.subTest(length=len(reference)):
                self.assert_denied_receipt(
                    review_lab_reference_batch((reference,)), "REVIEW_ONLY"
                )

    def test_review_only_cannot_mean_release_even_when_valid(self):
        receipt = review_lab_reference_batch(("LAB-TEST-0001",))
        self.assertNotEqual(receipt.status, "ALLOW")
        self.assertNotEqual(receipt.status, "APPROVED")
        self.assert_denied_receipt(receipt, "REVIEW_ONLY")

    def test_missing_and_generic_source_fallback_are_hold(self):
        for refs in ((), ("LAB",), (None,), ("",), (" ",), ("lab",)):
            with self.subTest(refs=refs):
                self.assert_denied_receipt(review_lab_reference_batch(refs), "HOLD")

    def test_batch_must_be_exact_tuple_and_never_consumes_custom_iterable(self):
        for refs in (
            ["LAB-SESSION-001"],
            {"LAB-SESSION-001"},
            "LAB-SESSION-001",
            StrangeContainer(("LAB-SESSION-001",)),
            iter(("LAB-SESSION-001",)),
        ):
            self.assert_denied_receipt(review_lab_reference_batch(refs), "HOLD")

    def test_no_truthiness_or_hash_methods_on_untrusted_entries(self):
        for refs in (
            (StrangeString("LAB-SESSION-001"),),
            (object(),),
            (True,),
            (7,),
            (b"LAB-SESSION-001",),
        ):
            self.assert_denied_receipt(review_lab_reference_batch(refs), "HOLD")

    def test_no_permissive_normalization_for_deceptive_inputs(self):
        samples = (
            "LAB-SESSION-001 ",
            " LAB-SESSION-001",
            "LAB-SESSION-001\n",
            "LAB-SESSION-001\x00",
            "LAB-SESSION-001/OTHER",
            "LAB-SESSION-001?permit=true",
            "LAB-SESSION-001.example.test",
            "LAB_SESS_001",
            "LAB--SESSION-001",
            "LAB-SESSION-001-",
            "LAB-SESSION-001\u200b",
            "LAB-SESSI\u041eN-001",
            "LAB-SESSION-00\uff11",
            "lab-session-001",
            "Lab-Session-001",
            "LAB-\u00c5",
        )
        for reference in samples:
            with self.subTest(reference=repr(reference)):
                self.assert_denied_receipt(
                    review_lab_reference_batch((reference,)), "HOLD"
                )

    def test_reject_duplicate_session_references_atomically(self):
        for refs in (
            ("LAB-SESSION-001", "LAB-SESSION-001"),
            ("LAB-SESSION-001", "LAB-SESSION-002", "LAB-SESSION-001"),
            ("LAB-SESSION-001", "LAB"),
            ("LAB", "LAB-SESSION-001"),
        ):
            self.assert_denied_receipt(review_lab_reference_batch(refs), "HOLD")

    def test_hard_item_count_limit(self):
        valid_64 = tuple(f"LAB-SESSION-{i:03d}" for i in range(64))
        valid_65 = tuple(f"LAB-SESSION-{i:03d}" for i in range(65))
        self.assert_denied_receipt(review_lab_reference_batch(valid_64), "REVIEW_ONLY")
        self.assert_denied_receipt(review_lab_reference_batch(valid_65), "HOLD")

    def test_overlong_and_short_entry_fail_atomically(self):
        for bad in ("LAB-ABC", "LAB-" + "Z" * 125):
            self.assert_denied_receipt(
                review_lab_reference_batch(("LAB-SESSION-001", bad)), "HOLD"
            )

    def test_order_invariance_without_global_state(self):
        fixture = tuple(f"LAB-SESSION-{i:03d}" for i in range(10))
        rng = random.Random(1487)
        for _ in range(128):
            shuffled = list(fixture)
            rng.shuffle(shuffled)
            self.assert_denied_receipt(
                review_lab_reference_batch(tuple(shuffled)), "REVIEW_ONLY"
            )
        self.assertEqual(fixture[0], "LAB-SESSION-000")

    def test_invalid_item_permutations_all_hold_without_partial_accept(self):
        valid = ["LAB-SESSION-001", "LAB-SESSION-002", "LAB-SESSION-003"]
        for bad in ("LAB", "LAB-SESSION-001", None, StrangeString("LAB-SESSION-004")):
            for index in range(len(valid) + 1):
                samples = valid.copy()
                samples.insert(index, bad)
                self.assert_denied_receipt(
                    review_lab_reference_batch(tuple(samples)), "HOLD"
                )

    def test_review_receipt_is_immutable(self):
        receipt = review_lab_reference_batch(("LAB-SESSION-001",))
        with self.assertRaises(FrozenInstanceError):
            receipt.can_dispatch = True
        with self.assertRaises(FrozenInstanceError):
            receipt.status = "ALLOW"

    def test_review_is_pure_no_file_network_db_or_process(self):
        refs = ("LAB-SESSION-001", "LAB-SESSION-002")
        with patch("builtins.open", side_effect=AssertionError("file I/O")), (
            patch.object(os, "open", side_effect=AssertionError("fd I/O"))
        ), (
            patch.object(socket, "socket", side_effect=AssertionError("network"))
        ), (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS"))
        ), (
            patch.object(sqlite3, "connect", side_effect=AssertionError("database"))
        ), (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process"))
        ):
            self.assert_denied_receipt(
                review_lab_reference_batch(refs), "REVIEW_ONLY"
            )
            self.assert_denied_receipt(
                review_lab_reference_batch(("LAB",)), "HOLD"
            )


if __name__ == "__main__":
    unittest.main()
