"""W3 purely offline replay-window and receipt-integrity checks (#1487)."""
import builtins
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
    review_lab_reference_history,
)


class StrWithMethods(str):
    def __hash__(self):
        raise AssertionError("hostile hash should never run")

    def __eq__(self, other):
        raise AssertionError("hostile equality should never run")


class TupleWithMethods(tuple):
    def __iter__(self):
        raise AssertionError("hostile iterator should never run")


class LabReferenceHistory1487(unittest.TestCase):
    def assert_no_authority(self, receipt, status):
        self.assertIs(type(receipt), LabReferenceReview)
        self.assertEqual(receipt.status, status)
        for key in ("grants_authority", "can_issue_permit", "can_dispatch", "can_release"):
            self.assertIs(getattr(receipt, key), False)
        self.assertNotIn("LAB-SESSION", repr(receipt))
        self.assertNotIn("approval", repr(receipt).lower())

    def test_empty_history_requires_explicit_proposed_reference(self):
        self.assert_no_authority(
            review_lab_reference_history((), ("LAB-SESSION-0001",)), "REVIEW_ONLY"
        )
        self.assert_no_authority(review_lab_reference_history((), ()), "HOLD")
        self.assert_no_authority(review_lab_reference_history((), ("LAB",)), "HOLD")

    def test_distinct_sessions_are_review_only_never_authorized(self):
        result = review_lab_reference_history(
            ("LAB-SESSION-0001",), ("LAB-SESSION-0002", "LAB-SESSION-0003")
        )
        self.assert_no_authority(result, "REVIEW_ONLY")
        self.assertNotIn(result.status, ("ALLOW", "APPROVED", "GO"))

    def test_replay_in_history_is_atomic_hold(self):
        history = ("LAB-SESSION-0001", "LAB-SESSION-0002")
        for proposal in (
            ("LAB-SESSION-0001",),
            ("LAB-SESSION-0003", "LAB-SESSION-0001"),
            ("LAB-SESSION-0003", "LAB-SESSION-0002", "LAB-SESSION-0004"),
        ):
            self.assert_no_authority(
                review_lab_reference_history(history, proposal), "HOLD"
            )

    def test_duplicated_prior_history_or_proposal_holds(self):
        for prior, proposed in (
            (("LAB-SESSION-0001", "LAB-SESSION-0001"), ("LAB-SESSION-0002",)),
            (("LAB-SESSION-0001",), ("LAB-SESSION-0002", "LAB-SESSION-0002")),
            (("LAB-SESSION-0001",), ("LAB", "LAB-SESSION-0002")),
        ):
            self.assert_no_authority(
                review_lab_reference_history(prior, proposed), "HOLD"
            )

    def test_both_lists_are_bounded_independently(self):
        prior64 = tuple(f"LAB-PRIOR-{i:04d}" for i in range(64))
        proposed64 = tuple(f"LAB-NEXT-{i:04d}" for i in range(64))
        self.assert_no_authority(
            review_lab_reference_history(prior64, proposed64), "REVIEW_ONLY"
        )
        prior65 = prior64 + ("LAB-PRIOR-0064",)
        proposed65 = proposed64 + ("LAB-NEXT-0064",)
        self.assert_no_authority(
            review_lab_reference_history(prior65, proposed64), "HOLD"
        )
        self.assert_no_authority(
            review_lab_reference_history(prior64, proposed65), "HOLD"
        )

    def test_polymorphic_or_non_tuple_input_not_consumed(self):
        for malicious in (
            ["LAB-SESSION-0001"],
            TupleWithMethods(("LAB-SESSION-0001",)),
            "LAB-SESSION-0001",
            iter(("LAB-SESSION-0001",)),
        ):
            self.assert_no_authority(
                review_lab_reference_history(malicious, ("LAB-SESSION-0002",)),
                "HOLD",
            )
            self.assert_no_authority(
                review_lab_reference_history((), malicious), "HOLD"
            )

    def test_no_custom_string_methods_invoked(self):
        malicious = StrWithMethods("LAB-SESSION-0001")
        for prior, proposed in (
            ((malicious,), ("LAB-SESSION-0002",)),
            (("LAB-SESSION-0002",), (malicious,)),
            ((malicious,), (malicious,)),
        ):
            self.assert_no_authority(
                review_lab_reference_history(prior, proposed), "HOLD"
            )

    def test_unicode_alias_and_case_changes_do_not_become_review_only(self):
        for bad in (
            "lab-session-0002",
            "LAB-SESSION-0002\u200b",
            "LAB-SESSION-000\uff12",
            "LAB-SESSION-0002 ",
            "LAB-SESSION-0002/",
            "LAB--SESSION-0002",
            "LAB-SESSION-0002:443",
        ):
            self.assert_no_authority(
                review_lab_reference_history(
                    ("LAB-SESSION-0001",), (bad,)
                ),
                "HOLD",
            )

    def test_historical_replay_order_invariance_and_no_state_change(self):
        previous = tuple(f"LAB-OLD-{i:03d}" for i in range(18))
        upcoming = tuple(f"LAB-NEW-{i:03d}" for i in range(18))
        rng = random.Random(1487)
        for _ in range(256):
            p = list(previous)
            q = list(upcoming)
            rng.shuffle(p)
            rng.shuffle(q)
            self.assert_no_authority(
                review_lab_reference_history(tuple(p), tuple(q)), "REVIEW_ONLY"
            )
            q[-1] = previous[0]
            self.assert_no_authority(
                review_lab_reference_history(tuple(p), tuple(q)), "HOLD"
            )
        self.assertEqual(previous[0], "LAB-OLD-000")
        self.assertEqual(upcoming[0], "LAB-NEW-000")

    def test_permuted_replay_at_every_position_is_hold(self):
        previous = ("LAB-OLD-001", "LAB-OLD-002", "LAB-OLD-003")
        for hit in previous:
            for insertion in range(4):
                proposed = ["LAB-NEW-001", "LAB-NEW-002", "LAB-NEW-003"]
                proposed.insert(insertion, hit)
                self.assert_no_authority(
                    review_lab_reference_history(previous, tuple(proposed)), "HOLD"
                )

    def test_manually_forged_statuses_and_authority_flags_rejected(self):
        for status in ("ALLOW", "APPROVED", "GO", "review_only", "", None, 1):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    LabReferenceReview(status)
        for field in (
            "grants_authority",
            "can_issue_permit",
            "can_dispatch",
            "can_release",
        ):
            for value in (True, 0, 1, "false", None):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        LabReferenceReview("REVIEW_ONLY", **{field: value})

    def test_receipts_cannot_be_mutated_or_authorize(self):
        for receipt in (
            LabReferenceReview("HOLD"),
            LabReferenceReview("REVIEW_ONLY"),
            review_lab_reference_history((), ("LAB-SESSION-0001",)),
        ):
            self.assert_no_authority(receipt, receipt.status)
            with self.assertRaises(FrozenInstanceError):
                receipt.status = "APPROVED"
            with self.assertRaises(FrozenInstanceError):
                receipt.can_dispatch = True

    def test_batch_and_history_have_independent_reference_validation(self):
        fixture = ("LAB-SESSION-0001",)
        self.assert_no_authority(review_lab_reference_batch(fixture), "REVIEW_ONLY")
        self.assert_no_authority(
            review_lab_reference_history(fixture, fixture), "HOLD"
        )
        self.assert_no_authority(
            review_lab_reference_history((), fixture), "REVIEW_ONLY"
        )

    def test_no_io_or_external_authorization_calls(self):
        prior = ("LAB-SESSION-0001",)
        proposed = ("LAB-SESSION-0002",)
        with patch.object(builtins, "open", side_effect=AssertionError("file")), (
            patch.object(os, "open", side_effect=AssertionError("file descriptor"))
        ), (
            patch.object(socket, "socket", side_effect=AssertionError("network"))
        ), (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS"))
        ), (
            patch.object(sqlite3, "connect", side_effect=AssertionError("DB"))
        ), (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process"))
        ), (
            patch.object(os, "system", side_effect=AssertionError("shell"))
        ):
            self.assert_no_authority(
                review_lab_reference_history(prior, proposed), "REVIEW_ONLY"
            )
            self.assert_no_authority(
                review_lab_reference_history(prior, prior), "HOLD"
            )


if __name__ == "__main__":
    unittest.main()
