"""Synthetic LAB session-lineage preflight tests. Never authorize (#1487)."""
import builtins
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import os
import random
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.lab_session_lineage_1487 import (
    FictionalLabLineageClaim,
    review_fictional_lab_lineage,
)
from lightup.lab_reference_review_1487 import LabReferenceReview

NOW = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)


class StrangeString(str):
    def __hash__(self):
        raise AssertionError("unexpected polymorphic hash")

    def __eq__(self, other):
        raise AssertionError("unexpected polymorphic comparison")


class StrangeTuple(tuple):
    def __iter__(self):
        raise AssertionError("unexpected polymorphic iteration")


class StrangeDate(datetime):
    def __lt__(self, other):
        raise AssertionError("unexpected polymorphic datetime")


class StrangeClaim(FictionalLabLineageClaim):
    pass


def fictional_claim(index=1, **overrides):
    data = {
        "lab_reference": f"LAB-SYNTH-{index:03d}",
        "operator_id": "ACTOR-FICTIONAL-001",
        "session_id": f"SESSION-SYNTH-{index:03d}",
        "engagement_id": "ENG-FICTIONAL-001",
        "asset_id": "ASSET-LOOPBACK-001",
        "capability_id": "CAP-REVIEW-ONLY",
        "starts_at": NOW - timedelta(minutes=20),
        "expires_at": NOW + timedelta(minutes=20),
        "revoked": False,
    }
    data.update(overrides)
    return FictionalLabLineageClaim(**data)


class FictionalLabSessionLineageTests1487(unittest.TestCase):
    def assert_only_review(self, receipt, status):
        self.assertIs(type(receipt), LabReferenceReview)
        self.assertEqual(receipt.status, status)
        for field in ("grants_authority", "can_issue_permit", "can_dispatch", "can_release"):
            self.assertIs(getattr(receipt, field), False)
        self.assertNotIn("ACTOR-", repr(receipt))
        self.assertNotIn("ASSET-", repr(receipt))
        self.assertNotIn("LAB-", repr(receipt))

    def test_valid_fictional_claim_only_review_not_approval(self):
        receipt = review_fictional_lab_lineage((fictional_claim(),), NOW)
        self.assert_only_review(receipt, "REVIEW_ONLY")
        self.assertNotIn(receipt.status, ("APPROVE", "AUTHORIZED", "ALLOW"))

    def test_empty_and_wrong_outer_container_hold(self):
        for claims in (
            (), [fictional_claim()], StrangeTuple((fictional_claim(),)),
            (fictional_claim() for _ in range(1)), "LAB-SYNTH-001", None,
        ):
            self.assert_only_review(review_fictional_lab_lineage(claims, NOW), "HOLD")

    def test_fictional_claim_must_have_exact_class(self):
        base = fictional_claim()
        child = StrangeClaim(**{
            name: getattr(base, name) for name in base.__dataclass_fields__
        })
        for bad in ((child,), (object(),), ({"lab_reference": base.lab_reference},)):
            self.assert_only_review(review_fictional_lab_lineage(bad, NOW), "HOLD")

    def test_identifier_type_or_alias_never_coerces(self):
        for field in ("operator_id", "session_id", "engagement_id", "asset_id", "capability_id"):
            for bad in (
                "bad", " ", "", 12, True, None, StrangeString("ACTOR-FICTIONAL-001"),
                "ACTOR-FICTIONAL-001\u200b", "ACTOR-FICTIONAL-001\n",
                "ACTOR-FICTIONAL-001/", "ACTOR-FICTI\uff2fNAL-001",
                "ACTOR--FICTIONAL",
            ):
                with self.subTest(field=field, bad=repr(bad)):
                    self.assert_only_review(
                        review_fictional_lab_lineage((fictional_claim(**{field: bad}),), NOW),
                        "HOLD",
                    )

    def test_reference_type_and_lexical_canonical_required(self):
        for bad in (
            "LAB", "", "LAB-AAA", "LAB-ABC\u200b", "LAB-ABC/",
            StrangeString("LAB-SYNTH-001"), b"LAB-SYNTH-001",
            None, True, "lab-synth-001",
        ):
            with self.subTest(ref=repr(bad)):
                self.assert_only_review(
                    review_fictional_lab_lineage(
                        (fictional_claim(lab_reference=bad),), NOW
                    ),
                    "HOLD",
                )

    def test_duplicate_reference_or_session_holds_atomically(self):
        first, second = fictional_claim(1), fictional_claim(2)
        self.assert_only_review(
            review_fictional_lab_lineage((first, second), NOW), "REVIEW_ONLY"
        )
        self.assert_only_review(
            review_fictional_lab_lineage(
                (first, replace(second, lab_reference=first.lab_reference)), NOW
            ),
            "HOLD",
        )
        self.assert_only_review(
            review_fictional_lab_lineage(
                (first, replace(second, session_id=first.session_id)), NOW
            ),
            "HOLD",
        )

    def test_revoked_or_nonboolean_rejected(self):
        for revoked in (True, None, 0, 1, "false", "true", (), False.__class__):
            self.assert_only_review(
                review_fictional_lab_lineage(
                    (fictional_claim(revoked=revoked),), NOW
                ), "HOLD"
            )
        self.assert_only_review(
            review_fictional_lab_lineage((fictional_claim(revoked=False),), NOW),
            "REVIEW_ONLY",
        )

    def test_no_subclass_or_naive_temporal_values(self):
        strange = StrangeDate(2030, 1, 1, 12, tzinfo=timezone.utc)
        naive = datetime(2030, 1, 1, 12)
        for bad in (strange, naive, None, "2030-01-01", 0, True):
            for field in ("starts_at", "expires_at"):
                self.assert_only_review(
                    review_fictional_lab_lineage(
                        (fictional_claim(**{field: bad}),), NOW
                    ),
                    "HOLD",
                )
            self.assert_only_review(
                review_fictional_lab_lineage((fictional_claim(),), bad),
                "HOLD",
            )

    def test_utc_fold_one_does_not_gain_authority(self):
        for field in ("starts_at", "expires_at"):
            bad = replace(fictional_claim(), **{
                field: getattr(fictional_claim(), field).replace(fold=1)
            })
            self.assert_only_review(review_fictional_lab_lineage((bad,), NOW), "HOLD")
        self.assert_only_review(
            review_fictional_lab_lineage((fictional_claim(),), NOW.replace(fold=1)),
            "HOLD",
        )

    def test_upper_and_lower_time_bounds_inclusive(self):
        for instant in (NOW - timedelta(minutes=20), NOW, NOW + timedelta(minutes=20)):
            self.assert_only_review(
                review_fictional_lab_lineage((fictional_claim(),), instant),
                "REVIEW_ONLY",
            )
        for instant in (
            NOW - timedelta(minutes=20, microseconds=1),
            NOW + timedelta(minutes=20, microseconds=1),
        ):
            self.assert_only_review(
                review_fictional_lab_lineage((fictional_claim(),), instant), "HOLD"
            )

    def test_nonpositive_and_excessive_windows_rejected(self):
        for offset in (timedelta(0), timedelta(microseconds=-1), timedelta(hours=9)):
            self.assert_only_review(
                review_fictional_lab_lineage(
                    (fictional_claim(starts_at=NOW, expires_at=NOW + offset),),
                    NOW,
                ),
                "HOLD",
            )
        self.assert_only_review(
            review_fictional_lab_lineage(
                (fictional_claim(starts_at=NOW, expires_at=NOW + timedelta(hours=8)),),
                NOW,
            ),
            "REVIEW_ONLY",
        )

    def test_max_batch_size_enforced_before_iterating(self):
        group = tuple(fictional_claim(i) for i in range(1, 65))
        self.assert_only_review(review_fictional_lab_lineage(group, NOW), "REVIEW_ONLY")
        self.assert_only_review(
            review_fictional_lab_lineage(group + (fictional_claim(65),), NOW),
            "HOLD",
        )

    def test_atomic_hold_in_every_position_of_mixed_batch(self):
        valid = [fictional_claim(1), fictional_claim(2), fictional_claim(3)]
        bad = fictional_claim(4, revoked=True)
        for idx in range(4):
            batch = valid.copy()
            batch.insert(idx, bad)
            self.assert_only_review(review_fictional_lab_lineage(tuple(batch), NOW), "HOLD")

    def test_deterministic_permutation_and_repeatability(self):
        base = tuple(fictional_claim(i) for i in range(1, 21))
        randomizer = random.Random(1487)
        for _ in range(200):
            shuffled = list(base)
            randomizer.shuffle(shuffled)
            self.assert_only_review(
                review_fictional_lab_lineage(tuple(shuffled), NOW), "REVIEW_ONLY"
            )
            shuffled[-1] = replace(shuffled[-1], revoked=True)
            self.assert_only_review(
                review_fictional_lab_lineage(tuple(shuffled), NOW), "HOLD"
            )
        self.assertEqual(base[0].lab_reference, "LAB-SYNTH-001")

    def test_response_cannot_be_mutated_or_used_as_token(self):
        receipt = review_fictional_lab_lineage((fictional_claim(),), NOW)
        self.assert_only_review(receipt, "REVIEW_ONLY")
        with self.assertRaises(FrozenInstanceError):
            receipt.can_dispatch = True
        with self.assertRaises(FrozenInstanceError):
            receipt.status = "APPROVED"

    def test_claim_cannot_be_mutated_through_normal_setattr(self):
        record = fictional_claim()
        with self.assertRaises(FrozenInstanceError):
            record.operator_id = "ACTOR-OTHER"
        with self.assertRaises(FrozenInstanceError):
            record.revoked = True

    def test_no_file_socket_dns_database_shell_or_subprocess(self):
        record = fictional_claim()
        with patch.object(builtins, "open", side_effect=AssertionError("file")), (
            patch.object(os, "open", side_effect=AssertionError("file descriptor"))
        ), (
            patch.object(socket, "socket", side_effect=AssertionError("socket"))
        ), (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS"))
        ), (
            patch.object(sqlite3, "connect", side_effect=AssertionError("database"))
        ), (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process"))
        ), (
            patch.object(os, "system", side_effect=AssertionError("shell"))
        ):
            self.assert_only_review(
                review_fictional_lab_lineage((record,), NOW), "REVIEW_ONLY"
            )
            self.assert_only_review(
                review_fictional_lab_lineage(
                    (replace(record, revoked=True),), NOW
                ),
                "HOLD",
            )

    def test_caller_supplied_clock_is_not_trusted_current_authority(self):
        old = datetime(2020, 1, 1, 12, tzinfo=timezone.utc)
        outdated = fictional_claim(
            starts_at=old - timedelta(minutes=2),
            expires_at=old + timedelta(minutes=2),
        )
        # Shape-only reviewer sees the *caller-supplied* instant as valid.
        self.assert_only_review(
            review_fictional_lab_lineage((outdated,), old), "REVIEW_ONLY"
        )
        # This proves the result cannot be a live authorization decision.
        self.assert_only_review(
            review_fictional_lab_lineage((outdated,), NOW), "HOLD"
        )


if __name__ == "__main__":
    unittest.main()
