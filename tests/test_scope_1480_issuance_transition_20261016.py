"""Standalone, no-authority check/issue instant transition contracts (#1480)."""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup import activation_issuance_window_review_1480 as reviewer
from lightup.activation_issuance_window_review_1480 import review_issuance_transition
from lightup.models import Authorization

A = datetime(2026, 10, 16, 8, 0, tzinfo=timezone.utc)
B = A + timedelta(minutes=5)
VALID = Authorization(owner="fictional", reference="fictional", valid_from=A, valid_until=B)


class _TimeImposter(datetime):
    pass


class Transition1480Tests(unittest.TestCase):
    def assert_no_authority(self, result):
        for name in ("may_issue_permits", "may_dispatch_tools", "release_authorized"):
            self.assertIs(getattr(result, name), False)

    def test_increasing_inside_window_is_structural_review_only(self):
        review = review_issuance_transition(
            authorization=VALID, checked_at=A, issued_at=B
        )
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assert_no_authority(review)

    def test_same_instant_is_structural_review_only(self):
        review = review_issuance_transition(
            authorization=VALID, checked_at=A, issued_at=A
        )
        self.assertEqual(review.reason, "structural_transition_coherent")
        self.assert_no_authority(review)

    def test_check_outside_validity_does_not_inherit_later_valid_stamp(self):
        review = review_issuance_transition(
            authorization=VALID, checked_at=A - timedelta(microseconds=1), issued_at=A
        )
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.reason, "check_before_approved_window")
        self.assert_no_authority(review)

    def test_expiry_between_check_and_stamp_is_hold(self):
        review = review_issuance_transition(
            authorization=VALID, checked_at=B - timedelta(seconds=1),
            issued_at=B + timedelta(microseconds=1),
        )
        self.assertEqual(review.reason, "issuance_after_approved_window")
        self.assert_no_authority(review)

    def test_backwards_clock_even_within_window_is_hold(self):
        review = review_issuance_transition(
            authorization=VALID, checked_at=B, issued_at=A
        )
        self.assertEqual(review.reason, "issuance_before_check")
        self.assert_no_authority(review)

    def test_expired_check_holds_even_when_stamp_is_past(self):
        review = review_issuance_transition(
            authorization=VALID,
            checked_at=B + timedelta(microseconds=1),
            issued_at=A,
        )
        self.assertEqual(review.reason, "check_after_approved_window")
        self.assert_no_authority(review)

    def test_polymorphic_checked_clock_holds(self):
        review = review_issuance_transition(
            authorization=VALID,
            checked_at=_TimeImposter(2026, 10, 16, 8, tzinfo=timezone.utc),
            issued_at=B,
        )
        self.assertEqual(review.reason, "check_noncanonical_issuance_instant")
        self.assert_no_authority(review)

    def test_polymorphic_issuance_clock_holds(self):
        review = review_issuance_transition(
            authorization=VALID, checked_at=A,
            issued_at=_TimeImposter(2026, 10, 16, 8, tzinfo=timezone.utc),
        )
        self.assertEqual(review.reason, "issuance_noncanonical_issuance_instant")
        self.assert_no_authority(review)

    def test_missing_authorization_is_hold_not_crash(self):
        review = review_issuance_transition(
            authorization=None, checked_at=A, issued_at=A
        )
        self.assertEqual(review.reason, "check_noncanonical_authorization")
        self.assert_no_authority(review)

    def test_live_input_widening_between_two_reviews_cannot_change_original_snapshot(self):
        original = Authorization(
            owner="fictional",
            reference="fictional",
            valid_from=A,
            valid_until=B,
        )
        initial = reviewer.review_issuance_window
        calls = []

        def mutate_after_initial_check(*, authorization, issued_at):
            calls.append(authorization)
            if len(calls) == 1:
                # Explicit synthetic race witness: caller-held dataclass can
                # be forcibly mutated despite frozen=True. It must NOT
                # broaden the internally captured window at stamp review.
                object.__setattr__(
                    original, "valid_until", B + timedelta(hours=1)
                )
            return initial(authorization=authorization, issued_at=issued_at)

        with patch.object(
            reviewer, "review_issuance_window",
            side_effect=mutate_after_initial_check,
        ):
            verdict = review_issuance_transition(
                authorization=original,
                checked_at=B - timedelta(microseconds=1),
                issued_at=B + timedelta(microseconds=1),
            )
        self.assertEqual(len(calls), 2)
        self.assertIsNot(calls[0], original)
        self.assertIs(calls[0], calls[1])
        self.assertEqual(calls[0].valid_until, B)
        self.assertGreater(original.valid_until, B)  # race canary fired
        self.assertEqual(verdict.reason, "issuance_after_approved_window")
        self.assert_no_authority(verdict)

    def test_no_caller_values_mutated(self):
        before = dict(vars(VALID))
        review_issuance_transition(authorization=VALID, checked_at=A, issued_at=B)
        self.assertEqual(vars(VALID), before)


if __name__ == "__main__":
    unittest.main()
