"""#1480 pure bounded issuance metadata oracle (never a grant decision)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation_issuance_window_review_1480 import review_issuance_window
from lightup.models import Authorization

START = datetime(2026, 10, 16, 7, 0, tzinfo=timezone.utc)
END = datetime(2026, 10, 16, 8, 0, tzinfo=timezone.utc)


def _auth(**changes):
    data = {
        "owner": "synthetic-owner",
        "reference": "synthetic-reference",
        "valid_from": START,
        "valid_until": END,
    }
    data.update(changes)
    return Authorization(**data)


class _WeirdDate(datetime):
    pass


class _WeirdAuthorization(Authorization):
    pass


class IssuanceWindowReview1480Tests(unittest.TestCase):
    def _check_no_authority(self, review):
        self.assertIs(review.may_issue_permits, False)
        self.assertIs(review.may_dispatch_tools, False)
        self.assertIs(review.release_authorized, False)

    def test_inside_window_remains_review_only(self):
        result = review_issuance_window(authorization=_auth(), issued_at=END - timedelta(seconds=1))
        self.assertEqual(result.status, "REVIEW_ONLY")
        self._check_no_authority(result)

    def test_both_inclusive_boundaries_are_only_review(self):
        for value in (START, END):
            with self.subTest(value=value):
                result = review_issuance_window(authorization=_auth(), issued_at=value)
                self.assertEqual(result.status, "REVIEW_ONLY")
                self._check_no_authority(result)

    def test_expired_issuance_is_hold(self):
        result = review_issuance_window(authorization=_auth(), issued_at=END + timedelta(microseconds=1))
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason, "after_approved_window")
        self._check_no_authority(result)

    def test_not_yet_valid_issuance_is_hold(self):
        result = review_issuance_window(authorization=_auth(), issued_at=START - timedelta(microseconds=1))
        self.assertEqual(result.reason, "before_approved_window")
        self._check_no_authority(result)

    def test_missing_or_naive_bounds_hold(self):
        for overrides in (
            {"valid_from": None},
            {"valid_until": None},
            {"valid_from": START.replace(tzinfo=None)},
            {"valid_until": END.replace(tzinfo=None)},
        ):
            with self.subTest(overrides=overrides):
                result = review_issuance_window(authorization=_auth(**overrides), issued_at=END)
                self.assertEqual(result.reason, "noncanonical_finite_utc_window")
                self._check_no_authority(result)

    def test_inverted_window_is_rejected(self):
        result = review_issuance_window(
            authorization=_auth(valid_from=END, valid_until=START), issued_at=END
        )
        self.assertEqual(result.reason, "inverted_window")
        self._check_no_authority(result)

    def test_polymorphic_time_never_inherits_authority(self):
        for variant in (
            (_auth(valid_from=_WeirdDate(2026, 10, 16, 7, tzinfo=timezone.utc)), END),
            (_auth(valid_until=_WeirdDate(2026, 10, 16, 8, tzinfo=timezone.utc)), END),
            (_auth(), _WeirdDate(2026, 10, 16, 8, tzinfo=timezone.utc)),
        ):
            with self.subTest(variant=variant):
                result = review_issuance_window(authorization=variant[0], issued_at=variant[1])
                self.assertEqual(result.status, "HOLD")
                self._check_no_authority(result)

    def test_authorization_subclass_refused(self):
        spoofed = _WeirdAuthorization(**vars(_auth()))
        result = review_issuance_window(authorization=spoofed, issued_at=END)
        self.assertEqual(result.reason, "noncanonical_authorization")
        self._check_no_authority(result)

    def test_result_is_slotless_and_even_object_setattr_cannot_forge_release(self):
        result = review_issuance_window(authorization=_auth(), issued_at=END)
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(AttributeError):
            result.release_authorized = True
        with self.assertRaises(AttributeError):
            object.__setattr__(result, "release_authorized", True)
        self._check_no_authority(result)

    def test_review_requires_no_network(self):
        with patch("socket.socket", side_effect=AssertionError("unexpected socket")):
            result = review_issuance_window(authorization=_auth(), issued_at=END)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self._check_no_authority(result)


if __name__ == "__main__":
    unittest.main()
