"""Ordinary passing tests for the opt-in #738 temporal SHAPE diagnostic.

Distinct from the expected-RED production canaries. These tests check a new
non-authorizing function, not actual customer consent or production enforcement.
"""
import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.direct_grant_window_shape_review_738 import (
    WindowShapeReview, review_direct_grant_window_shape
)
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition

NOW = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)


class _ComparatorSpoof(datetime):
    def __le__(self, other):
        return True

    def __ge__(self, other):
        return True


class _ExplodingTimezone(tzinfo):
    def utcoffset(self, value):
        raise AssertionError("untrusted timezone method must not be called")

    def dst(self, value):
        raise AssertionError("untrusted timezone method must not be called")


class _FakeGrant(AuthorizationGrant):
    pass


def _grant():
    return AuthorizationGrant(
        grant_id="fictional-authorization",
        client_id="fictional-client",
        engagement_id="fictional-engagement",
        approved_by="synthetic-operator@example.test",
        reference="NOT-CONSENT",
        scope=ScopeDefinition(
            assets=("fixture.example.test",),
            allowed_capabilities=("web-baseline",),
            max_risk=RiskLevel.LOW_IMPACT,
        ),
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(minutes=5),
    )


def _review(grant=None, now=NOW):
    return review_direct_grant_window_shape(_grant() if grant is None else grant, observed_at=now)


class DirectGrantWindowShapeReviewTests(unittest.TestCase):
    def assert_hold(self, result, reason):
        self.assertIs(type(result), WindowShapeReview)
        self.assertEqual((result.decision, result.reason), ("HOLD", reason))
        self.assertFalse(any(result.as_receipt()[key] for key in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved"
        )))

    def assert_review_only(self, result):
        self.assertEqual((result.decision, result.reason),
                         ("REVIEW_ONLY", "temporal_shape_only"))
        self.assertFalse(any(result.as_receipt()[key] for key in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved"
        )))

    def test_canonical_builtin_utc_window_is_review_only_not_authority(self):
        self.assert_review_only(_review())

    def test_fixed_offset_builtin_timezone_window(self):
        offset = timezone(timedelta(hours=5, minutes=30))
        g = _grant()
        self.assert_review_only(_review(replace(
            g, valid_from=g.valid_from.astimezone(offset),
            valid_until=g.valid_until.astimezone(offset)
        ), now=NOW.astimezone(offset)))

    def test_different_offset_timezones_are_compared_by_instant(self):
        offset = timezone(timedelta(hours=-8))
        g = _grant()
        self.assert_review_only(_review(replace(
            g, valid_until=g.valid_until.astimezone(offset)
        )))

    def test_start_endpoint_is_inclusive(self):
        self.assert_review_only(_review(now=_grant().valid_from))

    def test_end_endpoint_is_inclusive(self):
        self.assert_review_only(_review(now=_grant().valid_until))

    def test_after_end_is_hold(self):
        self.assert_hold(_review(now=_grant().valid_until + timedelta(microseconds=1)),
                         "outside_window")

    def test_before_start_is_hold(self):
        self.assert_hold(_review(now=_grant().valid_from - timedelta(microseconds=1)),
                         "outside_window")

    def test_identical_window_is_hold(self):
        g = _grant()
        self.assert_hold(_review(replace(g, valid_until=g.valid_from)), "invalid_window")

    def test_inverted_window_is_hold(self):
        g = _grant()
        self.assert_hold(_review(replace(g, valid_from=g.valid_until)), "invalid_window")

    def test_exact_grant_identity_is_required(self):
        g = _grant()
        self.assert_hold(_review(_FakeGrant(**vars(g))), "grant_type")
        self.assert_hold(_review({"grant_id": "fictional"}), "grant_type")

    def test_invalid_observed_at_types_hold(self):
        for value in (None, 0, False, "", "2026-10-14T12:00:00Z", [], NOW.replace(tzinfo=None)):
            with self.subTest(repr_value=repr(value)):
                self.assert_hold(_review(now=value), "evaluation_time")

    def test_subclassed_observed_time_holds(self):
        spoof = _ComparatorSpoof(2026, 10, 14, 12, tzinfo=timezone.utc)
        self.assert_hold(_review(now=spoof), "evaluation_time")

    def test_subclassed_future_lower_boundary_holds(self):
        g = _grant()
        spoof = _ComparatorSpoof(2026, 10, 15, 12, tzinfo=timezone.utc)
        self.assert_hold(_review(replace(g, valid_from=spoof)), "valid_from")

    def test_subclassed_expired_upper_boundary_holds(self):
        g = _grant()
        spoof = _ComparatorSpoof(2026, 10, 13, 12, tzinfo=timezone.utc)
        self.assert_hold(_review(replace(g, valid_until=spoof)), "valid_until")

    def test_invalid_not_before_shapes_are_refused(self):
        for value in (None, 0, False, "", (), NOW.replace(tzinfo=None)):
            with self.subTest(value=repr(value)):
                self.assert_hold(_review(replace(_grant(), valid_from=value)), "valid_from")

    def test_invalid_expiry_shapes_are_refused(self):
        for value in (None, 0, False, "", (), NOW.replace(tzinfo=None)):
            with self.subTest(value=repr(value)):
                self.assert_hold(_review(replace(_grant(), valid_until=value)), "valid_until")

    def test_custom_timezones_are_rejected_without_invoking_methods(self):
        bomb = _ExplodingTimezone()
        g = _grant()
        self.assert_hold(_review(replace(
            g, valid_from=datetime(2026, 10, 14, 11, tzinfo=bomb)
        )), "valid_from")
        self.assert_hold(_review(replace(
            g, valid_until=datetime(2026, 10, 14, 13, tzinfo=bomb)
        )), "valid_until")
        self.assert_hold(_review(now=datetime(2026, 10, 14, 12, tzinfo=bomb)),
                         "evaluation_time")

    def test_missing_explicit_observed_at_fails_as_argument_error(self):
        with self.assertRaises(TypeError):
            review_direct_grant_window_shape(_grant())

    def test_source_fields_are_unchanged(self):
        g = _grant()
        before = repr(g)
        self.assert_review_only(_review(g))
        self.assertEqual(repr(g), before)

    def test_receipt_has_only_fixed_non_authorizing_keys(self):
        expected = {
            "decision", "reason", "authorization_verified", "permit_issued",
            "execution_enabled", "merge_approved", "release_approved"
        }
        for receipt in (_review().as_receipt(), _review(now=None).as_receipt()):
            self.assertEqual(set(receipt), expected)
            for key in expected - {"decision", "reason"}:
                self.assertIs(receipt[key], False)
            self.assertNotIn("fixture", repr(receipt))
            self.assertNotIn("fictional", repr(receipt))

    def test_no_network_target_or_database_calls_in_review(self):
        from unittest.mock import patch
        with patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("socket.socket", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("database")):
            self.assert_review_only(_review())


if __name__ == "__main__":
    unittest.main()
