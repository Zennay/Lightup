"""Offline security regression for opt-in legacy temporal review (#301).

Independent of installed Authorization.is_current, which remains a known RED.
All identities are synthetic and no target I/O is performed.
"""
import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization
from lightup.legacy_temporal_shape_review_301 import (
    LegacyTemporalReview, review_legacy_authorization_window
)

START = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)
END = START + timedelta(hours=1)
MID = START + timedelta(minutes=30)


def fixture(*, start=START, end=END):
    return Authorization(
        owner="FICTIONAL_DO_NOT_AUTHORIZE",
        reference="FAKE_APPROVAL_NOT_CONSENT",
        valid_from=start,
        valid_until=end,
    )


def review(auth=None, now=MID):
    return review_legacy_authorization_window(
        fixture() if auth is None else auth, observed_at=now
    )


def assert_non_authorizing(testcase, result, status, reason):
    testcase.assertIs(type(result), LegacyTemporalReview)
    testcase.assertEqual((result.status, result.reason), (status, reason))
    receipt = result.as_receipt()
    testcase.assertEqual((receipt["status"], receipt["reason"]), (status, reason))
    testcase.assertEqual(set(receipt), {
        "status", "reason", "authorization_verified", "permit_issued",
        "execution_enabled", "target_dispatch_allowed", "merge_approved",
        "release_approved"
    })
    for key in set(receipt) - {"status", "reason"}:
        testcase.assertIs(receipt[key], False)
    testcase.assertNotIn("FICTIONAL_DO_NOT_AUTHORIZE", str(receipt))
    testcase.assertNotIn("FAKE_APPROVAL_NOT_CONSENT", str(receipt))


class _DatetimeSpoof(datetime):
    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return False

    def __le__(self, other):
        return True

    def __ge__(self, other):
        return True


class _MaliciousTZ(tzinfo):
    def utcoffset(self, value):
        raise AssertionError("custom tzinfo must never be consulted")

    def dst(self, value):
        raise AssertionError("custom tzinfo must never be consulted")


class _FakeAuthorization(Authorization):
    pass


class LegacyTemporalShapeReviewTests(unittest.TestCase):
    def test_canonical_valid_window_is_only_review(self):
        assert_non_authorizing(self, review(), "REVIEW_ONLY", "temporal_shape_only")

    def test_exact_inclusive_endpoints_and_microsecond_expiry(self):
        for instant in (START, MID, END):
            with self.subTest(instant=instant):
                assert_non_authorizing(self, review(now=instant),
                                       "REVIEW_ONLY", "temporal_shape_only")
        for instant in (START - timedelta(microseconds=1),
                        END + timedelta(microseconds=1)):
            assert_non_authorizing(self, review(now=instant), "HOLD", "outside_window")

    def test_valid_fixed_offset_zone_equivalence(self):
        plus = timezone(timedelta(hours=5, minutes=30))
        minus = timezone(timedelta(hours=-7))
        claim = fixture(start=START.astimezone(plus), end=END.astimezone(minus))
        assert_non_authorizing(self, review(claim, MID.astimezone(plus)),
                               "REVIEW_ONLY", "temporal_shape_only")

    def test_inverted_and_open_windows(self):
        assert_non_authorizing(self, review(fixture(start=END, end=START)),
                               "HOLD", "inverted_window")
        assert_non_authorizing(self, review(fixture(start=None, end=None)),
                               "HOLD", "unbounded_window")
        for claim in (fixture(start=None), fixture(end=None)):
            assert_non_authorizing(self, review(claim),
                                   "REVIEW_ONLY", "temporal_shape_only")

    def test_falsy_and_polymorphic_bounds_fail_closed(self):
        bad = [False, 0, 0.0, "", (), [], {}, object(),
               START.replace(tzinfo=None),
               _DatetimeSpoof(2026, 10, 15, 12, tzinfo=timezone.utc),
               datetime(2026, 10, 15, 12, tzinfo=_MaliciousTZ())]
        for bad_bound in bad:
            for field in ("valid_from", "valid_until"):
                with self.subTest(field=field, cls=type(bad_bound).__name__):
                    claim = replace(fixture(), **{field: bad_bound})
                    assert_non_authorizing(self, review(claim), "HOLD", "invalid_shape")

    def test_polymorphic_or_implicit_evaluation_time_fails_closed(self):
        for instant in (None, False, 0, "", [], {},
                        MID.replace(tzinfo=None),
                        _DatetimeSpoof(2026, 10, 15, 12, 30, tzinfo=timezone.utc),
                        datetime(2026, 10, 15, 12, tzinfo=_MaliciousTZ())):
            with self.subTest(cls=type(instant).__name__):
                assert_non_authorizing(self, review(now=instant),
                                       "HOLD", "invalid_shape")

    def test_forged_authorization_type_is_denied(self):
        auth = fixture()
        assert_non_authorizing(self, review(_FakeAuthorization(**vars(auth))),
                               "HOLD", "invalid_shape")
        for invalid in (None, {}, [], "authorization"):
            assert_non_authorizing(self, review(invalid), "HOLD", "invalid_shape")

    def test_forged_receipt_cannot_assert_permission(self):
        for malicious in (
            LegacyTemporalReview("APPROVED", "grant"),
            LegacyTemporalReview("REVIEW_ONLY", "invalid_shape"),
            LegacyTemporalReview("HOLD", "temporal_shape_only"),
            LegacyTemporalReview(True, "outside_window"),
            LegacyTemporalReview("HOLD", object()),
        ):
            receipt = malicious.as_receipt()
            self.assertEqual((receipt["status"], receipt["reason"]),
                             ("HOLD", "invalid_shape"))
            for key in set(receipt) - {"status", "reason"}:
                self.assertIs(receipt[key], False)
        with self.assertRaises(TypeError):
            LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only",
                                 permit_issued=True)

    def test_no_external_effects_or_clock_lookup(self):
        # Imports already complete: actual reviewer must not open files, spawn
        # processes, resolve hosts, or read current time for synthetic review.
        with patch("builtins.open", side_effect=AssertionError("file access")), \\
             patch("socket.socket", side_effect=AssertionError("network access")), \\
             patch("subprocess.Popen", side_effect=AssertionError("process access")):
            assert_non_authorizing(self, review(), "REVIEW_ONLY", "temporal_shape_only")
            assert_non_authorizing(self, review(fixture(end=False)),
                                   "HOLD", "invalid_shape")

    def test_receipt_snapshot_is_fresh_and_non_authorizing(self):
        verdict = review()
        first = verdict.as_receipt()
        first["permit_issued"] = True
        self.assertIs(verdict.as_receipt()["permit_issued"], False)


if __name__ == "__main__":
    unittest.main()
