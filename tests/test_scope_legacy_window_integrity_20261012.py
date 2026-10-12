"""Offline only: issue #1128 legacy temporal integrity acceptance."""
import os
import sys
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.legacy_window_integrity import review_legacy_window
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def authorization(*, valid_from=NOW - timedelta(hours=1),
                  valid_until=NOW + timedelta(hours=1),
                  owner="synthetic owner", reference="synthetic-approval"):
    return Authorization(
        owner=owner, reference=reference,
        valid_from=valid_from, valid_until=valid_until,
    )


class LegacyWindowIntegrityTests(unittest.TestCase):
    def review(self, auth, *, now=NOW):
        return review_legacy_window(auth, now=now)

    def test_valid_explicit_interval_is_only_integrity_control(self):
        result = self.review(authorization())
        self.assertTrue(result.integrity_ok)
        self.assertEqual(result.reason, "window_integrity_ok_not_authorized")
        with self.assertRaises(TypeError):
            bool(result)

    def test_missing_start_is_conservative_structural_control(self):
        self.assertTrue(self.review(authorization(valid_from=None)).integrity_ok)

    def test_expiry_always_required(self):
        result = self.review(authorization(valid_until=None))
        self.assertFalse(result.integrity_ok)
        self.assertEqual(result.reason, "missing_expiry")

    def test_falsy_non_timestamps_cannot_skip_bounds(self):
        for value in (0, False, "", [], {}, 0.0):
            with self.subTest(value=repr(value)):
                for field in ("valid_from", "valid_until"):
                    with self.subTest(field=field):
                        kwargs = {field: value}
                        result = self.review(authorization(**kwargs))
                        self.assertFalse(result.integrity_ok)
                        self.assertEqual(
                            result.reason, "invalid_start" if field == "valid_from" else "invalid_expiry"
                        )

    def test_truthy_non_timestamps_are_refused_without_exception(self):
        for value in (1, "2026-10-12T12:00:00+00:00", True, object()):
            with self.subTest(value=repr(value)):
                for field in ("valid_from", "valid_until"):
                    result = self.review(authorization(**{field: value}))
                    self.assertFalse(result.integrity_ok)

    def test_naive_datetime_is_refused(self):
        naive = NOW.replace(tzinfo=None)
        self.assertEqual(self.review(authorization(valid_from=naive)).reason, "invalid_start")
        self.assertEqual(self.review(authorization(valid_until=naive)).reason, "invalid_expiry")
        self.assertEqual(self.review(authorization(), now=naive).reason, "invalid_clock")

    def test_datetime_subclass_is_refused(self):
        class PolymorphicDateTime(datetime):
            pass
        copied = PolymorphicDateTime.fromtimestamp(NOW.timestamp(), timezone.utc)
        self.assertEqual(self.review(authorization(valid_from=copied)).reason, "invalid_start")
        self.assertEqual(self.review(authorization(valid_until=copied)).reason, "invalid_expiry")

    def test_fixed_offset_timestamps_are_compared_as_utc(self):
        plus_two = timezone(timedelta(hours=2))
        start = datetime(2026, 10, 12, 13, 0, tzinfo=plus_two)
        end = datetime(2026, 10, 12, 15, 0, tzinfo=plus_two)
        self.assertTrue(self.review(authorization(valid_from=start, valid_until=end)).integrity_ok)

    def test_start_inclusive_and_expiry_exclusive(self):
        self.assertTrue(self.review(authorization(valid_from=NOW), now=NOW).integrity_ok)
        self.assertEqual(self.review(authorization(valid_until=NOW), now=NOW).reason, "expired")

    def test_inverted_or_zero_length_window_rejected(self):
        for start, end in ((NOW, NOW), (NOW + timedelta(seconds=1), NOW)):
            with self.subTest(start=start, end=end):
                self.assertEqual(
                    self.review(authorization(valid_from=start, valid_until=end)).reason,
                    "inverted_or_empty_window",
                )

    def test_future_start_denied_even_if_expiry_future(self):
        result = self.review(authorization(valid_from=NOW + timedelta(seconds=1)))
        self.assertEqual(result.reason, "not_yet_valid")

    def test_expired_window_denied(self):
        self.assertEqual(
            self.review(authorization(valid_until=NOW - timedelta(seconds=1))).reason,
            "expired",
        )

    def test_invalid_clock_must_not_use_fallback_truthiness(self):
        for clock in (False, 0, "", [], {}, "now"):
            with self.subTest(clock=clock):
                self.assertEqual(self.review(authorization(), now=clock).reason, "invalid_clock")

    def test_noncanonical_outer_authorization_rejected(self):
        class SubAuthorization(Authorization):
            pass
        for obj in (None, object(), {}, SubAuthorization("owner", "reference")):
            with self.subTest(obj=type(obj).__name__):
                self.assertEqual(self.review(obj).reason, "noncanonical_authorization")

    def test_provenance_text_shape_requires_exact_nonempty_control_free(self):
        for field in ("owner", "reference"):
            for bad in ("", " ", " leading", "trailing ", "line\nfeed", "x\x00y", "x" * 257, None, 1):
                with self.subTest(field=field, bad=repr(bad)):
                    self.assertEqual(
                        self.review(authorization(**{field: bad})).reason,
                        "invalid_provenance_shape",
                    )

    def test_format_bidi_surrogates_and_private_use_provenance_denied(self):
        for character in ("\\u200b", "\\u200e", "\\u202e", "\\u2060", "\\ud800", "\\ue000"):
            for field in ("owner", "reference"):
                with self.subTest(character=repr(character), field=field):
                    result = self.review(authorization(**{field: "real" + character + "label"}))
                    self.assertEqual(result.reason, "invalid_provenance_shape")

    def test_international_plain_text_is_not_rejected_as_control(self):
        result = self.review(authorization(owner="Équipe française", reference="référence-123"))
        self.assertTrue(result.integrity_ok)

    def test_review_does_not_modify_existing_authorization(self):
        auth = authorization()
        before = (auth.owner, auth.reference, auth.valid_from, auth.valid_until)
        result = self.review(auth)
        self.assertTrue(result.integrity_ok)
        self.assertEqual((auth.owner, auth.reference, auth.valid_from, auth.valid_until), before)
        with self.assertRaises(FrozenInstanceError):
            result.integrity_ok = False

    def test_legacy_scope_false_positive_is_only_characterized(self):
        # Contrasting current legacy behavior, NOT integrating into ScopePolicy.
        policy = ScopePolicy(explicit_hosts=frozenset({"app.example.test"}))
        for bad in (0, False, ""):
            with self.subTest(bad=repr(bad)):
                candidate = authorization(valid_from=bad, valid_until=bad)
                legacy = policy.decide(Target("app.example.test", authorization=candidate))
                self.assertEqual(legacy.reason, ScopeReason.EXPLICIT_HOST)
                self.assertTrue(legacy.allowed)  # Existing defect #1128.
                self.assertFalse(self.review(candidate).integrity_ok)

    def test_review_does_not_infer_trusted_consent(self):
        # Even invented owner/reference values may pass structural review.
        # This has zero dispatch authority and no issuer or revocation lookup.
        fake = authorization(owner="unverified", reference="invented")
        result = self.review(fake)
        self.assertTrue(result.integrity_ok)
        with self.assertRaisesRegex(TypeError, "not an authorization decision"):
            bool(result)


if __name__ == "__main__":
    unittest.main()
