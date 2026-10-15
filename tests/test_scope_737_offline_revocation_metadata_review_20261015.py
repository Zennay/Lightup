"""Strict offline #737 metadata reviewer tests, synthetic-only and no I/O."""
from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone, tzinfo

from scripts.scope_737_revocation_metadata_review import (
    RevocationReview,
    review_revocation_metadata,
)


DATE = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)


class BadTruthy:
    def __bool__(self):
        raise AssertionError("untrusted truthiness called")

    def __str__(self):
        raise AssertionError("untrusted to-string called")

    def __eq__(self, other):
        raise AssertionError("untrusted equality called")


class SubclassedDatetime(datetime):
    def utcoffset(self):
        raise AssertionError("polymorphic time conversion called")


class HostileTimezone(tzinfo):
    def utcoffset(self, dt):
        raise AssertionError("untrusted timezone executed")

    def dst(self, dt):
        raise AssertionError("untrusted timezone executed")

    def tzname(self, dt):
        raise AssertionError("untrusted timezone executed")


class SubclassedStr(str):
    def strip(self, chars=None):
        raise AssertionError("polymorphic strip called")


class ReviewRevocationMetadataTests(unittest.TestCase):
    def assertHold(self, result: RevocationReview) -> None:
        self.assertIs(type(result), RevocationReview)
        self.assertEqual(result.decision, "HOLD")
        self.assertIs(result.can_authorize, False)
        self.assertIs(result.can_dispatch, False)
        self.assertIs(result.can_release, False)
        self.assertIs(type(result.reason_codes), tuple)
        self.assertTrue(result.reason_codes)
        self.assertTrue(all(type(item) is str for item in result.reason_codes))

    def test_canonical_all_none_is_still_hold(self):
        r = review_revocation_metadata()
        self.assertHold(r)
        self.assertEqual(r.classification, "no_revocation_claim")
        self.assertEqual(r.reason_codes, ("independent_authorization_verification_required",))

    def test_complete_revocation_is_still_hold(self):
        r = review_revocation_metadata(
            revoked_at=DATE, revoked_by="fictional-reviewer", revocation_reason="fixture revocation"
        )
        self.assertHold(r)
        self.assertEqual(r.classification, "revocation_recorded")
        self.assertEqual(r.reason_codes, ("independent_revocation_verification_required",))

    def test_non_utc_aware_timezone_is_structurally_recognized_without_authority(self):
        dt = datetime(2026, 10, 15, 12, tzinfo=timezone(timedelta(hours=2)))
        r = review_revocation_metadata(
            revoked_at=dt, revoked_by="fictional-reviewer", revocation_reason="fixture revocation"
        )
        self.assertHold(r)
        self.assertEqual(r.classification, "revocation_recorded")

    def test_actor_only_without_timestamp_is_inconsistent(self):
        r = review_revocation_metadata(revoked_by="fictional-reviewer")
        self.assertHold(r)
        self.assertEqual(r.reason_codes, ("stale_revocation_provenance",))

    def test_reason_only_without_timestamp_is_inconsistent(self):
        r = review_revocation_metadata(revocation_reason="fixture revocation")
        self.assertHold(r)
        self.assertEqual(r.reason_codes, ("stale_revocation_provenance",))

    def test_both_without_timestamp_are_inconsistent(self):
        r = review_revocation_metadata(
            revoked_by="fictional-reviewer", revocation_reason="fixture revocation"
        )
        self.assertHold(r)
        self.assertEqual(r.reason_codes, ("stale_revocation_provenance",))

    def test_timestamp_only_is_incomplete(self):
        r = review_revocation_metadata(revoked_at=DATE)
        self.assertHold(r)
        self.assertIn("incomplete_revocation_event", r.reason_codes)

    def test_timestamp_and_actor_without_reason_are_incomplete(self):
        r = review_revocation_metadata(revoked_at=DATE, revoked_by="fictional-reviewer")
        self.assertHold(r)
        self.assertIn("incomplete_revocation_event", r.reason_codes)

    def test_timestamp_and_reason_without_actor_are_incomplete(self):
        r = review_revocation_metadata(revoked_at=DATE, revocation_reason="fixture revocation")
        self.assertHold(r)
        self.assertIn("incomplete_revocation_event", r.reason_codes)

    def test_timestamp_must_be_exact_datetime(self):
        for value in (False, 0, "", "2026-10-15", BadTruthy(), SubclassedDatetime(2026, 10, 15)):
            with self.subTest(value_type=type(value).__name__):
                r = review_revocation_metadata(
                    revoked_at=value,
                    revoked_by="fictional-reviewer",
                    revocation_reason="fixture revocation",
                )
                self.assertHold(r)
                self.assertIn("noncanonical_revoked_at", r.reason_codes)
                self.assertEqual(r.classification, "inconsistent")

    def test_foreign_timezone_callbacks_are_never_executed(self):
        # The exact datetime stores an untrusted tzinfo; *reading* its
        # offset would call attacker-supplied Python. Reject by type first.
        dt = datetime(2026, 10, 15, tzinfo=HostileTimezone())
        r = review_revocation_metadata(
            revoked_at=dt,
            revoked_by="fictional-reviewer",
            revocation_reason="fixture revocation",
        )
        self.assertHold(r)
        self.assertEqual(r.classification, "inconsistent")
        self.assertIn("noncanonical_revocation_timezone", r.reason_codes)

    def test_naive_timestamp_is_inconsistent(self):
        r = review_revocation_metadata(
            revoked_at=datetime(2026, 10, 15),
            revoked_by="fictional-reviewer",
            revocation_reason="fixture revocation",
        )
        self.assertHold(r)
        self.assertIn("naive_revoked_at", r.reason_codes)

    def test_revoker_must_be_exact_nonblank_trimmed_text(self):
        for value in (False, 0, "", "  ", " user ", BadTruthy(), SubclassedStr("user")):
            with self.subTest(value_type=type(value).__name__, is_str=type(value) is str):
                r = review_revocation_metadata(
                    revoked_at=DATE, revoked_by=value, revocation_reason="fixture revocation"
                )
                self.assertHold(r)
                self.assertIn("noncanonical_revoked_by", r.reason_codes)

    def test_revocation_reason_must_be_exact_nonblank_trimmed_text(self):
        for value in (False, 0, "", "  ", " reason ", BadTruthy(), SubclassedStr("reason")):
            with self.subTest(value_type=type(value).__name__, is_str=type(value) is str):
                r = review_revocation_metadata(
                    revoked_at=DATE, revoked_by="fictional-reviewer", revocation_reason=value
                )
                self.assertHold(r)
                self.assertIn("noncanonical_revocation_reason", r.reason_codes)

    def test_actor_and_reason_are_bounded(self):
        for name, value in (("revoked_by", "a"*257), ("revocation_reason", "b"*257)):
            with self.subTest(name=name):
                base = {"revoked_at": DATE, "revoked_by": "user", "revocation_reason": "fixture"}
                base[name] = value
                r = review_revocation_metadata(**base)
                self.assertHold(r)
                self.assertEqual(r.classification, "inconsistent")

    def test_stale_actor_empty_is_not_normalized_to_absent(self):
        r = review_revocation_metadata(revoked_by="")
        self.assertHold(r)
        self.assertEqual(r.classification, "inconsistent")
        self.assertIn("noncanonical_revoked_by", r.reason_codes)
        self.assertIn("stale_revocation_provenance", r.reason_codes)

    def test_stale_reason_empty_is_not_normalized_to_absent(self):
        r = review_revocation_metadata(revocation_reason="")
        self.assertHold(r)
        self.assertEqual(r.classification, "inconsistent")
        self.assertIn("noncanonical_revocation_reason", r.reason_codes)
        self.assertIn("stale_revocation_provenance", r.reason_codes)

    def test_both_malformed_codes_are_stable(self):
        r = review_revocation_metadata(
            revoked_at="bad", revoked_by=BadTruthy(), revocation_reason=SubclassedStr("yes")
        )
        self.assertHold(r)
        self.assertEqual(r.reason_codes, (
            "noncanonical_revoked_at",
            "noncanonical_revoked_by",
            "noncanonical_revocation_reason",
        ))

    def test_no_raw_revoker_or_reason_in_result_repr(self):
        person = "fictional-private-reviewer"
        reason = "fictional-private-evidence"
        for r in (
            review_revocation_metadata(revoked_by=person, revocation_reason=reason),
            review_revocation_metadata(revoked_at=DATE, revoked_by=person, revocation_reason=reason),
        ):
            self.assertHold(r)
            self.assertNotIn(person, repr(r))
            self.assertNotIn(reason, repr(r))

    def test_never_authorizes_under_adversarial_matrix(self):
        vals = (None, DATE, False, "untrusted", BadTruthy())
        for timestamp in vals:
            for actor in (None, "fixture", False, BadTruthy()):
                for reason in (None, "fixture", False, BadTruthy()):
                    r = review_revocation_metadata(
                        revoked_at=timestamp, revoked_by=actor, revocation_reason=reason
                    )
                    self.assertHold(r)

    def test_output_cannot_be_mutated_normally(self):
        r = review_revocation_metadata()
        with self.assertRaises(FrozenInstanceError):
            r.can_authorize = True

    def test_input_values_not_modified(self):
        a = BadTruthy()
        kwargs = {"revoked_at": a, "revoked_by": a, "revocation_reason": a}
        review_revocation_metadata(**kwargs)
        self.assertIs(kwargs["revoked_at"], a)
        self.assertIs(kwargs["revoked_by"], a)
        self.assertIs(kwargs["revocation_reason"], a)

    def test_only_keyword_call_supported(self):
        with self.assertRaises(TypeError):
            review_revocation_metadata(DATE, "fictional-reviewer", "fixture revocation")


if __name__ == "__main__":
    unittest.main()
