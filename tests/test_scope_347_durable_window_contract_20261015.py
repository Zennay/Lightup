"""#347: deterministic, source-backed durable authorization-window contracts.

All identities and instants are fictional; no I/O, grants, targets or handlers.
This module deliberately does not modify or wrap production grant evaluation.
"""
import os
import sys
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


UTC = timezone.utc
START = datetime(2030, 1, 2, 12, 0, tzinfo=UTC)
END = START + timedelta(hours=2)


def fictional_grant(start=START, end=END):
    return AuthorizationGrant(
        grant_id="fictional-grant-347",
        client_id="fictional-client-347",
        engagement_id="fictional-engagement-347",
        approved_by="fictional-operator",
        reference="FICTIONAL-AUTH-347",
        scope=ScopeDefinition(assets=("offline.invalid",), max_risk=RiskLevel.PASSIVE),
        valid_from=start,
        valid_until=end,
    )


class DurableGrantWindow347ContractTests(unittest.TestCase):
    def test_start_is_inclusive(self):
        self.assertIs(fictional_grant().is_current(START), True)

    def test_end_is_inclusive(self):
        self.assertIs(fictional_grant().is_current(END), True)

    def test_midpoint_is_current(self):
        self.assertIs(fictional_grant().is_current(START + timedelta(hours=1)), True)

    def test_before_start_is_denied_at_microsecond_precision(self):
        self.assertIs(fictional_grant().is_current(START - timedelta(microseconds=1)), False)

    def test_after_end_is_denied_at_microsecond_precision(self):
        self.assertIs(fictional_grant().is_current(END + timedelta(microseconds=1)), False)

    def test_window_offset_equivalence_positive(self):
        offset = timezone(timedelta(hours=5, minutes=30))
        self.assertIs(fictional_grant().is_current(START.astimezone(offset)), True)
        self.assertIs(fictional_grant().is_current(END.astimezone(offset)), True)

    def test_window_offset_equivalence_negative(self):
        offset = timezone(-timedelta(hours=7))
        self.assertIs(fictional_grant().is_current((START - timedelta(seconds=1)).astimezone(offset)), False)
        self.assertIs(fictional_grant().is_current((END + timedelta(seconds=1)).astimezone(offset)), False)

    def test_bounds_in_non_utc_zone_are_same_instants(self):
        offset = timezone(timedelta(hours=9))
        grant = fictional_grant(START.astimezone(offset), END.astimezone(offset))
        for instant in [START, END, START + timedelta(hours=1)]:
            with self.subTest(instant=instant.isoformat()):
                self.assertIs(grant.is_current(instant), True)

    def test_naive_evaluation_clock_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            fictional_grant().is_current(START.replace(tzinfo=None))

    def test_inverted_window_never_becomes_current(self):
        grant = fictional_grant(END, START)
        for seconds in [-86400, -1, 0, 1, 3600, 7200, 86400]:
            with self.subTest(seconds=seconds):
                self.assertIs(grant.is_current(START + timedelta(seconds=seconds)), False)

    def test_zero_length_window_is_only_one_instant(self):
        grant = fictional_grant(START, START)
        self.assertIs(grant.is_current(START), True)
        self.assertIs(grant.is_current(START - timedelta(microseconds=1)), False)
        self.assertIs(grant.is_current(START + timedelta(microseconds=1)), False)

    def test_shifted_window_does_not_inherit_old_authority(self):
        shift = timedelta(days=3)
        grant = fictional_grant(START + shift, END + shift)
        self.assertIs(grant.is_current(START), False)
        self.assertIs(grant.is_current(END), False)
        self.assertIs(grant.is_current(START + shift), True)

    def test_matrix_all_boundaries_and_offsets(self):
        offsets = [-12, -5, 0, 3, 10, 14]
        seconds = [-86400, -1, 0, 1, 3600, 7199, 7200, 7201, 86400]
        grant = fictional_grant()
        for hours in offsets:
            zone = timezone(timedelta(hours=hours))
            for second in seconds:
                with self.subTest(hours=hours, second=second):
                    result = grant.is_current((START + timedelta(seconds=second)).astimezone(zone))
                    self.assertIs(result, 0 <= second <= 7200)

    def test_evaluation_has_no_side_effect_on_grant_fields(self):
        grant = fictional_grant()
        snapshot = (grant.grant_id, grant.client_id, grant.engagement_id,
                    grant.approved_by, grant.reference, grant.scope, grant.valid_from,
                    grant.valid_until, grant.recurring_retest_allowed)
        for instant in [START - timedelta(seconds=1), START, END, END + timedelta(seconds=1)]:
            grant.is_current(instant)
        self.assertEqual(snapshot, (grant.grant_id, grant.client_id, grant.engagement_id,
                                   grant.approved_by, grant.reference, grant.scope,
                                   grant.valid_from, grant.valid_until, grant.recurring_retest_allowed))

    def test_grant_window_fields_are_frozen(self):
        grant = fictional_grant()
        with self.assertRaises(FrozenInstanceError):
            grant.valid_until = END + timedelta(days=1)
        self.assertEqual(grant.valid_until, END)

    @staticmethod
    def _fictional_fall_back():
        """Two different physical instants that display the same local hour."""
        zone = ZoneInfo("America/New_York")
        before_change = datetime(2030, 11, 3, 1, 30, tzinfo=zone, fold=0)
        after_change = datetime(2030, 11, 3, 1, 30, tzinfo=zone, fold=1)
        # November 3, 2030 is the first Sunday of November, the NYC fall-back.
        return before_change, after_change

    @unittest.expectedFailure
    def test_source_red_same_zone_fold_before_start_must_deny(self):
        """Existing source compares same tzinfo wall times, ignoring fold."""
        early, late = self._fictional_fall_back()
        # Late-fold grant has not begun at the early-fold evaluation instant.
        grant = fictional_grant(late, late.replace(minute=45, fold=1))
        self.assertIs(grant.is_current(early), False)

    @unittest.expectedFailure
    def test_source_red_same_zone_fold_after_expiry_must_deny(self):
        early, late = self._fictional_fall_back()
        grant = fictional_grant(early.replace(minute=0, fold=0), early)
        # In absolute UTC time, late is one full hour AFTER expiry.
        self.assertIs(grant.is_current(late), False)

    def test_fold_source_red_witness_proves_real_grant_misadmission(self):
        """Do not accept an incidental exception as evidence of a defect."""
        early, late = self._fictional_fall_back()
        self.assertLess(early.astimezone(UTC), late.astimezone(UTC))
        self.assertNotEqual(early.utcoffset(), late.utcoffset())
        self.assertEqual(early, late)  # Python same-tzinfo fold comparison.
        not_yet_active = fictional_grant(late, late.replace(minute=45, fold=1))
        already_expired = fictional_grant(early.replace(minute=0, fold=0), early)
        self.assertIs(not_yet_active.is_current(early), True)
        self.assertIs(already_expired.is_current(late), True)

    def test_fold_utc_normalization_preserves_actual_denial(self):
        early, late = self._fictional_fall_back()
        utc_early, utc_late = early.astimezone(UTC), late.astimezone(UTC)
        self.assertLess(utc_early, utc_late)
        self.assertIs(
            fictional_grant(utc_late, utc_late + timedelta(minutes=15)).is_current(utc_early),
            False,
        )
        self.assertIs(
            fictional_grant(utc_early - timedelta(minutes=15), utc_early).is_current(utc_late),
            False,
        )

    def test_other_grant_with_same_window_has_independent_identity(self):
        first = fictional_grant()
        second = fictional_grant()
        self.assertIsNot(first, second)
        self.assertIs(first.is_current(START), True)
        self.assertIs(second.is_current(END + timedelta(seconds=1)), False)
        self.assertEqual(first.valid_from, second.valid_from)


if __name__ == "__main__":
    unittest.main()
