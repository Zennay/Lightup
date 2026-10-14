"""Offline type, equality, privacy and genuine disposable SQLite canaries (#647).

Not a production grant issuance or authorization mechanism. All SQL rows are
synthetic and kept under TemporaryDirectory; no target network I/O.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.grant_issuance_window_snapshot_647 import (
    CanonicalIssueWindow, snapshot_grant_issuance_window,
)
from lightup.grant_window_storage_consistency_647 import (
    WindowStorageConsistencyReview,
    review_grant_window_storage_consistency,
)
from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


START = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
UNTIL = START + timedelta(minutes=12)


def _review(reference, stored_start=None, stored_end=None):
    return review_grant_window_storage_consistency(
        reference,
        stored_valid_from=START.isoformat() if stored_start is None else stored_start,
        stored_valid_until=UNTIL.isoformat() if stored_end is None else stored_end,
    )


class _SpoofStr(str):
    def __eq__(self, other):
        return True


class _SpoofDatetime(datetime):
    def isoformat(self, *args, **kwargs):
        return "2999-01-01T00:00:00+00:00"


class PureWindowStorageConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.window = snapshot_grant_issuance_window(START, UNTIL)

    def assert_hold(self, value, why):
        self.assertIs(type(value), WindowStorageConsistencyReview)
        self.assertEqual((value.decision, value.reason), ("HOLD", why))
        self._no_authority(value)

    def assert_review_only(self, value):
        self.assertIs(type(value), WindowStorageConsistencyReview)
        self.assertEqual((value.decision, value.reason),
                         ("REVIEW_ONLY", "shape_and_values_match"))
        self._no_authority(value)

    def _no_authority(self, value):
        flags = ("authorization_verified", "grant_issued", "execution_enabled",
                 "release_approved")
        receipt = value.as_receipt()
        self.assertEqual(set(receipt), {"decision", "reason", *flags})
        for flag in flags:
            self.assertIs(getattr(value, flag), False)
            self.assertIs(receipt[flag], False)

    def test_exact_builtin_utc_storage_matches(self):
        self.assert_review_only(_review(self.window))

    def test_fixed_offset_snapshot_compared_to_utc_row(self):
        offset = timezone(timedelta(hours=5, minutes=30))
        earlier = START.astimezone(offset)
        later = UNTIL.astimezone(timezone(timedelta(hours=-8)))
        snapshot = snapshot_grant_issuance_window(earlier, later)
        self.assert_review_only(_review(snapshot))

    def test_earlier_stored_start_detected(self):
        self.assert_hold(
            _review(self.window, stored_start=(START - timedelta(days=365)).isoformat()),
            "start_mismatch",
        )

    def test_later_stored_expiry_detected(self):
        self.assert_hold(
            _review(self.window, stored_end=(UNTIL + timedelta(days=365)).isoformat()),
            "expiry_mismatch",
        )

    def test_shortened_window_also_detected(self):
        self.assert_hold(
            _review(self.window, stored_end=(UNTIL - timedelta(seconds=1)).isoformat()),
            "expiry_mismatch",
        )

    def test_moved_start_detected(self):
        self.assert_hold(
            _review(self.window, stored_start=(START + timedelta(seconds=1)).isoformat()),
            "start_mismatch",
        )

    def test_untrusted_reference_types_rejected(self):
        for ref in (None, {}, [], (), True, START):
            with self.subTest(ref=repr(ref)):
                self.assert_hold(_review(ref), "reference_type")

    def test_spoof_datetime_inside_reference_refused(self):
        forged = _SpoofDatetime(2026, 10, 14, 12, tzinfo=timezone.utc)
        self.assert_hold(
            _review(CanonicalIssueWindow(forged, UNTIL)),
            "reference_time",
        )
        self.assert_hold(
            _review(CanonicalIssueWindow(START, forged)),
            "reference_time",
        )

    def test_naive_reference_refused(self):
        self.assert_hold(
            _review(CanonicalIssueWindow(START.replace(tzinfo=None), UNTIL)),
            "reference_time",
        )

    def test_non_utc_reference_refused_even_same_instant(self):
        other = START.astimezone(timezone(timedelta(hours=3)))
        self.assert_hold(
            _review(CanonicalIssueWindow(other, UNTIL)),
            "reference_time",
        )

    def test_empty_reference_refused(self):
        self.assert_hold(
            _review(CanonicalIssueWindow(START, START)),
            "reference_window",
        )

    def test_reversed_reference_refused(self):
        self.assert_hold(
            _review(CanonicalIssueWindow(UNTIL, START)),
            "reference_window",
        )

    def test_stored_str_subclass_refused_before_custom_equality(self):
        self.assert_hold(
            _review(self.window, stored_start=_SpoofStr(START.isoformat())),
            "stored_start",
        )
        self.assert_hold(
            _review(self.window, stored_end=_SpoofStr(UNTIL.isoformat())),
            "stored_expiry",
        )

    def test_non_string_stored_start_rejected(self):
        for item in (False, 0, [], {}, b"2026-10-14", datetime.now(timezone.utc)):
            with self.subTest(item=type(item).__name__):
                self.assert_hold(_review(self.window, stored_start=item),
                                 "stored_start")

    def test_non_string_stored_end_rejected(self):
        for item in (False, 0, [], {}, b"2026-10-14", datetime.now(timezone.utc)):
            with self.subTest(item=type(item).__name__):
                self.assert_hold(_review(self.window, stored_end=item),
                                 "stored_expiry")

    def test_malformed_start_storage_rejected(self):
        invalid = (
            "2026-10-14T12:00:00Z", "2026-10-14t12:00:00+00:00",
            "2026-10-14 12:00:00+00:00", "2026-10-14T12:00:00+01:00",
            "2026-10-14T12:00:00.000000+00:00",
            "2026-10-14T12:00:00+00:00\n",
            "2026-10-14T12:00:00\u200b+00:00",
            "2026-10-14T12:00:00-00:00",
            "2026-10-14T12:00:00", "2026-10-14T25:00:00+00:00",
            "2026-02-30T12:00:00+00:00", "99999-10-14T12:00:00+00:00",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assert_hold(_review(self.window, stored_start=value),
                                 "stored_start")

    def test_malformed_end_storage_rejected(self):
        for value in ("2026-10-14T12:12:00Z", "2026-10-14T12:12:00+01:00",
                      "2026-10-14T12:12:00\n+00:00", "garbage"):
            with self.subTest(value=value):
                self.assert_hold(_review(self.window, stored_end=value),
                                 "stored_expiry")

    def test_microsecond_precision_can_be_matched(self):
        start = START + timedelta(microseconds=123)
        until = UNTIL + timedelta(microseconds=456)
        snapshot = snapshot_grant_issuance_window(start, until)
        self.assert_review_only(_review(snapshot, start.isoformat(), until.isoformat()))

    def test_microsecond_mismatch_is_detected(self):
        start = START + timedelta(microseconds=123)
        until = UNTIL + timedelta(microseconds=456)
        snapshot = snapshot_grant_issuance_window(start, until)
        self.assert_hold(
            _review(snapshot, (start + timedelta(microseconds=1)).isoformat(),
                    until.isoformat()),
            "start_mismatch",
        )

    def test_failure_receipt_is_privacy_minimal(self):
        secret = "SYNTHETIC_PRIVATE_TOKEN"
        failure = _review(self.window, stored_start=secret)
        serialized = repr(failure.as_receipt())
        self.assertNotIn(secret, serialized)
        self.assertNotIn("2026", serialized)
        self.assertNotIn("fixture", serialized)

    def test_no_network_disk_db_or_clock_calls(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")):
            self.assert_review_only(_review(self.window))
            self.assert_hold(
                _review(self.window,
                        stored_end=(UNTIL + timedelta(minutes=1)).isoformat()),
                "expiry_mismatch",
            )


class DisposableSQLiteStorageReviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="scope-647-consistency-")
        self.addCleanup(temp.cleanup)
        self.dbfile = Path(temp.name) / "fictional.sqlite"
        self.store = DomainStore(self.dbfile)
        self.ctx = AccessContext("fixture-operator", Role.OPERATOR)
        client = self.store.create_client(self.ctx, "Fixture Company - NOT REAL")
        self.engagement = self.store.create_engagement(
            self.ctx, client.client_id, "Fixture Only"
        )
        self.scope = ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        )
        self.window = snapshot_grant_issuance_window(START, UNTIL)
        self.grant = self.store.record_authorization_grant(
            self.ctx, self.engagement.engagement_id, "Synthetic Operator",
            "NOT_REAL_APPROVAL", self.scope,
            self.window.starts_at_utc, self.window.expires_at_utc,
        )

    def _raw_grant_row(self):
        with self.store._connect() as con:
            return con.execute(
                "SELECT valid_from, valid_until FROM authorization_grants "
                "WHERE grant_id=?", (self.grant.grant_id,)
            ).fetchone()

    def _check(self):
        row = self._raw_grant_row()
        return review_grant_window_storage_consistency(
            self.window,
            stored_valid_from=row["valid_from"],
            stored_valid_until=row["valid_until"],
        )

    def _mutate(self, field, value):
        self.assertIn(field, ("valid_from", "valid_until"))
        # Mutation is confined to the disposable fixture DB owned by this test.
        with self.store._connect() as con:
            con.execute(
                f"UPDATE authorization_grants SET {field}=? WHERE grant_id=?",
                (value, self.grant.grant_id),
            )

    def test_real_sqlite_canonical_grant_review_is_only_review(self):
        outcome = self._check()
        self.assertEqual(outcome.decision, "REVIEW_ONLY")
        self.assertFalse(outcome.authorization_verified)
        self.assertFalse(outcome.execution_enabled)

    def test_real_sqlite_widened_expiry_is_hold(self):
        self._mutate("valid_until", (UNTIL + timedelta(days=365)).isoformat())
        result = self._check()
        self.assertEqual((result.decision, result.reason), ("HOLD", "expiry_mismatch"))

    def test_real_sqlite_backdated_start_is_hold(self):
        self._mutate("valid_from", (START - timedelta(days=365)).isoformat())
        result = self._check()
        self.assertEqual((result.decision, result.reason), ("HOLD", "start_mismatch"))

    def test_real_sqlite_corrupt_string_is_hold_and_remains_unmodified(self):
        corrupted = "not_a_datetime_PRIVATE"
        self._mutate("valid_until", corrupted)
        result = self._check()
        self.assertEqual((result.decision, result.reason), ("HOLD", "stored_expiry"))
        self.assertEqual(self._raw_grant_row()["valid_until"], corrupted)
        self.assertNotIn(corrupted, repr(result.as_receipt()))

    def test_real_sqlite_narrowed_window_is_detected(self):
        self._mutate("valid_from", (START + timedelta(microseconds=1)).isoformat())
        self.assertEqual(self._check().reason, "start_mismatch")

    def test_real_sqlite_review_does_not_modify_rows(self):
        before = tuple(self._raw_grant_row())
        self._check()
        after = tuple(self._raw_grant_row())
        self.assertEqual(before, after)

    def test_no_outbound_socket_even_during_temp_sqlite_audit(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            self.assertEqual(self._check().decision, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
