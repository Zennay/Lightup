"""Issue #903: real disposable SQLite login-lockout timestamp admission.

Uses only the unmodified DomainStore and synthetic disposable accounts.
Intentional XFAILs demonstrate controlled AccountLockedError is not raised
for malformed and timezone-naive durable timestamps. They are not fixes.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccountLockedError, DomainStore


EMAIL = "scope903@lightup.test"
PASSWORD = "scope903-synthetic-test-password"


class LockoutTimestampAdmissionIssue903(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "scope903.db"
        self.store = DomainStore(self.db)
        self.store.bootstrap_operator(EMAIL, "Synthetic operator", PASSWORD)

    def insert_lockout(self, locked_until, failures=0):
        with sqlite3.connect(self.db) as con:
            con.execute(
                "INSERT INTO login_failures(email,failures,locked_until) VALUES(?,?,?) "
                "ON CONFLICT(email) DO UPDATE SET failures=excluded.failures, "
                "locked_until=excluded.locked_until",
                (EMAIL, failures, locked_until),
            )

    def read_lockout(self):
        with sqlite3.connect(self.db) as con:
            return con.execute(
                "SELECT failures,locked_until FROM login_failures WHERE email=?",
                (EMAIL,),
            ).fetchone()

    def test_aware_future_lockout_blocks_before_password_verification(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.insert_lockout(future, 4)
        with patch.object(self.store, "verify_password", side_effect=AssertionError("password evaluated")):
            with self.assertRaises(AccountLockedError):
                self.store.authenticate(EMAIL, PASSWORD)
        self.assertEqual(self.read_lockout(), (4, future))

    def test_aware_expired_lockout_preserves_normal_sign_in(self):
        expired = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        self.insert_lockout(expired, 4)
        signed_in = self.store.authenticate(EMAIL, PASSWORD)
        self.assertIsNotNone(signed_in)
        self.assertIsNone(self.read_lockout())

    def test_aware_future_non_utc_offset_stays_locked(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=3)).astimezone(
            timezone(timedelta(hours=5, minutes=30))
        ).isoformat()
        self.insert_lockout(future)
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_malformed_lockout_raises_controlled_account_locked(self):
        self.insert_lockout("not-an-iso-time")
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_naive_future_timestamp_raises_controlled_account_locked(self):
        naive = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
            tzinfo=None
        ).isoformat()
        self.insert_lockout(naive)
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_corrupt_timestamp_denied_before_password_or_counter_mutation(self):
        self.insert_lockout("2030-99-99T25:99:99", failures=3)
        with patch.object(self.store, "verify_password", side_effect=AssertionError("not called")):
            with self.assertRaises(AccountLockedError):
                self.store.authenticate(EMAIL, PASSWORD)
        self.assertEqual(self.read_lockout(), (3, "2030-99-99T25:99:99"))

    def test_invalid_timestamp_does_not_alter_original_sqlite_row(self):
        for raw in ("not-an-iso-time", "2026-02-31T09:00:00+00:00", "2030-99-99T25:99:99"):
            with self.subTest(raw=raw):
                self.insert_lockout(raw, failures=2)
                with self.assertRaises((ValueError, TypeError, AccountLockedError)):
                    self.store.authenticate(EMAIL, PASSWORD)
                self.assertEqual(self.read_lockout(), (2, raw))

    def test_valid_future_lockout_preserves_row_across_repeated_attempts(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=5)).isoformat()
        self.insert_lockout(future, failures=1)
        for _ in range(3):
            with self.assertRaises(AccountLockedError):
                self.store.authenticate(EMAIL, "different-password")
        self.assertEqual(self.read_lockout(), (1, future))

    def test_normal_wrong_password_after_no_lockout_counts_failure(self):
        self.assertIsNone(self.store.authenticate(EMAIL, "incorrect-password"))
        failure = self.read_lockout()
        self.assertEqual(failure[0], 1)
        self.assertIsNone(failure[1])

    def test_invalid_lockout_refuses_unknown_or_noncanonical_clock_state(self):
        # Deliberately use the actual parser failure as only a characterization
        # until the #670 owner provides a controlled account-lock contract.
        self.insert_lockout("2026-10-12T22:30:00+99:99")
        with self.assertRaises((ValueError, TypeError, AccountLockedError)):
            self.store.authenticate(EMAIL, PASSWORD)


if __name__ == "__main__":
    unittest.main()
