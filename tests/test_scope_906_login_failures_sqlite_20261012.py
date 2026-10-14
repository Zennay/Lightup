"""#906: tests-only SQLite login-failure counter producer-integrity acceptance.

Runs on real temporary DomainStore and disposable SQLite. Expected failures
are deliberate current-source security gaps, not successful auth fixes.
"""
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccountLockedError, DomainStore


EMAIL = "scope906@lightup.test"
PASSWORD = "scope906-synthetic-passphrase"


class FailureCounterIntegrityIssue906(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "scope906.db"
        self.store = DomainStore(self.db)
        self.store.bootstrap_operator(EMAIL, "Synthetic", PASSWORD)

    def seed(self, failures, locked_until=None):
        with sqlite3.connect(self.db) as con:
            con.execute(
                "INSERT INTO login_failures(email,failures,locked_until) VALUES (?,?,?) "
                "ON CONFLICT(email) DO UPDATE SET failures=excluded.failures, "
                "locked_until=excluded.locked_until",
                (EMAIL, failures, locked_until),
            )

    def snapshot(self):
        with sqlite3.connect(self.db) as con:
            return con.execute(
                "SELECT failures,typeof(failures),locked_until "
                "FROM login_failures WHERE email=?", (EMAIL,),
            ).fetchone()

    @unittest.expectedFailure
    def test_red_negative_counter_denies_even_correct_password(self):
        self.seed(-1)
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_unlocked_threshold_counter_does_not_reset_on_success(self):
        self.seed(DomainStore.LOGIN_MAX_FAILURES)
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_real_counter_does_not_authenticate_or_clear(self):
        self.seed(1.5)
        self.assertEqual(self.snapshot()[1], "real")
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_text_counter_does_not_authenticate_or_clear(self):
        self.seed("spoofed")
        self.assertEqual(self.snapshot()[1], "text")
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    @unittest.expectedFailure
    def test_red_corrupt_counter_denied_before_password_verifier(self):
        self.seed(-99)
        with patch.object(self.store, "verify_password", side_effect=AssertionError("password evaluated")):
            with self.assertRaises(AccountLockedError):
                self.store.authenticate(EMAIL, PASSWORD)

    def test_valid_zero_counter_wrong_password_increments(self):
        self.seed(0)
        self.assertIsNone(self.store.authenticate(EMAIL, "invalid-password"))
        self.assertEqual(self.snapshot(), (1, "integer", None))

    def test_valid_prethreshold_counter_progresses_to_locked_row(self):
        self.seed(DomainStore.LOGIN_MAX_FAILURES - 1)
        self.assertIsNone(self.store.authenticate(EMAIL, "invalid-password"))
        current = self.snapshot()
        self.assertEqual(current[0:2], (0, "integer"))
        self.assertIsNotNone(current[2])
        with self.assertRaises(AccountLockedError):
            self.store.authenticate(EMAIL, PASSWORD)

    def test_correct_password_clears_only_valid_unlocked_row(self):
        self.seed(3)
        user = self.store.authenticate(EMAIL, PASSWORD)
        self.assertIsNotNone(user)
        self.assertIsNone(self.snapshot())

    def test_canonical_future_locked_row_preserves_zero_counter(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        self.seed(0, future)
        with patch.object(self.store, "verify_password", side_effect=AssertionError("password evaluated")):
            with self.assertRaises(AccountLockedError):
                self.store.authenticate(EMAIL, PASSWORD)
        self.assertEqual(self.snapshot(), (0, "integer", future))

    def test_invalid_input_row_immutability_characterization(self):
        # The original source may return the user, so use the wrong password
        # only where conversion cannot reach a persisted update. Even a parser
        # exception is *not* a controlled AccountLockedError proof.
        self.seed("corrupt-not-a-number")
        before = self.snapshot()
        with self.assertRaises((TypeError, ValueError, AccountLockedError)):
            self.store.authenticate(EMAIL, "invalid-password")
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
