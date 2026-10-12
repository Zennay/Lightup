"""Independent offline authentication-failure accounting acceptance for #910.

Pure disposable SQLite, stubbed password comparison, no sessions, sockets,
targets or production activation. RED canaries are intentionally xfailed
until the DomainStore source owner serializes the read/verify/write lifetime.
"""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccountLockedError, DomainStore


EMAIL = "offline-counter@example.invalid"


class LoginFailureAtomicityIndependentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "isolated.db"
        self.store = DomainStore(self.db_path)

    def _read_row(self, email: str = EMAIL):
        with sqlite3.connect(self.db_path) as con:
            return con.execute(
                "SELECT failures, locked_until FROM login_failures WHERE email=?", (email,)
            ).fetchone()

    def _session_count(self) -> int:
        with sqlite3.connect(self.db_path) as con:
            return con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def _seed_failure_count(self, failures: int) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO login_failures(email,failures,locked_until) VALUES(?,?,NULL)",
                (EMAIL, failures),
            )

    def _run_interleaved_failures(self, initial: int = 0) -> tuple[tuple[int, str | None], int]:
        """Force overlap at verification without requiring fixed code to overlap.

        Vulnerable source reads the same counter before both reach verifier;
        a BEGIN IMMEDIATE repair can serialize the second read, in which case
        the first verifier exits after a bounded wait instead of deadlocking.
        """
        if initial:
            self._seed_failure_count(initial)
        first_in_verifier = threading.Event()
        second_in_verifier = threading.Event()
        mutex = threading.Lock()
        visits = 0

        def fake_verify(email: str, password: str):
            nonlocal visits
            self.assertEqual(email, EMAIL)
            self.assertEqual(password, "synthetic-invalid")
            with mutex:
                visits += 1
                ordinal = visits
            if ordinal == 1:
                first_in_verifier.set()
                second_in_verifier.wait(timeout=0.65)
            else:
                second_in_verifier.set()
            return None

        def fail_once():
            return self.store.authenticate("  OFFLINE-counter@example.invalid  ", "synthetic-invalid")

        with patch.object(self.store, "verify_password", side_effect=fake_verify):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(fail_once)
                self.assertTrue(
                    first_in_verifier.wait(timeout=4),
                    "first offline verification did not start",
                )
                second = pool.submit(fail_once)
                self.assertIsNone(first.result(timeout=8))
                self.assertIsNone(second.result(timeout=8))

        self.assertEqual(visits, 2)
        self.assertEqual(self._session_count(), 0)
        row = self._read_row()
        self.assertIsNotNone(row)
        self.assertIsNone(row[1], "two failures must not lock the account yet")
        return row, visits

    def test_one_failed_login_uses_canonical_email_and_creates_no_session(self):
        with patch.object(self.store, "verify_password", return_value=None) as verifier:
            self.assertIsNone(self.store.authenticate("  OFFLINE-counter@example.invalid  ", "invalid"))
        verifier.assert_called_once_with(EMAIL, "invalid")
        self.assertEqual(self._read_row(), (1, None))
        self.assertEqual(self._session_count(), 0)
        self.assertIsNone(self._read_row("  OFFLINE-counter@example.invalid  "))

    def test_serial_failures_increment_and_fifth_locks(self):
        with patch.object(self.store, "verify_password", return_value=None) as verifier:
            for expected in range(1, self.store.LOGIN_MAX_FAILURES):
                self.assertIsNone(self.store.authenticate(EMAIL, "invalid"))
                self.assertEqual(self._read_row(), (expected, None))
            self.assertIsNone(self.store.authenticate(EMAIL, "invalid"))
            row = self._read_row()
            self.assertEqual(row[0], 0)
            self.assertIsNotNone(row[1])
            with self.assertRaises(AccountLockedError):
                self.store.authenticate(EMAIL, "invalid")
        self.assertEqual(verifier.call_count, self.store.LOGIN_MAX_FAILURES)
        self.assertEqual(self._session_count(), 0)

    def test_unrelated_email_counters_do_not_mix(self):
        with patch.object(self.store, "verify_password", return_value=None):
            self.store.authenticate(EMAIL, "invalid")
            self.store.authenticate("another-offline@example.invalid", "invalid")
            self.store.authenticate(EMAIL, "invalid")
        self.assertEqual(self._read_row(), (2, None))
        self.assertEqual(self._read_row("another-offline@example.invalid"), (1, None))
        self.assertEqual(self._session_count(), 0)

    def test_concurrent_stubs_finish_without_creating_session(self):
        # GREEN control: even the broken historical source completes and has no
        # successful user/session. Counting correctness is asserted separately.
        row, calls = self._run_interleaved_failures()
        self.assertEqual(calls, 2)
        self.assertIn(row[0], (1, 2))
        self.assertEqual(self._session_count(), 0)

    @unittest.expectedFailure
    def test_red_two_concurrent_failures_must_persist_both_increments(self):
        row, _ = self._run_interleaved_failures()
        self.assertEqual(row, (2, None), "lost a failed login due to stale read/update")

    @unittest.expectedFailure
    def test_red_existing_counter_two_overlapping_failures_increment_twice(self):
        row, _ = self._run_interleaved_failures(initial=1)
        self.assertEqual(row, (3, None), "overlap overwrote an already-persisted counter")


if __name__ == "__main__":
    unittest.main()
