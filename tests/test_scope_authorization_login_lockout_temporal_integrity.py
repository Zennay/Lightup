from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccountLockedError, DomainStore


class LoginLockoutTemporalIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "domain.db"
        self.store = DomainStore(self.db_path)
        self.user = self.store.bootstrap_operator(
            "operator@lightup.test",
            "Operator",
            "correct-horse-battery",
        )
        self.email = self.user.email

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_lockout(self, locked_until: str) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO login_failures(email, failures, locked_until) VALUES(?,?,?) "
                "ON CONFLICT(email) DO UPDATE SET failures=excluded.failures, "
                "locked_until=excluded.locked_until",
                (self.email, 0, locked_until),
            )

    def _raw_lockout(self) -> tuple[int, str] | None:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT failures, locked_until FROM login_failures WHERE email=?",
                (self.email,),
            ).fetchone()
        if row is None:
            return None
        return int(row[0]), str(row[1])

    def test_canonical_future_lockout_remains_locked(self) -> None:
        locked_until = (
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat()
        self._write_lockout(locked_until)

        with self.assertRaises(AccountLockedError):
            self.store.authenticate(self.email, "correct-horse-battery")

        self.assertEqual(self._raw_lockout(), (0, locked_until))

    def test_canonical_expired_lockout_preserves_authentication_path(self) -> None:
        locked_until = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()
        self._write_lockout(locked_until)

        authenticated = self.store.authenticate(
            self.email,
            "correct-horse-battery",
        )

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.user_id, self.user.user_id)
        self.assertIsNone(self._raw_lockout())

    def test_malformed_persisted_lockout_fails_closed_without_repair(self) -> None:
        raw = "not-an-iso-datetime"
        self._write_lockout(raw)

        with self.assertRaisesRegex(AccountLockedError, "lock|sign-in|authentication"):
            self.store.authenticate(self.email, "correct-horse-battery")

        self.assertEqual(self._raw_lockout(), (0, raw))

    def test_naive_persisted_lockout_fails_closed_without_repair(self) -> None:
        raw = (datetime.now() + timedelta(minutes=10)).isoformat()
        self._write_lockout(raw)

        with self.assertRaisesRegex(AccountLockedError, "lock|sign-in|authentication"):
            self.store.authenticate(self.email, "correct-horse-battery")

        self.assertEqual(self._raw_lockout(), (0, raw))


if __name__ == "__main__":
    unittest.main()
