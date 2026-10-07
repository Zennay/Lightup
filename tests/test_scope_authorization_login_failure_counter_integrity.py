from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccountLockedError, DomainStore


class LoginFailureCounterIntegrityTests(unittest.TestCase):
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

    def _write_failure_state(self, failures: object) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO login_failures(email, failures, locked_until) VALUES(?,?,NULL) "
                "ON CONFLICT(email) DO UPDATE SET failures=excluded.failures, locked_until=NULL",
                (self.email, failures),
            )

    def _raw_failure_state(self) -> tuple[str, object, object] | None:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT typeof(failures), failures, locked_until "
                "FROM login_failures WHERE email=?",
                (self.email,),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), row[1], row[2]

    def test_canonical_unlocked_counter_preserves_successful_login_reset(self) -> None:
        self._write_failure_state(2)
        self.assertEqual(self._raw_failure_state(), ("integer", 2, None))

        authenticated = self.store.authenticate(
            self.email,
            "correct-horse-battery",
        )

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.user_id, self.user.user_id)
        self.assertIsNone(self._raw_failure_state())

    def test_corrupt_unlocked_counters_fail_closed_without_reset(self) -> None:
        invalid_values = (
            -1,
            DomainStore.LOGIN_MAX_FAILURES,
            1.5,
            "not-a-counter",
        )
        for value in invalid_values:
            with self.subTest(value=repr(value)):
                self._write_failure_state(value)
                before = self._raw_failure_state()
                self.assertIsNotNone(before)

                with self.assertRaisesRegex(
                    AccountLockedError,
                    "lock|sign-in|authentication",
                ):
                    self.store.authenticate(
                        self.email,
                        "correct-horse-battery",
                    )

                self.assertEqual(self._raw_failure_state(), before)


if __name__ == "__main__":
    unittest.main()
