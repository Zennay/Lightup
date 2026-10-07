from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from lightup.domain import DomainStore


class CoordinatedFailureStore(DomainStore):
    """Pause the first verification after its failure-state read."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.first_verify_entered = threading.Event()
        self.second_verify_entered = threading.Event()
        self.release_first_verify = threading.Event()
        self._verify_lock = threading.Lock()
        self._verify_calls = 0

    def verify_password(self, email: str, password: str):  # type: ignore[override]
        with self._verify_lock:
            self._verify_calls += 1
            call_number = self._verify_calls

        if call_number == 1:
            self.first_verify_entered.set()
            if not self.release_first_verify.wait(timeout=5):
                raise AssertionError("first verification was not released")
        elif call_number == 2:
            self.second_verify_entered.set()
        else:
            raise AssertionError("unexpected additional password verification")

        return None


class LoginFailureAtomicityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "domain.db"
        self.store = CoordinatedFailureStore(self.db_path)
        self.email = "operator@lightup.test"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _failure_state(self) -> tuple[int, object] | None:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT failures, locked_until FROM login_failures WHERE email=?",
                (self.email,),
            ).fetchone()
        if row is None:
            return None
        return int(row[0]), row[1]

    def test_two_concurrent_failures_are_counted_twice(self) -> None:
        errors: list[BaseException] = []

        def attempt() -> None:
            try:
                self.store.authenticate(self.email, "definitely-wrong-password")
            except BaseException as exc:  # pragma: no cover - assertion capture
                errors.append(exc)

        first = threading.Thread(target=attempt)
        first.start()
        self.assertTrue(
            self.store.first_verify_entered.wait(timeout=2),
            "first authentication did not reach verification",
        )

        second = threading.Thread(target=attempt)
        second.start()

        # Current source lets the second path read the same empty failure row
        # while the first path is paused in verification. A future serialized
        # implementation may instead block the second read; either way, release
        # the first path after a bounded observation window so the test cannot
        # deadlock on the intended fix.
        self.store.second_verify_entered.wait(timeout=0.25)
        self.store.release_first_verify.set()

        first.join(timeout=5)
        second.join(timeout=5)
        self.assertFalse(first.is_alive(), "first authentication thread hung")
        self.assertFalse(second.is_alive(), "second authentication thread hung")
        self.assertEqual(errors, [])

        self.assertEqual(
            self._failure_state(),
            (2, None),
            "two failed authentications must produce two durable failures",
        )


if __name__ == "__main__":
    unittest.main()
