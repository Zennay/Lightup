from __future__ import annotations

import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import DomainStore


_CANONICAL_CSRF = re.compile(r"^[A-Za-z0-9_-]{43}$")


class SessionCsrfIntegrityBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = self.store.bootstrap_operator(
            "csrf-boundary@lightup.test",
            "CSRF Boundary",
            "correct-horse-battery",
        )
        self.token, self.csrf = self.store.create_session(self.operator.user_id)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _token_hash(self) -> str:
        return self.store._token_hash(self.token)

    def _row(self):
        with self.store._connect() as con:
            return con.execute(
                "SELECT token_hash,user_id,csrf_token,created_at,expires_at "
                "FROM sessions WHERE token_hash=?",
                (self._token_hash(),),
            ).fetchone()

    def _set_csrf(self, value) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE sessions SET csrf_token=? WHERE token_hash=?",
                (value, self._token_hash()),
            )

    def _assert_unauthenticated_without_mutation(self) -> None:
        before = self._row()
        self.assertIsNotNone(before)

        try:
            resolved = self.store.session_context(self.token)
        except Exception as exc:
            self.fail(f"corrupt CSRF state escaped auth boundary: {exc!r}")

        self.assertIsNone(resolved)
        after = self._row()
        self.assertIsNotNone(after)
        self.assertEqual(tuple(after), tuple(before))

    def test_generated_csrf_control_is_canonical_and_resolves(self) -> None:
        self.assertIs(type(self.csrf), str)
        self.assertRegex(self.csrf, _CANONICAL_CSRF)

        resolved = self.store.session_context(self.token)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0].user_id, self.operator.user_id)
        self.assertEqual(resolved[1], self.csrf)

    def test_blank_persisted_csrf_fails_closed(self) -> None:
        self._set_csrf("")
        self._assert_unauthenticated_without_mutation()

    def test_short_guessable_persisted_csrf_fails_closed(self) -> None:
        self._set_csrf("known")
        self._assert_unauthenticated_without_mutation()

    def test_whitespace_padded_persisted_csrf_fails_closed(self) -> None:
        self._set_csrf(f" {self.csrf} ")
        self._assert_unauthenticated_without_mutation()

    def test_invalid_character_persisted_csrf_fails_closed(self) -> None:
        self._set_csrf("!" * 43)
        self._assert_unauthenticated_without_mutation()

    def test_non_text_persisted_csrf_fails_closed(self) -> None:
        # SQLite is dynamically typed even for a TEXT column; durable corruption
        # can therefore surface bytes unless the authorization boundary rechecks.
        self._set_csrf(sqlite3.Binary(b"A" * 43))
        self._assert_unauthenticated_without_mutation()


if __name__ == "__main__":
    unittest.main()
