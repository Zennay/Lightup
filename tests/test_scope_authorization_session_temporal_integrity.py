from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import DomainStore


class SessionTemporalIntegrityBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = self.store.bootstrap_operator(
            "session-time@lightup.test",
            "Session Time",
            "correct-horse-battery",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _create_session(self, ttl_seconds: int = 8 * 3600) -> tuple[str, str]:
        return self.store.create_session(self.operator.user_id, ttl_seconds=ttl_seconds)

    def _row(self, token: str):
        with self.store._connect() as con:
            return con.execute(
                "SELECT token_hash,user_id,csrf_token,created_at,expires_at "
                "FROM sessions WHERE token_hash=?",
                (self.store._token_hash(token),),
            ).fetchone()

    def _set_times(self, token: str, *, created_at: str | None = None,
                   expires_at: str | None = None) -> None:
        assignments = []
        values = []
        if created_at is not None:
            assignments.append("created_at=?")
            values.append(created_at)
        if expires_at is not None:
            assignments.append("expires_at=?")
            values.append(expires_at)
        values.append(self.store._token_hash(token))
        with self.store._connect() as con:
            con.execute(
                f"UPDATE sessions SET {', '.join(assignments)} WHERE token_hash=?",
                tuple(values),
            )

    def _assert_unauthenticated_without_exception(self, token: str) -> None:
        try:
            resolved = self.store.session_context(token)
        except Exception as exc:  # the direct auth boundary must absorb corruption
            self.fail(f"session temporal corruption escaped auth boundary: {exc!r}")
        self.assertIsNone(resolved)

    def _assert_row_unchanged(self, token: str, before) -> None:
        after = self._row(token)
        self.assertIsNotNone(after)
        self.assertEqual(tuple(after), tuple(before))

    def test_canonical_maximum_lifetime_control_resolves(self) -> None:
        token, csrf = self._create_session(ttl_seconds=30 * 24 * 3600)
        resolved = self.store.session_context(token)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0].user_id, self.operator.user_id)
        self.assertEqual(resolved[1], csrf)

    def test_malformed_expiry_fails_closed_without_mutation(self) -> None:
        token, _ = self._create_session()
        self._set_times(token, expires_at="not-a-datetime")
        before = self._row(token)

        self._assert_unauthenticated_without_exception(token)
        self._assert_row_unchanged(token, before)

    def test_naive_expiry_fails_closed_without_mutation(self) -> None:
        token, _ = self._create_session()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1))
        self._set_times(token, expires_at=expires_at.replace(tzinfo=None).isoformat())
        before = self._row(token)

        self._assert_unauthenticated_without_exception(token)
        self._assert_row_unchanged(token, before)

    def test_future_created_at_fails_closed_without_mutation(self) -> None:
        token, _ = self._create_session()
        now = datetime.now(timezone.utc)
        self._set_times(
            token,
            created_at=(now + timedelta(hours=1)).isoformat(),
            expires_at=(now + timedelta(hours=2)).isoformat(),
        )
        before = self._row(token)

        self._assert_unauthenticated_without_exception(token)
        self._assert_row_unchanged(token, before)

    def test_overlong_persisted_lifetime_fails_closed_without_mutation(self) -> None:
        token, _ = self._create_session()
        row = self._row(token)
        created_at = datetime.fromisoformat(row["created_at"])
        self._set_times(
            token,
            expires_at=(created_at + timedelta(days=30, seconds=1)).isoformat(),
        )
        before = self._row(token)

        self._assert_unauthenticated_without_exception(token)
        self._assert_row_unchanged(token, before)

    def test_expiry_before_created_at_fails_closed_without_normalization(self) -> None:
        token, _ = self._create_session()
        now = datetime.now(timezone.utc)
        self._set_times(
            token,
            created_at=(now - timedelta(minutes=5)).isoformat(),
            expires_at=(now - timedelta(minutes=10)).isoformat(),
        )
        before = self._row(token)

        self._assert_unauthenticated_without_exception(token)
        self._assert_row_unchanged(token, before)


if __name__ == "__main__":
    unittest.main()
