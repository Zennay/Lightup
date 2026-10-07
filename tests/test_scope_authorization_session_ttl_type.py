from __future__ import annotations

import tempfile
import unittest
from enum import IntEnum
from pathlib import Path

from lightup.domain import DomainStore


class _IntTTL(int):
    pass


class _EnumTTL(IntEnum):
    MINIMUM = 60


class SessionTTLCanonicalityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = self.store.bootstrap_operator(
            "op@lightup.test",
            "Operator",
            "correct-horse-battery",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _session_count(self) -> int:
        with self.store._connect() as con:
            return int(con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])

    def _assert_rejected_without_session(self, ttl_seconds: object) -> None:
        before = self._session_count()
        rejected = False
        try:
            self.store.create_session(self.operator.user_id, ttl_seconds)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            rejected = True
        after = self._session_count()
        self.assertEqual(
            (rejected, after),
            (True, before),
            f"non-canonical TTL {ttl_seconds!r} must fail before session persistence",
        )

    def test_exact_builtin_integer_bounds_remain_canonical(self) -> None:
        minimum_token, _ = self.store.create_session(
            self.operator.user_id,
            60,
        )
        maximum_token, _ = self.store.create_session(
            self.operator.user_id,
            30 * 24 * 3600,
        )

        self.assertIsNotNone(self.store.session_context(minimum_token))
        self.assertIsNotNone(self.store.session_context(maximum_token))
        self.assertEqual(self._session_count(), 2)

    def test_exact_builtin_integer_out_of_range_still_rejected(self) -> None:
        for ttl_seconds in (59, 30 * 24 * 3600 + 1):
            with self.subTest(ttl_seconds=ttl_seconds):
                self._assert_rejected_without_session(ttl_seconds)

    def test_numeric_equivalent_float_is_rejected_before_persistence(self) -> None:
        self._assert_rejected_without_session(60.0)

    def test_integer_subclass_is_rejected_before_persistence(self) -> None:
        self._assert_rejected_without_session(_IntTTL(60))

    def test_integer_enum_is_rejected_before_persistence(self) -> None:
        self._assert_rejected_without_session(_EnumTTL.MINIMUM)


if __name__ == "__main__":
    unittest.main()
