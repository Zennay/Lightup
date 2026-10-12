"""Positive offline proof of a non-installed #910 serialization candidate.

The baseline DomainStore.authenticate RED canaries remain unchanged. These
synthetic checks never create users/sessions and never reach a network.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccountLockedError, DomainStore
from scope_910_serialized_lockout_reference import SerializedLoginReference


EMAIL = "reference-only@example.invalid"


class SerializedLoginReferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "isolated.sqlite3"
        self.store = DomainStore(self.db)
        self.reference = SerializedLoginReference(self.store)

    def _rows(self, email=EMAIL):
        with sqlite3.connect(self.db) as con:
            return con.execute(
                "SELECT failures,locked_until FROM login_failures WHERE email=?",
                (email,),
            ).fetchone()

    def _seed(self, count):
        with sqlite3.connect(self.db) as con:
            con.execute(
                "INSERT INTO login_failures(email,failures,locked_until) VALUES(?,?,NULL)",
                (EMAIL, count),
            )

    def _count_sessions(self):
        with sqlite3.connect(self.db) as con:
            return con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def _concurrent(self, names):
        with patch.object(self.store, "verify_password", return_value=None) as verifier:
            with ThreadPoolExecutor(max_workers=len(names)) as pool:
                futures = [
                    pool.submit(self.reference.authenticate, name, "synthetic-invalid")
                    for name in names
                ]
                results = [future.result(timeout=8) for future in futures]
        self.assertTrue(all(result is None for result in results))
        self.assertEqual(verifier.call_count, len(names))
        self.assertEqual(self._count_sessions(), 0)

    def test_two_concurrent_failures_persist_twice(self):
        self._concurrent((EMAIL, EMAIL))
        self.assertEqual(self._rows(), (2, None))

    def test_existing_one_plus_two_persists_three(self):
        self._seed(1)
        self._concurrent((EMAIL, EMAIL))
        self.assertEqual(self._rows(), (3, None))

    def test_case_variants_share_same_canonical_counter(self):
        self._concurrent(("  REFERENCE-ONLY@EXAMPLE.INVALID  ", EMAIL))
        self.assertEqual(self._rows(), (2, None))
        self.assertIsNone(self._rows("  REFERENCE-ONLY@EXAMPLE.INVALID  "))

    def test_prethreshold_three_plus_two_reaches_lockout(self):
        self._seed(3)
        self._concurrent((EMAIL, EMAIL))
        count, locked_until = self._rows()
        self.assertEqual(count, 0)
        self.assertIsNotNone(locked_until)
        with patch.object(self.store, "verify_password") as verifier:
            with self.assertRaises(AccountLockedError):
                self.reference.authenticate(EMAIL, "synthetic-invalid")
            verifier.assert_not_called()

    def test_four_plus_two_rejects_second_without_extra_verification(self):
        self._seed(4)
        with patch.object(self.store, "verify_password", return_value=None) as verifier:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(self.reference.authenticate, EMAIL, "synthetic-invalid")
                    for _ in range(2)
                ]
                outcomes = []
                for future in futures:
                    try:
                        outcomes.append(future.result(timeout=8))
                    except AccountLockedError:
                        outcomes.append("locked")
        self.assertEqual(outcomes.count(None), 1)
        self.assertEqual(outcomes.count("locked"), 1)
        self.assertEqual(verifier.call_count, 1)
        count, locked_until = self._rows()
        self.assertEqual(count, 0)
        self.assertIsNotNone(locked_until)
        self.assertEqual(self._count_sessions(), 0)

    def test_verifier_fault_rolls_back_without_changing_existing_failure(self):
        self._seed(2)
        with patch.object(
            self.store, "verify_password",
            side_effect=RuntimeError("isolated verifier exception"),
        ):
            with self.assertRaisesRegex(RuntimeError, "isolated verifier exception"):
                self.reference.authenticate(EMAIL, "synthetic-invalid")
        self.assertEqual(self._rows(), (2, None))
        self.assertEqual(self._count_sessions(), 0)

    def test_synthetic_success_clears_failure_counter_only(self):
        self._seed(2)
        dummy_synthetic_result = object()
        with patch.object(
            self.store, "verify_password", return_value=dummy_synthetic_result
        ) as verifier:
            self.assertIs(
                self.reference.authenticate(EMAIL, "synthetic-only"),
                dummy_synthetic_result,
            )
        verifier.assert_called_once_with(EMAIL, "synthetic-only")
        self.assertIsNone(self._rows())
        self.assertEqual(self._count_sessions(), 0)

    def test_rejects_malformed_types_without_database_side_effects(self):
        for bad_email, bad_password in ((None, "x"), (1, "x"), (EMAIL, None), (EMAIL, 1), ("  ", "x")):
            with self.subTest(bad_email=repr(bad_email), bad_password=repr(bad_password)):
                with self.assertRaises((TypeError, ValueError)):
                    self.reference.authenticate(bad_email, bad_password)
        self.assertIsNone(self._rows())
        self.assertEqual(self._count_sessions(), 0)


if __name__ == "__main__":
    unittest.main()
