"""Genuine disposable SQLite reference-admission tests for evidence #1075.

All cases are synthetic. These tests do not install the adapter, issue grants
or touch targets. An injected synthetic checker is NOT real authorization.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from lightup.evidence_scoped_lookup_reference import (
    get_evidence_with_current_scope_reference as lookup,
)
from lightup.state import StateStore


class StringSubclass(str):
    pass


_NOT_GIVEN = object()


class RefScopedEvidenceAdmissionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-current-scope-reference-")
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "only-synthetic.sqlite3"
        self.store = StateStore(self.path)
        self.run_id = self.store.create_run(
            "synthetic-offline-fixture", activation_mode="plan_only"
        )
        self.capability_id = "synthetic-check"
        self.evidence_id = self.store.add_evidence(
            self.run_id, self.capability_id, "fixture", "local-test",
            b"synthetic immutable evidence", metadata={"fixture": "true"}
        )
        self.grants = []

    def _lookup(self, evidence_id=_NOT_GIVEN, *, checker=None, run_id=None, capability_id=None):
        if evidence_id is _NOT_GIVEN:
            evidence_id = self.evidence_id
        if checker is None:
            checker = lambda rid, cid, eid: True
        return lookup(
            self.store, evidence_id,
            trusted_run_id=self.run_id if run_id is None else run_id,
            trusted_capability_id=self.capability_id if capability_id is None else capability_id,
            check_current_permission=checker,
        )

    def _rows(self):
        with self.store.connect() as conn:
            return tuple(
                tuple(r) for r in conn.execute(
                    "SELECT evidence_id,run_id,capability_id,sha256,metadata_json "
                    "FROM evidence ORDER BY evidence_id"
                )
            )

    def test_valid_canonical_scoped_read_calls_checker_twice_and_preserves_rows(self):
        before = self._rows()
        def checker(run_id, capability, evidence):
            self.grants.append((run_id, capability, evidence))
            return True
        record = self._lookup(checker=checker)
        self.assertEqual(record.evidence_id, self.evidence_id)
        self.assertEqual(record.run_id, self.run_id)
        self.assertEqual(record.capability_id, self.capability_id)
        self.assertEqual(
            self.grants,
            [(self.run_id, self.capability_id, self.evidence_id)] * 2,
        )
        self.assertEqual(self._rows(), before)
        self.assertEqual(StateStore(self.path).get_evidence(self.evidence_id), record)

    def test_noncanonical_inputs_are_denied_before_checker_or_store_lookup(self):
        invalid = (
            None, True, b"x", 1,
            StringSubclass(self.evidence_id),
            self.evidence_id.upper(),
            self.evidence_id.replace("-", ""),
            "{" + self.evidence_id + "}",
            "urn:uuid:" + self.evidence_id,
            "12345678-1234-1234-8234-123456789abc",
            self.evidence_id + "\u200b",
        )
        before = self._rows()
        for candidate in invalid:
            with self.subTest(candidate=repr(candidate)):
                with patch.object(
                    self.store, "get_evidence",
                    side_effect=AssertionError("store access forbidden"),
                ) as reader:
                    with self.assertRaisesRegex(ValueError, "noncanonical"):
                        self._lookup(
                            candidate,
                            checker=lambda *_: self.fail(
                                "must reject malformed ID before scope callback"
                            ),
                        )
                    reader.assert_not_called()
        self.assertEqual(self._rows(), before)

    def test_first_current_scope_denial_prohibits_any_store_access(self):
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaisesRegex(PermissionError, "lookup denied"):
                self._lookup(checker=lambda *_: False)
            reader.assert_not_called()

    def test_truthy_nonbool_grant_values_are_not_permissions(self):
        for invalid_result in (1, "true", [], object(), None, 0):
            with self.subTest(grant=repr(invalid_result)):
                with patch.object(self.store, "get_evidence") as reader:
                    with self.assertRaises(PermissionError):
                        self._lookup(checker=lambda *_: invalid_result)
                    reader.assert_not_called()

    def test_scope_callback_exception_is_generic_and_never_hits_store(self):
        def failed_checker(*_):
            raise RuntimeError("SECRET_TENANT_ID_AND_GRANT")
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaises(PermissionError) as caught:
                self._lookup(checker=failed_checker)
            reader.assert_not_called()
        self.assertNotIn("SECRET_", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_missing_grant_callback_fails_closed(self):
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaises(PermissionError):
                lookup(
                    self.store, self.evidence_id,
                    trusted_run_id=self.run_id,
                    trusted_capability_id=self.capability_id,
                    check_current_permission=None,
                )
            reader.assert_not_called()

    def test_missing_canonical_evidence_still_requires_current_grant(self):
        missing = str(uuid4())
        if missing == self.evidence_id:
            missing = str(uuid4())
        seen = []
        with self.assertRaisesRegex(LookupError, "lookup unavailable") as caught:
            self._lookup(
                missing,
                checker=lambda *_: seen.append("admitted") or True,
            )
        self.assertEqual(seen, ["admitted"])
        self.assertNotIn(missing, str(caught.exception))
        self.assertEqual(self._rows()[0][0], self.evidence_id)

    def test_wrong_run_label_never_returns_foreign_run_evidence(self):
        foreign_run = str(uuid4())
        with self.assertRaisesRegex(PermissionError, "lookup denied"):
            self._lookup(run_id=foreign_run)
        self.assertEqual(self._rows()[0][1], self.run_id)

    def test_wrong_capability_label_never_returns_foreign_capability_evidence(self):
        with self.assertRaises(PermissionError):
            self._lookup(capability_id="other-capability")
        self.assertEqual(self._rows()[0][2], self.capability_id)

    def test_revoked_grant_after_sqlite_read_denies_result(self):
        calls = []
        def checker(*_):
            calls.append("checked")
            return len(calls) == 1
        before = self._rows()
        with self.assertRaises(PermissionError):
            self._lookup(checker=checker)
        self.assertEqual(calls, ["checked", "checked"])
        self.assertEqual(before, self._rows())

    def test_callback_exception_after_sqlite_read_is_sanitized(self):
        calls = []
        def checker(*_):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("SECRET_SECOND_CHECK")
            return True
        with self.assertRaises(PermissionError) as caught:
            self._lookup(checker=checker)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_noncanonical_run_and_capability_labels_denied_before_read(self):
        invalid_scopes = (
            (StringSubclass(self.run_id), self.capability_id),
            (self.run_id.upper(), self.capability_id),
            (self.run_id, StringSubclass(self.capability_id)),
            (self.run_id, self.capability_id + " "),
            (self.run_id, "\u0000"),
            (self.run_id, "x" * 129),
        )
        for run, cap in invalid_scopes:
            with self.subTest(run=repr(run), cap=repr(cap)):
                with patch.object(self.store, "get_evidence") as reader:
                    with self.assertRaises(PermissionError):
                        self._lookup(
                            run_id=run, capability_id=cap,
                            checker=lambda *_: self.fail("invalid scope reached checker"),
                        )
                    reader.assert_not_called()

    def test_invalid_metadata_decode_exposes_no_evidence_id_or_contents(self):
        with self.store.connect() as db:
            db.execute(
                "UPDATE evidence SET metadata_json=? WHERE evidence_id=?",
                ('{"SYNTHETIC_PRIVATE":', self.evidence_id),
            )
        before = self._rows()
        with self.assertRaisesRegex(LookupError, "lookup unavailable") as caught:
            self._lookup()
        self.assertNotIn(self.evidence_id, str(caught.exception))
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(before, self._rows())

    def test_sqlite_driver_error_does_not_leak_hidden_exception_context(self):
        # Error text is intentionally sensitive-looking, but MUST NOT survive
        # through __context__ of the sanitized public lookup error.
        with patch.object(
            self.store, "get_evidence",
            side_effect=sqlite3.OperationalError("SYNTHETIC_PRIVATE_SQL"),
        ):
            with self.assertRaisesRegex(LookupError, "lookup unavailable") as caught:
                self._lookup()
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_noncanonical_stored_historical_id_still_denied_without_migration(self):
        with self.store.connect() as db:
            db.execute(
                "UPDATE evidence SET evidence_id=? WHERE evidence_id=?",
                ("legacy-evidence-id", self.evidence_id),
            )
        before = self._rows()
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaises(ValueError):
                self._lookup(
                    "legacy-evidence-id",
                    checker=lambda *_: self.fail("invalid selector reached grant"),
                )
            reader.assert_not_called()
        self.assertEqual(before, self._rows())


if __name__ == "__main__":
    unittest.main()
