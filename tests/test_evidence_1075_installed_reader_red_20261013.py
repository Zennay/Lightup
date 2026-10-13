"""Producer-facing expected-RED SQLite boundary acceptance for evidence ID #1075.

The installed StateStore reader is intentionally UNCHANGED. The tests marked
expectedFailure are diagnostics of the current source-owner gap, not repairs.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from lightup.state import StateStore


class StrSubclass(str):
    pass


class EvidenceIdInstalledReaderRedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lightup-evidence-id-red-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.sqlite3"
        self.store = StateStore(self.path)
        run_id = self.store.create_run(
            target="synthetic-offline", activation_mode="plan_only",
        )
        self.canonical_id = self.store.add_evidence(
            run_id, "synthetic", "fixture", "local", b"immutable synthetic record",
        )

    def _db_snapshot(self):
        with self.store.connect() as db:
            return tuple(
                tuple(row) for row in db.execute(
                    "SELECT evidence_id, run_id, capability_id, kind, source, "
                    "sha256, metadata_json, created_at FROM evidence ORDER BY evidence_id"
                ).fetchall()
            )

    def _seed_noncanonical_historical_id(self, identifier):
        with self.store.connect() as db:
            db.execute(
                "UPDATE evidence SET evidence_id=? WHERE evidence_id=?",
                (identifier, self.canonical_id),
            )

    def test_canonical_issuer_id_still_roundtrips_through_real_reader(self):
        before = self._db_snapshot()
        record = self.store.get_evidence(self.canonical_id)
        self.assertEqual(record.evidence_id, self.canonical_id)
        self.assertEqual(StateStore(self.path).get_evidence(self.canonical_id), record)
        self.assertEqual(self._db_snapshot(), before)

    def test_absent_but_canonical_identifier_stays_unknown_without_writes(self):
        missing = str(uuid4())
        while missing == self.canonical_id:
            missing = str(uuid4())
        before = self._db_snapshot()
        with self.assertRaises(KeyError):
            self.store.get_evidence(missing)
        self.assertEqual(self._db_snapshot(), before)

    @unittest.expectedFailure
    def test_default_reader_must_refuse_noncanonical_historical_id(self):
        self._seed_noncanonical_historical_id("historical-invalid-evidence-ref")
        before = self._db_snapshot()
        with self.assertRaisesRegex(ValueError, "evidence.*id|identifier"):
            self.store.get_evidence("historical-invalid-evidence-ref")
        self.assertEqual(self._db_snapshot(), before)

    @unittest.expectedFailure
    def test_default_reader_must_refuse_uuid4_uppercase_alias_even_if_persisted(self):
        self._seed_noncanonical_historical_id(self.canonical_id.upper())
        before = self._db_snapshot()
        with self.assertRaisesRegex(ValueError, "evidence.*id|identifier"):
            self.store.get_evidence(self.canonical_id.upper())
        self.assertEqual(self._db_snapshot(), before)

    @unittest.expectedFailure
    def test_default_reader_must_refuse_str_subclass_for_real_row(self):
        before = self._db_snapshot()
        with self.assertRaisesRegex(ValueError, "evidence.*id|identifier"):
            self.store.get_evidence(StrSubclass(self.canonical_id))
        self.assertEqual(self._db_snapshot(), before)

    @unittest.expectedFailure
    def test_default_reader_must_refuse_type_confusion_before_database_access(self):
        # A corrected producer must validate before entering the SQLite context;
        # the current producer raises incidental AttributeError for None instead.
        calls = []
        def forbidden_connect():
            calls.append("database-open")
            raise AssertionError("invalid selector must not touch the database")
        with patch.object(self.store, "connect", forbidden_connect):
            with self.assertRaisesRegex(ValueError, "evidence.*id|identifier"):
                self.store.get_evidence(None)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
