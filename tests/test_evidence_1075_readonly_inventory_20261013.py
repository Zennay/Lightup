"""Disposable SQLite acceptance for the uninstalled #1075 identifier inventory."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from lightup.evidence_id_inventory_optin import (
    EvidenceIdInventory, inspect_evidence_id_shapes,
)
from lightup.state import StateStore


class EvidenceIdInventoryOptInSqliteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-id-inventory-lab-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "evidence-shapes.sqlite3"
        self.store = StateStore(self.path)
        self.run_id = self.store.create_run(
            "synthetic-no-target", activation_mode="plan_only"
        )

    def _insert(self, id_override=None):
        generated = self.store.add_evidence(
            self.run_id, "offline-inventory", "fixture", "test-only",
            b"synthetic payload", metadata={"lab": "only"}
        )
        if id_override is not None:
            with self.store.connect() as db:
                db.execute(
                    "UPDATE evidence SET evidence_id=? WHERE evidence_id=?",
                    (id_override, generated)
                )
        return generated

    def _all_rows(self):
        with self.store.connect() as db:
            return tuple(
                tuple(row) for row in db.execute(
                    "SELECT evidence_id, run_id, sha256, metadata_json "
                    "FROM evidence ORDER BY rowid"
                )
            )

    def test_empty_existing_database_produces_only_zero_counts(self):
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(0, 0, 0, 0),
        )

    def test_actual_issued_identifiers_are_canonical_after_reopening(self):
        self._insert()
        self._insert()
        before = self._all_rows()
        result = inspect_evidence_id_shapes(str(self.path))
        self.assertEqual(result, EvidenceIdInventory(2, 2, 0, 0))
        self.assertEqual(before, self._all_rows())
        self.assertEqual(result, inspect_evidence_id_shapes(self.path))
        self.assertEqual(self._all_rows(), before)

    def test_uppercase_compact_and_legacy_text_are_counted_not_rewritten(self):
        self._insert()
        self._insert(str(uuid4()).upper())
        self._insert(str(uuid4()).replace("-", ""))
        self._insert("legacy-evidence-reference")
        before = self._all_rows()
        result = inspect_evidence_id_shapes(self.path)
        self.assertEqual(result, EvidenceIdInventory(4, 1, 3, 0))
        self.assertEqual(self._all_rows(), before)

    def test_exact_length_wrong_uuid_version_variant_and_confusable_are_noncanonical(self):
        self._insert("12345678-1234-1234-8234-123456789abc")
        self._insert("12345678-1234-4234-0234-123456789abc")
        self._insert("12345678-1234-4234-8234-123456789abс")  # Cyrillic last char
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(3, 0, 3, 0),
        )

    def test_blob_and_null_sqlite_storage_classes_are_counted_without_coercion(self):
        self._insert(sqlite3.Binary(b"\x01\x02"))
        self._insert()
        with self.store.connect() as db:
            db.execute("UPDATE evidence SET evidence_id=NULL WHERE typeof(evidence_id)='text'")
        result = inspect_evidence_id_shapes(self.path)
        self.assertEqual(result, EvidenceIdInventory(2, 0, 0, 2))

    def test_overlong_legacy_value_not_materialized_into_inventory_result(self):
        very_long = "no-id-" + ("X" * 500_000)
        self._insert(very_long)
        result = inspect_evidence_id_shapes(self.path)
        self.assertEqual(result, EvidenceIdInventory(1, 0, 1, 0))
        self.assertNotIn("no-id-", repr(result))
        self.assertNotIn(very_long[:100], repr(result))

    def test_row_budget_rejects_without_partial_counts_or_writes(self):
        for _ in range(3):
            self._insert()
        before = self._all_rows()
        with self.assertRaisesRegex(ValueError, "row budget exceeded"):
            inspect_evidence_id_shapes(self.path, max_rows=2)
        self.assertEqual(before, self._all_rows())
        self.assertEqual(
            inspect_evidence_id_shapes(self.path, max_rows=3),
            EvidenceIdInventory(3, 3, 0, 0),
        )

    def test_max_rows_requires_exact_bounded_integer(self):
        self._insert()
        before = self._all_rows()
        for budget in (True, False, 0, -1, 100001, 1.5, "5"):
            with self.subTest(budget=budget):
                with self.assertRaisesRegex(ValueError, "row budget"):
                    inspect_evidence_id_shapes(self.path, max_rows=budget)
        self.assertEqual(before, self._all_rows())

    def test_missing_file_fails_without_creating_database(self):
        missing = self.path.parent / "not-created.sqlite3"
        with self.assertRaisesRegex(ValueError, "existing SQLite file"):
            inspect_evidence_id_shapes(missing)
        self.assertFalse(missing.exists())

    def test_invalid_sqlite_schema_raises_generic_no_content_error(self):
        other = self.path.parent / "unrelated.sqlite3"
        with sqlite3.connect(other) as db:
            db.execute("CREATE TABLE unrelated (secret TEXT)")
            db.execute("INSERT INTO unrelated VALUES (?)", ("SYNTHETIC_SECRET",))
        with self.assertRaisesRegex(ValueError, "invalid SQLite schema") as cm:
            inspect_evidence_id_shapes(other)
        self.assertNotIn("SYNTHETIC_SECRET", str(cm.exception))
        self.assertNotIn(str(other), str(cm.exception))

    def test_uri_punctuation_in_file_name_is_not_interpreted_as_query(self):
        unusual = self.path.parent / "evidence?shape#only.sqlite3"
        path_store = StateStore(unusual)
        run = path_store.create_run("synthetic", activation_mode="plan_only")
        path_store.add_evidence(run, "offline", "fixture", "test", b"x")
        self.assertEqual(
            inspect_evidence_id_shapes(unusual),
            EvidenceIdInventory(1, 1, 0, 0),
        )

    def test_result_is_an_immutable_aggregate_with_no_identifier_fields(self):
        issued = self._insert()
        result = inspect_evidence_id_shapes(self.path)
        self.assertEqual(set(result.__dataclass_fields__), {
            "total", "canonical_uuid4", "noncanonical_text", "nontext_or_null",
        })
        self.assertNotIn(issued, repr(result))
        with self.assertRaises((AttributeError, TypeError)):
            result.total = 99


if __name__ == "__main__":
    unittest.main()
