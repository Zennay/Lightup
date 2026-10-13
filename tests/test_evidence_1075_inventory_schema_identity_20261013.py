"""Read-only schema-identity acceptance for opt-in evidence inventory (#1075).

Every fixture is a disposable local SQLite database. No stored identifiers,
client data, target requests, migrations or existing production source touched.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from lightup.evidence_id_inventory_optin import (
    EvidenceIdInventory,
    inspect_evidence_id_shapes,
)
from lightup.state import StateStore


_COLUMNS = (
    "evidence_id TEXT PRIMARY KEY, run_id TEXT, capability_id TEXT, "
    "kind TEXT, source TEXT, sha256 TEXT, metadata_json TEXT, created_at TEXT"
)


class EvidenceIdInventorySchemaIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="lightup-schema-review-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "synthetic-evidence.sqlite3"

    def _make(self, ddl: str, insert: str | None = None) -> None:
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(ddl)
            if insert is not None:
                db.execute(insert)
            db.commit()

    def _assert_schema_rejected_without_database_mutation(self) -> None:
        before = self.path.read_bytes()
        with self.assertRaisesRegex(
            ValueError, "evidence inventory unavailable or invalid SQLite schema"
        ) as error:
            inspect_evidence_id_shapes(self.path)
        self.assertNotIn(str(self.path), str(error.exception))
        self.assertEqual(self.path.read_bytes(), before)

    def test_genuine_state_store_schema_remains_accepted(self) -> None:
        store = StateStore(self.path)
        run = store.create_run("synthetic", activation_mode="plan_only")
        issued = store.add_evidence(
            run, "fixture", "synthetic", "offline", b"synthetic-only"
        )
        self.assertEqual(len(issued), 36)
        before = self.path.read_bytes()
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(1, 1, 0, 0),
        )
        self.assertEqual(self.path.read_bytes(), before)

    def test_compatibility_with_additive_evidence_column(self) -> None:
        store = StateStore(self.path)
        with store.connect() as db:
            db.execute("ALTER TABLE evidence ADD COLUMN future_optional_text TEXT")
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(0, 0, 0, 0),
        )

    def test_missing_evidence_table_is_not_valid_inventory(self) -> None:
        self._make("CREATE TABLE unrelated (evidence_id TEXT PRIMARY KEY)")
        self._assert_schema_rejected_without_database_mutation()

    def test_lookalike_view_must_not_be_executed_or_counted(self) -> None:
        self._make(
            "CREATE TABLE secrets(secret TEXT NOT NULL)",
            "INSERT INTO secrets VALUES ('synthetic-sensitive-value')",
        )
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                "CREATE VIEW evidence AS SELECT secret AS evidence_id FROM secrets"
            )
            db.commit()
        self._assert_schema_rejected_without_database_mutation()

    def test_valid_column_name_without_primary_key_is_not_valid_schema(self) -> None:
        self._make(
            "CREATE TABLE evidence (evidence_id TEXT, run_id TEXT, "
            "capability_id TEXT, kind TEXT, source TEXT, sha256 TEXT, "
            "metadata_json TEXT, created_at TEXT)"
        )
        self._assert_schema_rejected_without_database_mutation()

    def test_wrong_primary_key_affinity_is_not_valid_schema(self) -> None:
        self._make(
            "CREATE TABLE evidence (" +
            _COLUMNS.replace("evidence_id TEXT PRIMARY KEY", "evidence_id BLOB PRIMARY KEY") +
            ")"
        )
        self._assert_schema_rejected_without_database_mutation()

    def test_missing_required_metadata_column_is_not_valid_schema(self) -> None:
        self._make(
            "CREATE TABLE evidence (" +
            _COLUMNS.replace(", metadata_json TEXT", "") +
            ")"
        )
        self._assert_schema_rejected_without_database_mutation()

    def test_foreign_schema_with_only_evidence_id_is_not_valid_schema(self) -> None:
        self._make("CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY)")
        self._assert_schema_rejected_without_database_mutation()


if __name__ == "__main__":
    unittest.main()
