"""Offline concurrent SQLite snapshot acceptance for #1075 optional inventory.

These tests use a disposable StateStore and a controlled second SQLite writer.
They never connect to a customer DB, network endpoint, target or authorization API.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from lightup.evidence_id_inventory_optin import (
    EvidenceIdInventory, inspect_evidence_id_shapes,
)
from lightup.state import StateStore


class EvidenceIdInventorySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="lightup-evidence-snapshot-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "snapshot.sqlite3"
        self.store = StateStore(self.path)
        self.run_id = self.store.create_run(
            "synthetic-offline-only", activation_mode="plan_only"
        )
        self.first_id = self.store.add_evidence(
            self.run_id, "synthetic", "offline", "fixture", b"first"
        )

    def _insert_writer_row(self, writer: sqlite3.Connection) -> None:
        writer.execute(
            "INSERT INTO evidence(evidence_id,run_id,capability_id,kind,source,"
            "sha256,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                str(uuid4()), self.run_id, "fixture", "synthetic", "test-only",
                "0" * 64, "{}", "2026-10-13T00:00:00+00:00",
            )
        )
        writer.commit()

    def _inventory_with_queued_write(self, action):
        # The injected test writer runs AFTER all schema checks but BEFORE
        # the evidence SELECT starts. A read transaction must already hold
        # the schema snapshot; a previously autocommit reader would include
        # the newly committed row or changed schema.
        raw_connect = sqlite3.connect
        fired = []
        class ProbeConnection(sqlite3.Connection):
            def execute(self, sql, parameters=(), /):
                if sql.startswith("SELECT typeof(evidence_id)"):
                    fired.append("before-evidence-select")
                    action()
                return super().execute(sql, parameters)

        def connect_probe(*args, **kwargs):
            if kwargs.get("uri") is True:
                return raw_connect(*args, factory=ProbeConnection, **kwargs)
            return raw_connect(*args, **kwargs)

        with patch("lightup.evidence_id_inventory_optin.sqlite3.connect", side_effect=connect_probe):
            aggregate = inspect_evidence_id_shapes(self.path)
        self.assertEqual(fired, ["before-evidence-select"])
        return aggregate

    def test_schema_and_row_counts_share_one_consistent_read_snapshot(self):
        with closing(sqlite3.connect(self.path)) as writer:
            counted = self._inventory_with_queued_write(
                lambda: self._insert_writer_row(writer)
            )
        self.assertEqual(counted, EvidenceIdInventory(1, 1, 0, 0))
        # A FRESH invocation must see the later committed writer row.
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(2, 2, 0, 0),
        )

    def test_schema_change_during_snapshot_cannot_reinterpret_evidence(self):
        with closing(sqlite3.connect(self.path)) as writer:
            def add_column():
                writer.execute("ALTER TABLE evidence ADD COLUMN future_extra TEXT")
                writer.commit()
            counted = self._inventory_with_queued_write(add_column)
        self.assertEqual(counted, EvidenceIdInventory(1, 1, 0, 0))
        # Additive schema changes remain acceptable on the next clean read.
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(1, 1, 0, 0),
        )

    def test_reopening_after_snapshot_sees_new_noncanonical_without_mutation(self):
        with closing(sqlite3.connect(self.path)) as writer:
            def insert_legacy():
                self._insert_writer_row(writer)
                writer.execute(
                    "UPDATE evidence SET evidence_id=? "
                    "WHERE evidence_id NOT IN (?)",
                    ("legacy-not-uuid4", self.first_id),
                )
                writer.commit()
            counted = self._inventory_with_queued_write(insert_legacy)
        self.assertEqual(counted, EvidenceIdInventory(1, 1, 0, 0))
        self.assertEqual(
            inspect_evidence_id_shapes(self.path),
            EvidenceIdInventory(2, 1, 1, 0),
        )


if __name__ == "__main__":
    unittest.main()
