"""Real disposable SQLite positive and negative controls for #170; no target I/O."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location(
    "check_scope_state_fk_offline", ROOT / "scripts" / "check_scope_state_fk_offline.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
from lightup.state import StateStore


class StrictStateStore(StateStore):
    @contextlib.contextmanager
    def connect(self):
        with super().connect() as con:
            con.execute("PRAGMA foreign_keys=ON")
            yield con


class PermissiveStateStore(StateStore):
    @contextlib.contextmanager
    def connect(self):
        with super().connect() as con:
            con.execute("PRAGMA foreign_keys=OFF")
            yield con


class ScopeStateForeignKeyOfflineTests(unittest.TestCase):
    def test_positive_known_good_state_connection(self):
        review = module.probe(StrictStateStore)
        self.assertEqual(review["status"], "REVIEW_ONLY")
        self.assertTrue(all(review["checks"].values()))
        self.assertEqual(review["reason"], "SYNTHETIC_BOUNDARY_VALID")

    def test_negative_known_bad_state_connection(self):
        review = module.probe(PermissiveStateStore)
        self.assertEqual(review["status"], "HOLD")
        for name in ("new_connection_fk_enabled", "orphan_evidence_denied",
                     "orphan_lease_denied", "no_orphan_rows_persisted"):
            self.assertFalse(review["checks"][name])
        self.assertTrue(review["checks"]["valid_run_evidence_stored"])

    def test_factory_error_never_exposes_private_path(self):
        def failing_factory(path):
            raise RuntimeError("PRIVATE_CLIENT_PATH:" + path)
        receipt = module.probe(failing_factory)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "PROBE_UNAVAILABLE")
        self.assertNotIn("PRIVATE_CLIENT_PATH", json.dumps(receipt))
        self.assertNotIn("/", json.dumps(receipt))

    def test_every_receipt_denies_authority(self):
        for factory in (StrictStateStore, PermissiveStateStore, lambda _: 0):
            with self.subTest(factory=factory):
                receipt = module.probe(factory)
                for flag in module.AUTHORITY:
                    self.assertIs(receipt[flag], False)

    def test_real_state_store_can_be_repaired_without_changing_oracle(self):
        # Owner may fix FK handling. Do not hardcode current vulnerability as PASS.
        receipt = module.probe(StateStore)
        self.assertIn(receipt["status"], ("REVIEW_ONLY", "HOLD"))
        if receipt["reason"] != "PROBE_UNAVAILABLE":
            self.assertEqual(receipt["status"] == "REVIEW_ONLY",
                             all(receipt["checks"].values()))

    def test_temp_db_deleted(self):
        requested = []
        def factory(path):
            requested.append(path)
            return StrictStateStore(path)
        self.assertEqual(module.probe(factory)["status"], "REVIEW_ONLY")
        self.assertEqual(len(requested), 1)
        self.assertFalse(os.path.exists(requested[0]))

    def test_evidence_denial_cannot_replace_lease_denial(self):
        class EvidenceRejectingStore(PermissiveStateStore):
            def add_evidence(self, run_id, *args, **kwargs):
                if run_id == "00000000-0000-4000-8000-000000000170":
                    raise sqlite3.IntegrityError("synthetic reject")
                return super().add_evidence(run_id, *args, **kwargs)
        review = module.probe(EvidenceRejectingStore)
        self.assertTrue(review["checks"]["orphan_evidence_denied"])
        self.assertFalse(review["checks"]["orphan_lease_denied"])
        self.assertEqual(review["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
