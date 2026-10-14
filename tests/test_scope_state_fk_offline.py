"""Disposable SQLite good/bad controls for issue #170; no target or operator DB IO."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import sqlite3
import sys
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
        for name in (
            "new_connection_fk_enabled", "orphan_evidence_denied",
            "orphan_lease_denied", "raw_orphan_evidence_denied",
            "no_orphan_rows_persisted", "connection_fk_consistent",
            "sqlite_foreign_key_check_clean", "delete_cascades_evidence",
            "delete_cascades_lease",
        ):
            self.assertFalse(review["checks"][name], name)
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
        # Source-owner #167/#170 may fix FK handling: never lock in a RED expectation.
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
                if run_id == module.MISSING_RUN:
                    raise sqlite3.IntegrityError("synthetic reject")
                return super().add_evidence(run_id, *args, **kwargs)
        review = module.probe(EvidenceRejectingStore)
        self.assertTrue(review["checks"]["orphan_evidence_denied"])
        self.assertFalse(review["checks"]["orphan_lease_denied"])
        self.assertFalse(review["checks"]["raw_orphan_evidence_denied"])
        self.assertEqual(review["status"], "HOLD")

    def test_lease_denial_cannot_replace_evidence_denial(self):
        class LeaseRejectingStore(PermissiveStateStore):
            def acquire_lease(self, run_id, *args, **kwargs):
                if run_id == module.MISSING_RUN:
                    raise sqlite3.IntegrityError("synthetic reject")
                return super().acquire_lease(run_id, *args, **kwargs)
        review = module.probe(LeaseRejectingStore)
        self.assertTrue(review["checks"]["orphan_lease_denied"])
        self.assertFalse(review["checks"]["orphan_evidence_denied"])
        self.assertFalse(review["checks"]["raw_orphan_evidence_denied"])
        self.assertEqual(review["status"], "HOLD")

    def test_high_level_denials_do_not_mask_raw_sqlite_bypass(self):
        class ValidateOnlyStore(PermissiveStateStore):
            def add_evidence(self, run_id, *args, **kwargs):
                if run_id == module.MISSING_RUN:
                    raise sqlite3.IntegrityError("synthetic reject")
                return super().add_evidence(run_id, *args, **kwargs)

            def acquire_lease(self, run_id, *args, **kwargs):
                if run_id == module.MISSING_RUN:
                    raise sqlite3.IntegrityError("synthetic reject")
                return super().acquire_lease(run_id, *args, **kwargs)

        result = module.probe(ValidateOnlyStore)
        self.assertTrue(result["checks"]["orphan_evidence_denied"])
        self.assertTrue(result["checks"]["orphan_lease_denied"])
        self.assertFalse(result["checks"]["raw_orphan_evidence_denied"])
        self.assertEqual(result["status"], "HOLD")

    def test_synthetic_run_authority_cannot_be_swapped(self):
        class ModeConfusedStore(StrictStateStore):
            def create_run(self, target, activation_mode="plan_only", authorization_ref=None):
                return super().create_run(target, activation_mode="lab_autonomous")
        result = module.probe(ModeConfusedStore)
        self.assertTrue(result["checks"]["new_connection_fk_enabled"])
        self.assertTrue(result["checks"]["valid_run_evidence_stored"])
        self.assertFalse(result["checks"]["registered_run_provenance_exact"])
        self.assertEqual(result["status"], "HOLD")

    def test_synthetic_run_target_cannot_be_swapped(self):
        class TargetConfusedStore(StrictStateStore):
            def create_run(self, target, activation_mode="plan_only", authorization_ref=None):
                return super().create_run("not-a-loopback-target", activation_mode=activation_mode)
        result = module.probe(TargetConfusedStore)
        self.assertTrue(result["checks"]["valid_run_evidence_stored"])
        self.assertFalse(result["checks"]["registered_run_provenance_exact"])
        self.assertEqual(result["status"], "HOLD")

    def test_missing_provenance_row_fails_closed_without_auth(self):
        class BadFactory:
            def __init__(self, _):
                raise sqlite3.OperationalError("customer-secret-path")
        result = module.probe(BadFactory)
        self.assertEqual(result["reason"], "PROBE_UNAVAILABLE")
        self.assertNotIn("customer-secret-path", json.dumps(result))
        self.assertFalse(any(result["checks"].values()))
        self.assertFalse(any(result[k] for k in module.AUTHORITY))

    def test_machine_receipt_names_and_flags_are_bounded(self):
        for factory in (StrictStateStore, PermissiveStateStore):
            result = module.probe(factory)
            self.assertEqual(tuple(result["checks"]), module.CHECK_NAMES)
            self.assertEqual(set(result) - {"checks", "status", "reason"}, set(module.AUTHORITY))
            self.assertTrue(all(type(x) is bool for x in result["checks"].values()))
            self.assertLess(len(json.dumps(result)), 1250)


if __name__ == "__main__":
    unittest.main()
