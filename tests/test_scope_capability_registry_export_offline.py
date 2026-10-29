"""Regression tests for actual in-repository registry-to-review manifest export."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_drift_review import review_capability_registry_drift
from scripts.export_scope_capability_registry_offline import snapshot_manifest


class RegistryExporterTests(unittest.TestCase):
    def test_current_source_registry_is_reviewable_not_authorized(self):
        data = snapshot_manifest(get_capabilities())
        receipt = review_capability_registry_drift(data, data)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.merge_approved)
        self.assertEqual(len(json.loads(data)["capabilities"]), len(get_capabilities()))

    def test_entry_order_has_stable_manifest_bytes(self):
        records = get_capabilities()
        self.assertEqual(snapshot_manifest(records), snapshot_manifest(tuple(reversed(records))))

    def test_reject_non_tuple_registry(self):
        with self.assertRaises(ValueError):
            snapshot_manifest(list(get_capabilities()))

    def test_reject_empty_registry(self):
        with self.assertRaises(ValueError):
            snapshot_manifest(())

    def test_reject_record_subclass(self):
        class FakeCapability(Capability):
            pass
        original = get_capabilities()[0]
        with self.assertRaises(ValueError):
            snapshot_manifest((FakeCapability(
                original.capability_id, original.name, original.description,
                original.state, original.requires_explicit_activation
            ),))

    def test_reject_string_state_spoof(self):
        with self.assertRaises(ValueError):
            snapshot_manifest((Capability("safe-test", "Safe", "Synthetic", "planning"),))

    def test_reject_non_boolean_activation(self):
        with self.assertRaises(ValueError):
            snapshot_manifest((Capability("safe-test", "Safe", "Synthetic", CapabilityState.PLANNING, 1),))

    def test_reject_duplicate_capability(self):
        record = get_capabilities()[0]
        with self.assertRaises(ValueError):
            snapshot_manifest((record, record))

    def test_reject_noncanonical_capability_identifier(self):
        with self.assertRaises(ValueError):
            snapshot_manifest((Capability("invalid--name", "Safe", "Synthetic", CapabilityState.PLANNING),))

    def test_adding_capability_requires_hold(self):
        original = get_capabilities()
        new = Capability("synthetic-new", "New", "Synthetic only", CapabilityState.DISABLED)
        baseline = snapshot_manifest(original)
        candidate = snapshot_manifest(original + (new,))
        receipt = review_capability_registry_drift(baseline, candidate)
        self.assertEqual(receipt.status, "HOLD")
        self.assertEqual(receipt.changed_capabilities, ("synthetic-new",))
        self.assertFalse(receipt.permit_issued)

    def test_cli_exports_actual_registry_without_exit_zero(self):
        script = Path(__file__).resolve().parents[1] / "scripts/export_scope_capability_registry_offline.py"
        run = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertEqual(review_capability_registry_drift(run.stdout.encode(), run.stdout.encode()).status, "REVIEW_ONLY")

    def test_cli_rejects_args_without_stdout(self):
        script = Path(__file__).resolve().parents[1] / "scripts/export_scope_capability_registry_offline.py"
        run = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")


if __name__ == "__main__":
    unittest.main()
