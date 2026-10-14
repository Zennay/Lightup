"""Independent offline review: declared history must end at real local metadata."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from lightup.capabilities import CapabilityState, get_capabilities
from lightup.capability_registry_checkout_review import review_history_against_local_registry
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_history_against_checkout_offline.py"
_AUTHORITY = ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved")


def invoke(paths):
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *map(str, paths)],
        text=True, capture_output=True, timeout=15,
    )


class LocalRegistryCheckoutReviewTests(unittest.TestCase):
    def setUp(self):
        self.source = get_capabilities()
        self.actual = snapshot_manifest(self.source)
        self.first = self.source[0]
        self.synthetic_changed = snapshot_manifest(
            (replace(self.first, description=self.first.description + " confidential synthetic fixture"),)
            + self.source[1:]
        )

    def assert_no_authority(self, receipt):
        for field in _AUTHORITY:
            self.assertIs(receipt.as_dict()[field], False)

    def test_real_checkout_two_matching_snapshots_non_authorizing(self):
        result = review_history_against_local_registry((self.actual, self.actual), self.actual)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.history_status, "REVIEW_ONLY")
        self.assertTrue(result.latest_matches_local_registry)
        self.assertEqual(result.history_transition_count, 0)
        self.assertEqual(result.current_registry_changed_fields, ())
        self.assert_no_authority(result)

    def test_stale_history_equal_endpoints_is_hold(self):
        result = review_history_against_local_registry(
            (self.synthetic_changed, self.synthetic_changed), self.actual
        )
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.history_status, "REVIEW_ONLY")
        self.assertFalse(result.latest_matches_local_registry)
        self.assertEqual(result.reason, "latest_snapshot_differs_from_local_registry")
        self.assertEqual(result.as_dict()["current_registry_changed_fields"],
                         {self.first.capability_id: ["description"]})
        self.assertNotIn("confidential synthetic fixture", json.dumps(result.as_dict()))
        self.assert_no_authority(result)

    def test_real_checkout_history_reverts_and_stays_hold(self):
        result = review_history_against_local_registry(
            (self.actual, self.synthetic_changed, self.actual), self.actual
        )
        self.assertEqual(result.status, "HOLD")
        self.assertTrue(result.latest_matches_local_registry)
        self.assertEqual(result.history_transition_count, 2)
        self.assertEqual(result.reason, "declared_historical_drift_requires_review")
        self.assert_no_authority(result)

    def test_latest_mismatch_and_history_drift_both_hold(self):
        result = review_history_against_local_registry(
            (self.actual, self.synthetic_changed), self.actual
        )
        self.assertEqual(result.status, "HOLD")
        self.assertFalse(result.latest_matches_local_registry)
        self.assertEqual(result.history_transition_count, 1)
        self.assert_no_authority(result)

    def test_description_change_detected_without_echo(self):
        result = review_history_against_local_registry(
            (self.synthetic_changed, self.synthetic_changed), self.actual
        )
        blob = json.dumps(result.as_dict())
        self.assertNotIn(self.first.name, blob)
        self.assertNotIn(self.first.description, blob)
        self.assertIn('"description"', blob)

    def test_risk_state_mismatch_fails_closed(self):
        changed = snapshot_manifest(
            (replace(self.first, state=CapabilityState.LAB_ONLY),) + self.source[1:]
        )
        result = review_history_against_local_registry((changed, changed), self.actual)
        self.assertEqual(result.as_dict()["current_registry_changed_fields"],
                         {self.first.capability_id: ["state"]})
        self.assertEqual(result.status, "HOLD")

    def test_legacy_snapshot_metadata_not_silently_trusted(self):
        records = json.loads(self.actual)["capabilities"]
        for rec in records:
            del rec["name"]
            del rec["description"]
        legacy = json.dumps({"capabilities": records}).encode()
        result = review_history_against_local_registry((legacy, legacy), self.actual)
        self.assertEqual(result.status, "HOLD")
        self.assertFalse(result.latest_matches_local_registry)
        self.assertIn("description",
                      result.as_dict()["current_registry_changed_fields"][self.first.capability_id])
        self.assert_no_authority(result)

    def test_invalid_intermediate_erases_partial_data(self):
        result = review_history_against_local_registry(
            (self.actual, b'{"capabilities":[]}', self.actual), self.actual
        )
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.history_transition_count, 0)
        self.assertIsNone(result.local_registry_fingerprint)
        self.assertEqual(result.as_dict()["current_registry_changed_fields"], {})

    def test_bad_local_registry_is_hold(self):
        result = review_history_against_local_registry((self.actual, self.actual), b"{}")
        self.assertEqual(result.status, "HOLD")
        self.assertFalse(result.latest_matches_local_registry)
        self.assert_no_authority(result)

    def test_bad_container_and_primitive_types_are_hold(self):
        for history, current in (
            ([self.actual, self.actual], self.actual),
            ((self.actual,), self.actual),
            ((self.actual, self.actual), "not bytes"),
            ((self.actual, False), self.actual),
            ((), self.actual),
        ):
            with self.subTest(type=type(history).__name__):
                result = review_history_against_local_registry(history, current)
                self.assertEqual(result.status, "HOLD")
                self.assert_no_authority(result)

    def test_sixteen_history_snapshots_supported(self):
        result = review_history_against_local_registry((self.actual,) * 16, self.actual)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertTrue(result.latest_matches_local_registry)

    def test_seventeen_history_snapshots_denied(self):
        result = review_history_against_local_registry((self.actual,) * 17, self.actual)
        self.assertEqual(result.status, "HOLD")
        self.assertIsNone(result.latest_fingerprint)

    def test_cli_real_registry_matches_two_distinct_files(self):
        with tempfile.TemporaryDirectory() as folder:
            files = [Path(folder) / f"{i}.json" for i in range(2)]
            for f in files:
                f.write_bytes(self.actual)
            run = invoke(files)
            self.assertEqual(run.returncode, 3, run.stderr)
            receipt = json.loads(run.stdout)
            self.assertEqual(receipt["status"], "REVIEW_ONLY")
            self.assertIs(receipt["latest_matches_local_registry"], True)
            self.assertIs(receipt["execution_enabled"], False)

    def test_cli_stale_history_matches_itself_but_denied_against_source(self):
        with tempfile.TemporaryDirectory() as folder:
            files = [Path(folder) / f"{i}.json" for i in range(2)]
            for f in files:
                f.write_bytes(self.synthetic_changed)
            run = invoke(files)
            self.assertEqual(run.returncode, 2, run.stderr)
            receipt = json.loads(run.stdout)
            self.assertEqual(receipt["reason"], "latest_snapshot_differs_from_local_registry")
            self.assertIs(receipt["release_approved"], False)

    def test_cli_reverted_history_still_holds(self):
        with tempfile.TemporaryDirectory() as folder:
            files = [Path(folder) / f"{i}.json" for i in range(3)]
            for f, raw in zip(files, (self.actual, self.synthetic_changed, self.actual)):
                f.write_bytes(raw)
            run = invoke(files)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertTrue(json.loads(run.stdout)["latest_matches_local_registry"])
            self.assertEqual(json.loads(run.stdout)["history_transition_count"], 2)

    def test_cli_duplicate_physical_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "a.json"
            f.write_bytes(self.actual)
            run = invoke((f, f))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["permit_issued"], False)

    def test_cli_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "a.json", Path(folder) / "b.json"
            a.write_bytes(self.actual)
            try:
                os.link(a, b)
            except OSError:
                self.skipTest("hardlinks unsupported")
            run = invoke((a, b))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["execution_enabled"], False)

    def test_cli_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "a.json", Path(folder) / "b.json"
            a.write_bytes(self.actual)
            b.symlink_to(a)
            run = invoke((a, b))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["merge_approved"], False)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_cli_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "a.json", Path(folder) / "fifo"
            a.write_bytes(self.actual)
            os.mkfifo(b)
            run = invoke((a, b))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["execution_enabled"], False)

    def test_cli_argument_count_rejected(self):
        for args in ((), ("untrusted.json",)):
            result = invoke(args)
            self.assertEqual(result.returncode, 2)
            self.assertIs(json.loads(result.stdout)["authorization_verified"], False)


if __name__ == "__main__":
    unittest.main()
