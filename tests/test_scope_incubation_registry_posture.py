"""Real-registry and adversarial offline incubation metadata regressions."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from lightup.capabilities import CapabilityState, get_capabilities
from lightup.capability_registry_incubation_review import review_incubation_capability_posture
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_incubation_registry_offline.py"
_LABS = frozenset({
    "ot-lab", "wireless-lab", "social-engineering-lab",
    "human-layer-lab", "physical-security-lab",
})
_DENY = ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved")


def mutate(records, name, **updates):
    return tuple(replace(entry, **updates) if entry.capability_id == name else entry for entry in records)


class RegistryIncubationPostureTests(unittest.TestCase):
    def setUp(self):
        self.source = get_capabilities()
        self.raw = snapshot_manifest(self.source)

    def assert_not_authority(self, receipt):
        for field in _DENY:
            self.assertIs(receipt.as_dict()[field], False)

    def test_actual_checkout_stays_plan_lab_only(self):
        result = review_incubation_capability_posture(self.raw)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.violations, ())
        self.assertTrue(result.metadata_fingerprint.startswith("sha256:"))
        self.assert_not_authority(result)

    def test_no_false_activation_flags_in_current_source(self):
        for entry in self.source:
            self.assertIs(entry.requires_explicit_activation, True)

    def test_all_sensitive_labs_are_present_and_lab_only(self):
        all_names = {entry.capability_id for entry in self.source}
        self.assertTrue(_LABS <= all_names)
        self.assertTrue(all(entry.state is CapabilityState.LAB_ONLY for entry in self.source
                            if entry.capability_id in _LABS))

    def test_equal_unsafe_snapshots_never_safe_for_posture(self):
        unsafe = snapshot_manifest(mutate(self.source, "web-baseline", requires_explicit_activation=False))
        result = review_incubation_capability_posture(unsafe)
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("web-baseline", "explicit_activation_required"), result.violations)
        self.assert_not_authority(result)

    def test_sensitive_lab_activation_false_holds(self):
        raw = snapshot_manifest(mutate(self.source, "wireless-lab", requires_explicit_activation=False))
        result = review_incubation_capability_posture(raw)
        self.assertIn(("wireless-lab", "explicit_activation_required"), result.violations)
        self.assertEqual(result.status, "HOLD")

    def test_sensitive_lab_reclassified_to_planning_holds(self):
        raw = snapshot_manifest(mutate(self.source, "ot-lab", state=CapabilityState.PLANNING))
        result = review_incubation_capability_posture(raw)
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("ot-lab", "sensitive_lab_capability_reclassified"), result.violations)
        self.assert_not_authority(result)

    def test_sensitive_lab_reclassified_to_disabled_also_requires_review(self):
        raw = snapshot_manifest(mutate(self.source, "human-layer-lab", state=CapabilityState.DISABLED))
        result = review_incubation_capability_posture(raw)
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("human-layer-lab", "sensitive_lab_capability_reclassified"), result.violations)

    def test_missing_lab_cannot_be_hidden(self):
        missing = tuple(entry for entry in self.source if entry.capability_id != "physical-security-lab")
        result = review_incubation_capability_posture(snapshot_manifest(missing))
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.violations, (("physical-security-lab", "required_lab_capability_missing"),))

    def test_multiple_violations_sorted_deterministically(self):
        records = mutate(self.source, "wireless-lab", state=CapabilityState.PLANNING,
                         requires_explicit_activation=False)
        records = mutate(records, "web-baseline", requires_explicit_activation=False)
        result = review_incubation_capability_posture(snapshot_manifest(records))
        self.assertEqual(result.violations, (
            ("web-baseline", "explicit_activation_required"),
            ("wireless-lab", "explicit_activation_required"),
            ("wireless-lab", "sensitive_lab_capability_reclassified"),
        ))

    def test_legacy_three_field_metadata_fails_closed(self):
        parsed = json.loads(self.raw)
        for entry in parsed["capabilities"]:
            del entry["name"]
            del entry["description"]
        result = review_incubation_capability_posture(json.dumps(parsed).encode())
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason, "invalid_or_incomplete_registry_metadata")
        self.assertIsNone(result.metadata_fingerprint)
        self.assert_not_authority(result)

    def test_partial_v2_metadata_fails_closed(self):
        parsed = json.loads(self.raw)
        del parsed["capabilities"][0]["description"]
        result = review_incubation_capability_posture(json.dumps(parsed).encode())
        self.assertEqual(result.status, "HOLD")
        self.assertIsNone(result.metadata_fingerprint)

    def test_type_spoofed_boolean_fails_closed(self):
        parsed = json.loads(self.raw)
        parsed["capabilities"][0]["requires_explicit_activation"] = 1
        result = review_incubation_capability_posture(json.dumps(parsed).encode())
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.violations, ())

    def test_source_free_text_never_leaks_to_receipt(self):
        raw = snapshot_manifest(mutate(
            self.source, "web-baseline", description="Synthetic confidential fixture",
            requires_explicit_activation=False,
        ))
        receipt = review_incubation_capability_posture(raw).as_dict()
        self.assertNotIn("Synthetic confidential fixture", json.dumps(receipt))
        self.assertIn("web-baseline", json.dumps(receipt))

    def test_invalid_empty_and_oversized_bytes_denied(self):
        for bad in (b"", b"{}", b"[]", b"x" * 33000, b"\xff"):
            with self.subTest(length=len(bad)):
                review = review_incubation_capability_posture(bad)
                self.assertEqual(review.status, "HOLD")
                self.assert_not_authority(review)

    def test_unexpected_active_state_rejected_by_parser(self):
        parsed = json.loads(self.raw)
        parsed["capabilities"][0]["state"] = "target_active"
        review = review_incubation_capability_posture(json.dumps(parsed).encode())
        self.assertEqual(review.status, "HOLD")
        self.assertIsNone(review.metadata_fingerprint)

    def test_receipt_is_immutable(self):
        review = review_incubation_capability_posture(self.raw)
        with self.assertRaises(FrozenInstanceError):
            review.status = "GRANTED"

    def test_real_checkout_cli_success_only_review_exit_three(self):
        run = subprocess.run([sys.executable, str(_SCRIPT)], capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 3, run.stderr)
        data = json.loads(run.stdout)
        self.assertEqual(data["status"], "REVIEW_ONLY")
        for field in _DENY:
            self.assertIs(data[field], False)

    def test_cli_rejects_args_even_help(self):
        for args in (("--help",), ("--allow-active",)):
            with self.subTest(args=args):
                run = subprocess.run([sys.executable, str(_SCRIPT), *args],
                                     capture_output=True, text=True, timeout=15)
                self.assertEqual(run.returncode, 2, run.stderr)
                data = json.loads(run.stdout)
                self.assertEqual(data["status"], "HOLD")
                for field in _DENY:
                    self.assertIs(data[field], False)


if __name__ == "__main__":
    unittest.main()
