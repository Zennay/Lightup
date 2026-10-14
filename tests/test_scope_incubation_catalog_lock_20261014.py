"""Offline incubation closed-world catalog acceptance, against real source data."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_incubation_catalog_review import (
    _EXPECTED, review_incubation_catalog,
)
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_DENY = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")
_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_incubation_catalog_offline.py"


class ClosedWorldIncubationCatalogTests(unittest.TestCase):
    def setUp(self):
        self.records = get_capabilities()
        self.raw = snapshot_manifest(self.records)

    def check_no_authority(self, review):
        receipt = review.as_dict()
        for flag in _DENY:
            self.assertIs(receipt[flag], False)

    def modify(self, ident, **kwargs):
        return snapshot_manifest(tuple(
            replace(c, **kwargs) if c.capability_id == ident else c
            for c in self.records
        ))

    def test_real_checkout_canonical_catalog_is_review_only(self):
        result = review_incubation_catalog(self.raw)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.violations, ())
        self.assertEqual(len(_EXPECTED), len(self.records))
        self.assertTrue(result.metadata_fingerprint.startswith("sha256:"))
        self.check_no_authority(result)

    def test_unreviewed_new_planned_capability_holds(self):
        records = self.records + (
            Capability("new-synthetic-capability", "Synthetic", "Fixture",
                       CapabilityState.PLANNING),)
        result = review_incubation_catalog(snapshot_manifest(records))
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("new-synthetic-capability", "unreviewed_capability_added"), result.violations)
        self.check_no_authority(result)

    def test_unreviewed_new_lab_capability_also_holds(self):
        records = self.records + (
            Capability("new-synthetic-lab", "Synthetic lab", "Fixture", CapabilityState.LAB_ONLY),)
        result = review_incubation_catalog(snapshot_manifest(records))
        self.assertIn(("new-synthetic-lab", "unreviewed_capability_added"), result.violations)

    def test_unreviewed_new_disabled_capability_holds(self):
        records = self.records + (
            Capability("new-synthetic-disabled", "Disabled fixture", "Fixture",
                       CapabilityState.DISABLED),)
        self.assertEqual(review_incubation_catalog(snapshot_manifest(records)).status, "HOLD")

    def test_missing_ordinary_capability_holds(self):
        raw = snapshot_manifest(tuple(c for c in self.records if c.capability_id != "web-baseline"))
        result = review_incubation_catalog(raw)
        self.assertEqual(result.violations, (("web-baseline", "required_capability_missing"),))

    def test_missing_lab_capability_holds(self):
        raw = snapshot_manifest(tuple(c for c in self.records if c.capability_id != "wireless-lab"))
        result = review_incubation_catalog(raw)
        self.assertEqual(result.violations, (("wireless-lab", "required_capability_missing"),))

    def test_ordinary_planning_to_lab_holds(self):
        result = review_incubation_catalog(self.modify("web-baseline", state=CapabilityState.LAB_ONLY))
        self.assertIn(("web-baseline", "incubation_state_changed"), result.violations)
        self.check_no_authority(result)

    def test_ordinary_planning_to_disabled_holds(self):
        result = review_incubation_catalog(self.modify("web-baseline", state=CapabilityState.DISABLED))
        self.assertIn(("web-baseline", "incubation_state_changed"), result.violations)

    def test_lab_to_planning_and_disabled_both_hold(self):
        for state in (CapabilityState.PLANNING, CapabilityState.DISABLED):
            with self.subTest(state=state):
                result = review_incubation_catalog(self.modify("ot-lab", state=state))
                self.assertIn(("ot-lab", "incubation_state_changed"), result.violations)

    def test_any_activation_flag_disabled_holds(self):
        for ident in ("web-baseline", "ot-lab"):
            with self.subTest(ident=ident):
                result = review_incubation_catalog(self.modify(
                    ident, requires_explicit_activation=False))
                self.assertIn((ident, "explicit_activation_required"), result.violations)

    def test_mixed_violations_are_stable_and_sorted(self):
        altered = tuple(
            replace(c, state=CapabilityState.DISABLED,
                    requires_explicit_activation=False) if c.capability_id == "web-baseline"
            else c for c in self.records if c.capability_id != "ot-lab"
        )
        result = review_incubation_catalog(snapshot_manifest(altered))
        self.assertEqual(result.violations, (
            ("ot-lab", "required_capability_missing"),
            ("web-baseline", "explicit_activation_required"),
            ("web-baseline", "incubation_state_changed"),
        ))
        self.check_no_authority(result)

    def test_duplicate_and_unknown_json_fields_hold_without_details(self):
        duplicate = b'{"capabilities":[],"capabilities":[]}'
        for raw in (duplicate, b'{"capabilities":[],"x":1}', b'[]', b'{}', b""):
            with self.subTest(raw=raw):
                result = review_incubation_catalog(raw)
                self.assertEqual(result.status, "HOLD")
                self.assertIsNone(result.metadata_fingerprint)
                self.assertEqual(result.violations, ())
                self.check_no_authority(result)

    def test_legacy_three_field_metadata_holds(self):
        obj = json.loads(self.raw)
        for record in obj["capabilities"]:
            del record["name"]
            del record["description"]
        result = review_incubation_catalog(json.dumps(obj).encode("utf-8"))
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason, "invalid_or_incomplete_manifest")

    def test_partial_metadata_and_nonboolean_activation_hold(self):
        obj = json.loads(self.raw)
        del obj["capabilities"][0]["description"]
        self.assertEqual(review_incubation_catalog(json.dumps(obj).encode()).status, "HOLD")
        obj = json.loads(self.raw)
        obj["capabilities"][0]["requires_explicit_activation"] = 1
        self.assertEqual(review_incubation_catalog(json.dumps(obj).encode()).status, "HOLD")

    def test_reordering_records_does_not_create_false_drift(self):
        obj = json.loads(self.raw)
        obj["capabilities"].reverse()
        result = review_incubation_catalog(json.dumps(obj).encode())
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.metadata_fingerprint,
                         review_incubation_catalog(self.raw).metadata_fingerprint)

    def test_no_untrusted_description_or_name_leaks_in_receipt(self):
        raw = self.modify("web-baseline", description="Secret fixture marker",
                          state=CapabilityState.DISABLED)
        result = review_incubation_catalog(raw)
        receipt = json.dumps(result.as_dict())
        self.assertNotIn("Secret fixture marker", receipt)
        self.assertIn("web-baseline", receipt)

    def test_review_receipt_is_frozen(self):
        result = review_incubation_catalog(self.raw)
        with self.assertRaises(FrozenInstanceError):
            result.status = "AUTHORIZED"

    def test_wrong_python_inputs_fail_closed(self):
        for bad in (None, "", {}, [], bytearray(self.raw), b"\xff", b"x" * 33_000):
            with self.subTest(value=type(bad).__name__):
                result = review_incubation_catalog(bad)
                self.assertEqual(result.status, "HOLD")
                self.check_no_authority(result)

    def test_real_checkout_cli_review_is_nonzero_and_non_authorizing(self):
        done = subprocess.run([sys.executable, str(_SCRIPT)], capture_output=True,
                              text=True, timeout=15)
        self.assertEqual(done.returncode, 3, done.stderr)
        receipt = json.loads(done.stdout)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        for key in _DENY:
            self.assertIs(receipt[key], False)

    def test_cli_rejects_any_arguments(self):
        for argument in ("--activate", "--help", "127.0.0.1"):
            with self.subTest(argument=argument):
                done = subprocess.run([sys.executable, str(_SCRIPT), argument],
                                      capture_output=True, text=True, timeout=15)
                self.assertEqual(done.returncode, 2, done.stderr)
                receipt = json.loads(done.stdout)
                self.assertEqual(receipt["status"], "HOLD")
                for key in _DENY:
                    self.assertIs(receipt[key], False)


if __name__ == "__main__":
    unittest.main()
