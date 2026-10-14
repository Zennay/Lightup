"""Regression for non-authorizing, privacy-safe incubation field change receipts."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_incubation_field_review import (
    _EXPECTED_FIELDS, review_incubation_fields,
)
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_incubation_fields_offline.py"
_NON_AUTH = ("authorization_verified", "permit_issued", "execution_enabled",
             "merge_approved", "release_approved")


class IncubationFieldDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.records = get_capabilities()
        self.raw = snapshot_manifest(self.records)

    def assert_denied_authority(self, review):
        for key in _NON_AUTH:
            self.assertIs(review.as_dict()[key], False, key)

    def mutate(self, ident="web-baseline", **fields):
        records = tuple(replace(c, **fields) if c.capability_id == ident else c
                        for c in self.records)
        return snapshot_manifest(records)

    def test_actual_full_registry_matches_checked_in_reference(self):
        review = review_incubation_fields(self.raw)
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertEqual(review.reason, "unchanged_reviewed_fields_only")
        self.assertEqual(review.changed_fields, ())
        self.assertEqual(len(_EXPECTED_FIELDS), 31)
        self.assertEqual(set(_EXPECTED_FIELDS), {c.capability_id for c in self.records})
        self.assertTrue(review.catalog_fingerprint.startswith("sha256:"))
        self.assert_denied_authority(review)

    def test_name_only_reports_fixed_field_label(self):
        review = review_incubation_fields(self.mutate(name="Sensitive fixture alpha"))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.changed_fields, (("web-baseline", ("name",)),))
        self.assertEqual(review.reason, "metadata_fields_require_review")
        self.assert_denied_authority(review)
        self.assertNotIn("Sensitive fixture alpha", json.dumps(review.as_dict()))

    def test_description_only_reports_fixed_field_label(self):
        review = review_incubation_fields(
            self.mutate(description="Sensitive fixture beta"))
        self.assertEqual(review.changed_fields, (("web-baseline", ("description",)),))
        self.assertEqual(review.status, "HOLD")
        self.assertNotIn("Sensitive fixture beta", json.dumps(review.as_dict()))

    def test_both_fields_reported_in_stable_field_order(self):
        review = review_incubation_fields(
            self.mutate(name="Changed name", description="Changed description"))
        self.assertEqual(review.changed_fields, (
            ("web-baseline", ("name", "description")),
        ))

    def test_multiple_ids_sorted_canonically(self):
        altered = tuple(
            replace(c, name="Synthetic later name") if c.capability_id == "web-baseline"
            else replace(c, description="Synthetic earlier description")
            if c.capability_id == "api-baseline" else c for c in self.records
        )
        review = review_incubation_fields(snapshot_manifest(altered))
        self.assertEqual(review.changed_fields, (
            ("api-baseline", ("description",)),
            ("web-baseline", ("name",)),
        ))
        self.assert_denied_authority(review)

    def test_changed_state_keeps_parent_hold_without_misleading_fields(self):
        review = review_incubation_fields(self.mutate(state=CapabilityState.DISABLED))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.reason, "invalid_or_changed_catalog_boundary")
        self.assertEqual(review.changed_fields, ())
        self.assertIsNone(review.catalog_fingerprint)

    def test_changed_activation_keeps_parent_hold(self):
        review = review_incubation_fields(self.mutate(requires_explicit_activation=False))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.changed_fields, ())

    def test_added_unknown_catalog_entry_denied_atomically(self):
        entries = self.records + (
            Capability("unknown-fixture", "Unknown", "Synthetic", CapabilityState.PLANNING),
        )
        review = review_incubation_fields(snapshot_manifest(entries))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.changed_fields, ())
        self.assertIsNone(review.catalog_fingerprint)

    def test_missing_known_entry_denied_atomically(self):
        entries = tuple(c for c in self.records if c.capability_id != "ot-lab")
        review = review_incubation_fields(snapshot_manifest(entries))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.changed_fields, ())

    def test_invalid_and_legacy_metadata_have_no_diagnostic_leaks(self):
        for raw in (b"", b"{}", b"[]", b'{"capabilities":[]}',
                    b'{"capabilities":[],"capabilities":[]}', b"\xff",
                    b"x" * 32769, None, "foo"):
            with self.subTest(raw=str(type(raw))):
                review = review_incubation_fields(raw)
                self.assertEqual(review.status, "HOLD")
                self.assertEqual(review.changed_fields, ())
                self.assertIsNone(review.catalog_fingerprint)
                self.assert_denied_authority(review)
        values = json.loads(self.raw)
        for cap in values["capabilities"]:
            cap.pop("description")
            cap.pop("name")
        review = review_incubation_fields(json.dumps(values).encode())
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.changed_fields, ())

    def test_reordered_snapshot_does_not_false_alarm(self):
        data = json.loads(self.raw)
        data["capabilities"].reverse()
        review = review_incubation_fields(json.dumps(data).encode())
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertEqual(review.changed_fields, ())
        self.assert_denied_authority(review)

    def test_review_receipt_dataclass_is_frozen(self):
        review = review_incubation_fields(self.raw)
        with self.assertRaises(FrozenInstanceError):
            review.status = "AUTHORIZED"

    def test_real_cli_current_source_exits_nonzero_review(self):
        p = subprocess.run([sys.executable, str(_SCRIPT)], capture_output=True,
                           text=True, timeout=15)
        self.assertEqual(p.returncode, 3, p.stderr)
        output = json.loads(p.stdout)
        self.assertEqual(output["status"], "REVIEW_ONLY")
        self.assertEqual(output["changed_fields"], {})
        for key in _NON_AUTH:
            self.assertIs(output[key], False)

    def test_cli_rejects_arguments_and_target_like_input(self):
        for arg in ("--help", "--activate", "https://synthetic.invalid", "../x"):
            with self.subTest(arg=arg):
                p = subprocess.run([sys.executable, str(_SCRIPT), arg],
                                   capture_output=True, text=True, timeout=15)
                self.assertEqual(p.returncode, 2, p.stderr)
                output = json.loads(p.stdout)
                self.assertEqual(output["status"], "HOLD")
                for flag in _NON_AUTH:
                    self.assertIs(output[flag], False)


if __name__ == "__main__":
    unittest.main()
