"""Fail-closed three-checker evidence coherence acceptance for #1366.

Patches are synthetic contradiction probes. The positive cases invoke all three
real reviewers on actual source snapshots and do no target/network work.
"""
from __future__ import annotations

import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_incubation_catalog_review import review_incubation_catalog
from lightup.capability_registry_incubation_review import review_incubation_capability_posture
from lightup.capability_registry_incubation_field_review import review_incubation_fields
from lightup.capability_registry_incubation_dossier import review_atomic_incubation_dossier
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_TARGET = "lightup.capability_registry_incubation_dossier."
_FIELDS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


class AtomicDossierCoherenceTests(unittest.TestCase):
    def setUp(self):
        self.records = get_capabilities()
        self.raw = snapshot_manifest(self.records)

    def mutated(self, ident="web-baseline", **fields):
        return snapshot_manifest(tuple(
            replace(c, **fields) if c.capability_id == ident else c
            for c in self.records
        ))

    def assert_atomic_hold(self, result):
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason, "invalid_or_incoherent_registry_dossier")
        self.assertEqual((result.catalog_status, result.posture_status, result.fields_status),
                         ("HOLD",) * 3)
        self.assertIsNone(result.fingerprint)
        self.assertEqual(result.catalog_violations, ())
        self.assertEqual(result.posture_violations, ())
        self.assertEqual(result.changed_fields, ())
        for field in _FIELDS:
            self.assertIs(result.as_dict()[field], False, field)

    def test_unmodified_real_source_remains_review_only(self):
        result = review_atomic_incubation_dossier(self.raw)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.catalog_violations, ())
        self.assertEqual(result.posture_violations, ())
        self.assertEqual(result.changed_fields, ())
        for field in _FIELDS:
            self.assertIs(result.as_dict()[field], False, field)

    def test_real_shuffled_registry_order_remains_review_only(self):
        import json
        rows = json.loads(self.raw)
        rows["capabilities"].reverse()
        result = review_atomic_incubation_dossier(json.dumps(rows).encode("utf-8"))
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.changed_fields, ())
        self.assertEqual(result.catalog_violations, ())

    def test_real_name_and_description_diff_still_reports_privacy_safe_hold(self):
        for name, fields in (
            ("name", {"name": "Synthetic secret new name"}),
            ("description", {"description": "Synthetic secret new description"}),
            ("both", {"name": "Synthetic secret n", "description": "Synthetic secret d"}),
        ):
            with self.subTest(name=name):
                result = review_atomic_incubation_dossier(self.mutated(**fields))
                self.assertEqual(result.status, "HOLD")
                self.assertEqual(result.reason, "one_or_more_checks_require_review")
                self.assertEqual(result.posture_status, "REVIEW_ONLY")
                self.assertEqual(result.catalog_status, "HOLD")
                self.assertEqual(result.fields_status, "HOLD")
                self.assertTrue(result.changed_fields)
                self.assertNotIn("Synthetic secret", json.dumps(result.as_dict()))

    def test_real_state_change_still_reports_catalog_hold(self):
        result = review_atomic_incubation_dossier(
            self.mutated(state=CapabilityState.DISABLED))
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("web-baseline", "incubation_state_changed"), result.catalog_violations)
        self.assertEqual(result.posture_status, "REVIEW_ONLY")

    def test_real_sensitive_lab_state_change_reports_both_hold(self):
        result = review_atomic_incubation_dossier(
            self.mutated("wireless-lab", state=CapabilityState.PLANNING))
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("wireless-lab", "incubation_state_changed"), result.catalog_violations)
        self.assertIn(("wireless-lab", "sensitive_lab_capability_reclassified"),
                      result.posture_violations)

    def test_real_activation_change_reports_both_hold(self):
        result = review_atomic_incubation_dossier(
            self.mutated(requires_explicit_activation=False))
        self.assertEqual(result.status, "HOLD")
        self.assertIn(("web-baseline", "explicit_activation_required"), result.catalog_violations)
        self.assertIn(("web-baseline", "explicit_activation_required"),
                      result.posture_violations)

    def test_real_added_and_missing_capabilities_still_hold(self):
        extra = Capability("new-synthetic", "Synthetic", "Synthetic description",
                           CapabilityState.PLANNING)
        for records in (
            self.records + (extra,),
            tuple(c for c in self.records if c.capability_id != "ot-lab"),
        ):
            with self.subTest(length=len(records)):
                result = review_atomic_incubation_dossier(snapshot_manifest(records))
                self.assertEqual(result.status, "HOLD")
                self.assertEqual(result.reason, "one_or_more_checks_require_review")
                self.assertEqual(result.changed_fields, ())

    def test_forged_catalog_review_only_with_violation_never_green(self):
        original = review_incubation_catalog(self.raw)
        fake = replace(original, violations=(("web-baseline", "incubation_state_changed"),))
        with patch(_TARGET + "review_incubation_catalog", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_catalog_review_only_with_wrong_reason_never_green(self):
        original = review_incubation_catalog(self.raw)
        fake = replace(original, reason="catalog_change_requires_independent_review")
        with patch(_TARGET + "review_incubation_catalog", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_posture_review_only_with_violation_never_green(self):
        original = review_incubation_capability_posture(self.raw)
        fake = replace(original, violations=(("wireless-lab", "required_lab_capability_missing"),))
        with patch(_TARGET + "review_incubation_capability_posture", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_posture_review_only_with_wrong_reason_never_green(self):
        original = review_incubation_capability_posture(self.raw)
        fake = replace(original, reason="incubation_posture_requires_independent_review")
        with patch(_TARGET + "review_incubation_capability_posture", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_posture_hold_without_violations_never_green(self):
        original = review_incubation_capability_posture(self.raw)
        fake = replace(original, status="HOLD",
                       reason="incubation_posture_requires_independent_review")
        with patch(_TARGET + "review_incubation_capability_posture", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_fields_review_only_with_wrong_reason_never_green(self):
        original = review_incubation_fields(self.raw)
        fake = replace(original, reason="metadata_fields_require_review")
        with patch(_TARGET + "review_incubation_fields", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_catalog_semantic_hold_without_field_diff_never_green(self):
        original = review_incubation_catalog(self.raw)
        fake = replace(original, status="HOLD",
                       reason="semantic_metadata_differs_from_reviewed_reference")
        with patch(_TARGET + "review_incubation_catalog", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_catalog_mismatched_unknown_code_without_violation_denied(self):
        original = review_incubation_catalog(self.raw)
        fake = replace(original, status="HOLD",
                       reason="catalog_change_requires_independent_review")
        with patch(_TARGET + "review_incubation_catalog", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(self.raw))

    def test_forged_posture_violation_unsupported_by_real_catalog_denied(self):
        raw = self.mutated(state=CapabilityState.DISABLED)
        original = review_incubation_capability_posture(raw)
        fake = replace(
            original, status="HOLD",
            reason="incubation_posture_requires_independent_review",
            violations=(("wireless-lab", "required_lab_capability_missing"),),
        )
        with patch(_TARGET + "review_incubation_capability_posture", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(raw))

    def test_forged_semantic_hold_with_wrong_posture_denied(self):
        raw = self.mutated(name="Secret name")
        original = review_incubation_capability_posture(raw)
        fake = replace(
            original, status="HOLD",
            reason="incubation_posture_requires_independent_review",
            violations=(("web-baseline", "explicit_activation_required"),),
        )
        with patch(_TARGET + "review_incubation_capability_posture", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(raw))

    def test_forged_fields_hold_with_wrong_reason_denied(self):
        raw = self.mutated(name="Synthetic secret field")
        original = review_incubation_fields(raw)
        fake = replace(original, reason="invalid_or_changed_catalog_boundary")
        with patch(_TARGET + "review_incubation_fields", return_value=fake):
            self.assert_atomic_hold(review_atomic_incubation_dossier(raw))

    def test_no_free_text_leaks_in_failure_receipt(self):
        raw = self.mutated(name="SUPER_SECRET_CUSTOMER_STRING")
        original = review_incubation_fields(raw)
        fake = replace(original, reason="invalid_or_changed_catalog_boundary")
        with patch(_TARGET + "review_incubation_fields", return_value=fake):
            result = review_atomic_incubation_dossier(raw)
        self.assert_atomic_hold(result)
        self.assertNotIn("SUPER_SECRET_CUSTOMER_STRING", json.dumps(result.as_dict()))

    def test_bad_manifest_stays_atomic_hold(self):
        for raw in (b"", b"{}", b"\xff", b"[]" , "not bytes", None):
            with self.subTest(type=type(raw).__name__):
                self.assert_atomic_hold(review_atomic_incubation_dossier(raw))


if __name__ == "__main__":
    unittest.main()
