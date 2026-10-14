"""In-process and actual CLI atomic incubation review dossier regressions."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_incubation_dossier import (
    review_atomic_incubation_dossier,
)
from lightup.capability_registry_incubation_field_review import review_incubation_fields
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_CLI = Path(__file__).resolve().parents[1] / "scripts/review_scope_incubation_dossier_offline.py"
_FALSE_FIELDS = ("authorization_verified", "permit_issued", "execution_enabled",
                 "merge_approved", "release_approved")


class AtomicIncubationDossierTests(unittest.TestCase):
    def setUp(self):
        self.source = get_capabilities()
        self.raw = snapshot_manifest(self.source)

    def mutate(self, ident="web-baseline", **fields):
        return snapshot_manifest(tuple(
            replace(c, **fields) if c.capability_id == ident else c
            for c in self.source
        ))

    def check_false(self, review):
        data = review.as_dict()
        for name in _FALSE_FIELDS:
            self.assertIs(data[name], False)
        return data

    def test_real_source_three_independent_controls_review_only(self):
        v = review_atomic_incubation_dossier(self.raw)
        self.assertEqual(v.status, "REVIEW_ONLY")
        self.assertEqual(v.reason, "unchanged_declared_source_metadata_only")
        self.assertEqual((v.catalog_status, v.posture_status, v.fields_status),
                         ("REVIEW_ONLY",) * 3)
        self.assertEqual(v.changed_fields, ())
        self.assertEqual(v.catalog_violations, ())
        self.assertEqual(v.posture_violations, ())
        self.assertTrue(v.fingerprint.startswith("sha256:"))
        self.check_false(v)

    def test_description_only_change_requires_atomic_hold_with_fixed_label(self):
        raw = self.mutate(description="Secret synthetic marker")
        result = review_atomic_incubation_dossier(raw)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.changed_fields, (("web-baseline", ("description",)),))
        self.assertEqual((result.catalog_status, result.posture_status, result.fields_status),
                         ("HOLD", "REVIEW_ONLY", "HOLD"))
        self.assertNotIn("Secret synthetic marker", json.dumps(self.check_false(result)))

    def test_name_only_change_requires_atomic_hold(self):
        v = review_atomic_incubation_dossier(self.mutate(name="Synthetic new title"))
        self.assertEqual(v.status, "HOLD")
        self.assertEqual(v.changed_fields, (("web-baseline", ("name",)),))
        self.assertNotIn("Synthetic new title", json.dumps(self.check_false(v)))

    def test_state_reclassified_denied_even_if_posture_still_unchanged(self):
        v = review_atomic_incubation_dossier(self.mutate(state=CapabilityState.DISABLED))
        self.assertEqual(v.status, "HOLD")
        self.assertIn(("web-baseline", "incubation_state_changed"), v.catalog_violations)
        self.assertEqual(v.posture_status, "REVIEW_ONLY")
        self.assertEqual(v.changed_fields, ())
        self.check_false(v)

    def test_activation_disabled_has_multiple_independent_hold_receipts(self):
        v = review_atomic_incubation_dossier(self.mutate(requires_explicit_activation=False))
        self.assertEqual(v.status, "HOLD")
        self.assertEqual(v.posture_status, "HOLD")
        self.assertEqual(v.catalog_status, "HOLD")
        self.assertEqual(v.fields_status, "HOLD")
        self.assertIn(("web-baseline", "explicit_activation_required"), v.catalog_violations)
        self.check_false(v)

    def test_missing_known_capability_refuses_partial_positive(self):
        raw = snapshot_manifest(tuple(c for c in self.source if c.capability_id != "ot-lab"))
        v = review_atomic_incubation_dossier(raw)
        self.assertEqual(v.status, "HOLD")
        self.assertIn(("ot-lab", "required_capability_missing"), v.catalog_violations)
        self.assertFalse(v.changed_fields)

    def test_added_unknown_capability_refuses_partial_positive(self):
        extra = Capability("synthetic-new", "Synthetic", "Synthetic fixture",
                           CapabilityState.PLANNING)
        v = review_atomic_incubation_dossier(snapshot_manifest(self.source + (extra,)))
        self.assertEqual(v.status, "HOLD")
        self.assertIn(("synthetic-new", "unreviewed_capability_added"), v.catalog_violations)
        self.check_false(v)

    def test_malformed_and_legacy_metadata_atomic_privacy_holds(self):
        for malformed in (b"", b"{}", b"[]", b"\xff", b"x" * 33000, None, "invalid"):
            with self.subTest(k=type(malformed).__name__):
                v = review_atomic_incubation_dossier(malformed)
                self.assertEqual(v.status, "HOLD")
                self.assertEqual(v.reason, "invalid_or_incoherent_registry_dossier")
                self.assertIsNone(v.fingerprint)
                self.assertEqual(v.changed_fields, ())
                self.assertEqual(v.catalog_violations, ())
                self.assertEqual(v.posture_violations, ())
                self.check_false(v)
        obj = json.loads(self.raw)
        for row in obj["capabilities"]:
            del row["name"]
            del row["description"]
        self.assertEqual(review_atomic_incubation_dossier(
            json.dumps(obj).encode()).status, "HOLD")

    def test_snapshot_order_ignored_without_spurious_drift(self):
        obj = json.loads(self.raw)
        obj["capabilities"].reverse()
        v = review_atomic_incubation_dossier(json.dumps(obj).encode())
        self.assertEqual(v.status, "REVIEW_ONLY")
        self.assertEqual(v.changed_fields, ())

    def test_malicious_field_component_contradiction_is_atomic_hold(self):
        good = review_incubation_fields(self.raw)
        with patch(
            "lightup.capability_registry_incubation_dossier.review_incubation_fields",
            return_value=replace(good, status="HOLD", changed_fields=(
                ("web-baseline", ("description",)),
            )),
        ):
            result = review_atomic_incubation_dossier(self.raw)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason, "invalid_or_incoherent_registry_dossier")
        self.assertIsNone(result.fingerprint)
        self.check_false(result)

    def test_untrusted_field_identifier_cannot_escape_to_receipt(self):
        good = review_incubation_fields(self.raw)
        with patch(
            "lightup.capability_registry_incubation_dossier.review_incubation_fields",
            return_value=replace(good, status="HOLD", changed_fields=(
                ("bad|id", ("name",)),
            )),
        ):
            result = review_atomic_incubation_dossier(self.raw)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.changed_fields, ())
        self.assertNotIn("bad|id", json.dumps(self.check_false(result)))

    def test_true_catalog_only_review_cannot_override_field_hold(self):
        good = review_incubation_fields(self.raw)
        with patch(
            "lightup.capability_registry_incubation_dossier.review_incubation_fields",
            return_value=replace(good, status="HOLD"),
        ):
            result = review_atomic_incubation_dossier(self.raw)
        self.assertEqual(result.status, "HOLD")
        self.assertIsNone(result.fingerprint)

    def test_real_cli_nonzero_review_only_and_five_false_flags(self):
        p = subprocess.run([sys.executable, str(_CLI)], capture_output=True,
                           text=True, timeout=15)
        self.assertEqual(p.returncode, 3, p.stderr)
        body = json.loads(p.stdout)
        self.assertEqual(body["status"], "REVIEW_ONLY")
        self.assertEqual(body["component_statuses"], {
            "catalog": "REVIEW_ONLY", "posture": "REVIEW_ONLY", "fields": "REVIEW_ONLY"})
        for k in _FALSE_FIELDS:
            self.assertIs(body[k], False)

    def test_cli_rejects_activation_and_target_args_with_nonzero_hold(self):
        for arg in ("--activate", "https://synthetic.invalid/path", "../secret.json"):
            with self.subTest(arg=arg):
                p = subprocess.run([sys.executable, str(_CLI), arg],
                                   text=True, capture_output=True, timeout=15)
                self.assertEqual(p.returncode, 2, p.stderr)
                body = json.loads(p.stdout)
                self.assertEqual(body["status"], "HOLD")
                for k in _FALSE_FIELDS:
                    self.assertIs(body[k], False)


if __name__ == "__main__":
    unittest.main()
