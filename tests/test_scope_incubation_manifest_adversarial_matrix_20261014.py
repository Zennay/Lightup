"""Deterministic adversarial mutation matrix of real source registry metadata.

Malformed witnesses MUST fail the strict parser and yield a privacy-safe,
non-authorizing atomic HOLD from the three-gate dossier. No external targets.
"""
from __future__ import annotations

import copy
import json
import unittest

from lightup.capabilities import get_capabilities
from lightup.capability_registry_drift_review import _decode_manifest
from lightup.capability_registry_incubation_dossier import review_atomic_incubation_dossier
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
          "merge_approved", "release_approved")


class AdversarialIncubationManifestMatrixTests(unittest.TestCase):
    def setUp(self):
        self.raw = snapshot_manifest(get_capabilities())
        self.canonical = json.loads(self.raw)
        self.assertEqual(len(self.canonical["capabilities"]), 31)

    def data(self):
        return copy.deepcopy(self.canonical)

    def raw_of(self, obj):
        return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")

    def assert_authority_false(self, review):
        for key in _FLAGS:
            self.assertIs(review.as_dict()[key], False, key)

    def assert_malformed(self, raw):
        with self.assertRaises((ValueError, TypeError, OverflowError, RecursionError)):
            _decode_manifest(raw)
        review = review_atomic_incubation_dossier(raw)
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.reason, "invalid_or_incoherent_registry_dossier")
        self.assertIsNone(review.fingerprint)
        self.assertEqual(review.catalog_violations, ())
        self.assertEqual(review.posture_violations, ())
        self.assertEqual(review.changed_fields, ())
        self.assert_authority_false(review)

    def assert_changed_hold(self, raw):
        decoded = _decode_manifest(raw)
        self.assertTrue(decoded)
        review = review_atomic_incubation_dossier(raw)
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.reason, "one_or_more_checks_require_review")
        self.assertIsNotNone(review.fingerprint)
        self.assert_authority_false(review)
        return review

    def test_exact_real_source_review_only_never_authorizes(self):
        _decode_manifest(self.raw)
        review = review_atomic_incubation_dossier(self.raw)
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertEqual(review.changed_fields, ())
        self.assert_authority_false(review)

    def test_equivalent_json_spacing_review_only(self):
        raw = json.dumps(self.canonical, ensure_ascii=True, indent=4).encode("ascii")
        self.assertEqual(review_atomic_incubation_dossier(raw).status, "REVIEW_ONLY")
        self.assert_authority_false(review_atomic_incubation_dossier(raw))

    def test_reversed_list_order_review_only(self):
        obj = self.data()
        obj["capabilities"].reverse()
        self.assertEqual(review_atomic_incubation_dossier(self.raw_of(obj)).status, "REVIEW_ONLY")

    def test_reordered_record_keys_review_only(self):
        obj = self.data()
        obj["capabilities"] = [dict(reversed(list(record.items()))) for record in obj["capabilities"]]
        self.assertEqual(review_atomic_incubation_dossier(self.raw_of(obj)).status, "REVIEW_ONLY")

    def test_empty_bytes_deny(self):
        self.assert_malformed(b"")

    def test_corrupt_utf8_deny(self):
        self.assert_malformed(b"\xff\xfe")

    def test_duplicate_json_root_key_deny(self):
        self.assert_malformed(b'{"capabilities":[{}],"capabilities":[{}]}')

    def test_duplicate_json_record_key_deny(self):
        item = self.data()["capabilities"][0]
        blob = json.dumps(item, separators=(",", ":"))
        duplicate = blob[:-1] + ',"state":"planning"}'
        self.assert_malformed(b'{"capabilities":[' + duplicate.encode() + b']}')

    def test_unknown_envelope_key_deny(self):
        obj = self.data()
        obj["extra"] = "fixture"
        self.assert_malformed(self.raw_of(obj))

    def test_unknown_record_key_deny(self):
        obj = self.data()
        obj["capabilities"][0]["execution_enabled"] = True
        self.assert_malformed(self.raw_of(obj))

    def test_missing_manifest_list_deny(self):
        self.assert_malformed(b'{"scope":[]}')
        self.assert_malformed(b'{}')

    def test_empty_manifest_list_deny(self):
        self.assert_malformed(b'{"capabilities":[]}')

    def test_nested_record_structure_deny(self):
        obj = self.data()
        obj["capabilities"][0]["name"] = ["nested", {"unauthorized": True}]
        self.assert_malformed(self.raw_of(obj))

    def test_wrong_records_container_deny(self):
        self.assert_malformed(b'{"capabilities":{}}')

    def test_array_item_wrong_type_deny(self):
        obj = self.data()
        obj["capabilities"][0] = 0
        self.assert_malformed(self.raw_of(obj))

    def test_duplicate_canonical_capability_id_deny(self):
        obj = self.data()
        obj["capabilities"].append(copy.deepcopy(obj["capabilities"][0]))
        self.assert_malformed(self.raw_of(obj))

    def test_more_than_max_records_denied(self):
        obj = {
            "capabilities": [
                {"capability_id": f"synthetic-{i:03}", "state": "planning",
                 "requires_explicit_activation": True, "name": "N",
                 "description": "D"} for i in range(129)
            ],
        }
        self.assert_malformed(self.raw_of(obj))

    def test_payload_exceeding_32768_bytes_denied(self):
        self.assert_malformed(self.raw + b" " * (32769 - len(self.raw)))

    def test_nonfinite_json_constant_denied(self):
        obj = self.data()
        raw = self.raw_of(obj)
        self.assertIn(b'"requires_explicit_activation":true', raw)
        self.assert_malformed(raw.replace(
            b'"requires_explicit_activation":true',
            b'"requires_explicit_activation":NaN', 1))

    def test_noncanonical_capability_identifiers_denied(self):
        for ident in ("UPPER-CASE", "a--b", "a_", "a" * 65, "", "-leading"):
            with self.subTest(ident=ident):
                obj = self.data()
                obj["capabilities"][0]["capability_id"] = ident
                self.assert_malformed(self.raw_of(obj))

    def test_bad_state_types_denied(self):
        for value in (None, 1, True, "AUTHORIZED", "LAB_ONLY", "planning "):
            with self.subTest(value=value):
                obj = self.data()
                obj["capabilities"][0]["state"] = value
                self.assert_malformed(self.raw_of(obj))

    def test_non_bool_activation_markers_denied(self):
        for value in (None, 1, 0, "false", "true", [], {}):
            with self.subTest(value=value):
                obj = self.data()
                obj["capabilities"][0]["requires_explicit_activation"] = value
                self.assert_malformed(self.raw_of(obj))

    def test_blank_or_control_names_denied(self):
        for text in ("", " ", " leading", "trailing ", "line\nfeed", "null\x00byte"):
            with self.subTest(text=repr(text)):
                obj = self.data()
                obj["capabilities"][0]["name"] = text
                self.assert_malformed(self.raw_of(obj))

    def test_unicode_non_nfc_description_denied(self):
        obj = self.data()
        obj["capabilities"][0]["description"] = "Cafe\u0301"
        self.assert_malformed(self.raw_of(obj))

    def test_unicode_surrogate_name_denied(self):
        obj = self.data()
        obj["capabilities"][0]["name"] = "\ud800"
        self.assert_malformed(self.raw_of(obj))

    def test_oversize_human_text_denied(self):
        for field, size in (("name", 129), ("description", 513)):
            with self.subTest(field=field):
                obj = self.data()
                obj["capabilities"][0][field] = "x" * size
                self.assert_malformed(self.raw_of(obj))

    def test_legacy_three_field_record_denied_by_dossier(self):
        obj = self.data()
        for row in obj["capabilities"]:
            del row["name"]
            del row["description"]
        raw = self.raw_of(obj)
        self.assertTrue(_decode_manifest(raw))
        review = review_atomic_incubation_dossier(raw)
        self.assertEqual(review.status, "HOLD")
        self.assertIsNone(review.fingerprint)
        self.assert_authority_false(review)

    def test_valid_name_change_holds_without_leaking_text(self):
        obj = self.data()
        obj["capabilities"][0]["name"] = "CONFIDENTIAL_SAFETY_FIXTURE"
        review = self.assert_changed_hold(self.raw_of(obj))
        self.assertNotIn("CONFIDENTIAL_SAFETY_FIXTURE", json.dumps(review.as_dict()))
        self.assertEqual(len(review.changed_fields), 1)

    def test_valid_explicit_activation_disabled_holds(self):
        obj = self.data()
        obj["capabilities"][0]["requires_explicit_activation"] = False
        review = self.assert_changed_hold(self.raw_of(obj))
        self.assertEqual(review.catalog_status, "HOLD")
        self.assertEqual(review.posture_status, "HOLD")

    def test_valid_state_reclassification_holds(self):
        obj = self.data()
        obj["capabilities"][0]["state"] = "disabled"
        review = self.assert_changed_hold(self.raw_of(obj))
        self.assertIn("incubation_state_changed", json.dumps(review.as_dict()))

    def test_extra_valid_capability_still_requires_review(self):
        obj = self.data()
        obj["capabilities"].append({
            "capability_id": "new-review-only", "state": "planning",
            "requires_explicit_activation": True,
            "name": "Other", "description": "Synthetic extra",
        })
        review = self.assert_changed_hold(self.raw_of(obj))
        self.assertIn("unreviewed_capability_added", json.dumps(review.as_dict()))

    def test_valid_removed_sensitive_lab_requires_review(self):
        obj = self.data()
        obj["capabilities"] = [
            row for row in obj["capabilities"] if row["capability_id"] != "ot-lab"
        ]
        review = self.assert_changed_hold(self.raw_of(obj))
        self.assertIn("required_lab_capability_missing", json.dumps(review.as_dict()))

    def test_name_change_plus_disabled_activation_still_atomic_hold(self):
        obj = self.data()
        obj["capabilities"][0]["name"] = "SECRET_DO_NOT_ECHO"
        obj["capabilities"][0]["requires_explicit_activation"] = False
        review = self.assert_changed_hold(self.raw_of(obj))
        self.assertEqual(review.changed_fields, ())
        self.assertNotIn("SECRET_DO_NOT_ECHO", json.dumps(review.as_dict()))


if __name__ == "__main__":
    unittest.main()
