"""Real capability semantic-metadata drift: non-authorizing offline regressions."""
from __future__ import annotations

import json
import unittest
from dataclasses import replace

from lightup.capabilities import get_capabilities
from lightup.capability_registry_drift_review import review_capability_registry_drift
from scripts.export_scope_capability_registry_offline import snapshot_manifest


def encoded(items):
    return json.dumps({"capabilities": items}, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def old():
    return {"capability_id": "web-baseline", "state": "planning", "requires_explicit_activation": True}


def full():
    return {**old(), "name": "Web baseline", "description": "HTTP/TLS configuration review"}


class RegistrySemanticDriftTests(unittest.TestCase):
    def assert_hold_without_authority(self, before, after):
        result = review_capability_registry_drift(before, after)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.changed_capabilities, ("web-baseline",))
        self.assertFalse(result.authorization_verified)
        self.assertFalse(result.permit_issued)
        self.assertFalse(result.execution_enabled)
        self.assertFalse(result.merge_approved)
        self.assertFalse(result.release_approved)
        return result

    def test_original_legacy_manifest_still_reviewable(self):
        data = encoded([old()])
        self.assertEqual(review_capability_registry_drift(data, data).status, "REVIEW_ONLY")

    def test_complete_metadata_matches_without_grant(self):
        data = encoded([full()])
        review = review_capability_registry_drift(data, data)
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertFalse(review.execution_enabled)
        self.assertEqual(review.baseline_fingerprint, review.candidate_fingerprint)

    def test_upgrade_from_legacy_metadata_is_hold(self):
        self.assert_hold_without_authority(encoded([old()]), encoded([full()]))

    def test_metadata_downgrade_to_legacy_is_hold(self):
        self.assert_hold_without_authority(encoded([full()]), encoded([old()]))

    def test_changed_name_is_hold(self):
        new = {**full(), "name": "Active service scanner"}
        self.assert_hold_without_authority(encoded([full()]), encoded([new]))

    def test_changed_description_is_hold(self):
        new = {**full(), "description": "Active network probing"}
        receipt = self.assert_hold_without_authority(encoded([full()]), encoded([new]))
        self.assertNotEqual(receipt.baseline_fingerprint, receipt.candidate_fingerprint)

    def test_braces_brackets_inside_description_are_not_structure(self):
        new = {**full(), "description": 'Review JSON {"capabilities":[]} and [security] "headers"'}
        data = encoded([new])
        self.assertEqual(review_capability_registry_drift(data, data).status, "REVIEW_ONLY")

    def test_canonical_unicode_name_supported(self):
        new = {**full(), "name": "Säkerhet — baseline"}
        data = encoded([new])
        self.assertEqual(review_capability_registry_drift(data, data).status, "REVIEW_ONLY")

    def test_noncanonical_unicode_name_rejected(self):
        new = {**full(), "name": "Se\u0301curity"}
        receipt = review_capability_registry_drift(encoded([full()]), encoded([new]))
        self.assertEqual(receipt.status, "HOLD")
        self.assertEqual(receipt.reason, "invalid_manifest")
        self.assertFalse(receipt.authorization_verified)

    def test_bidi_and_control_characters_rejected(self):
        for bad in ["name\u202e", "name\nnew", "name\tnew", "\x00name", "name\u200b"]:
            with self.subTest(bad=repr(bad)):
                new = {**full(), "name": bad}
                receipt = review_capability_registry_drift(encoded([full()]), encoded([new]))
                self.assertEqual(receipt.reason, "invalid_manifest")

    def test_partial_v2_metadata_rejected(self):
        for key in ("name", "description"):
            partial = {k: v for k, v in full().items() if k != key}
            receipt = review_capability_registry_drift(encoded([full()]), encoded([partial]))
            self.assertEqual(receipt.reason, "invalid_manifest")

    def test_missing_blank_and_long_text_rejected(self):
        for value in ("", " ", " leading", "trailing ", "A" * 129):
            with self.subTest(value=value[:20]):
                rec = {**full(), "name": value}
                self.assertEqual(review_capability_registry_drift(encoded([full()]), encoded([rec])).reason, "invalid_manifest")

    def test_malformed_description_rejected(self):
        for value in (None, 42, False, "x" * 513, "line\nbreak"):
            with self.subTest(value=str(value)[:20]):
                rec = {**full(), "description": value}
                self.assertEqual(review_capability_registry_drift(encoded([full()]), encoded([rec])).status, "HOLD")

    def test_actual_source_export_carries_name_description(self):
        source = get_capabilities()
        raw = snapshot_manifest(source)
        actual = json.loads(raw)["capabilities"]
        self.assertEqual(len(actual), len(source))
        self.assertTrue(all(set(x) == {"capability_id", "state", "requires_explicit_activation", "name", "description"} for x in actual))
        self.assertEqual(review_capability_registry_drift(raw, raw).status, "REVIEW_ONLY")

    def test_actual_registry_description_change_is_hold(self):
        source = get_capabilities()
        before = snapshot_manifest(source)
        modified = (replace(source[0], description=source[0].description + " reviewed"),) + source[1:]
        receipt = review_capability_registry_drift(before, snapshot_manifest(modified))
        self.assertEqual(receipt.status, "HOLD")
        self.assertEqual(receipt.changed_capabilities, (source[0].capability_id,))
        self.assertFalse(receipt.execution_enabled)

    def test_actual_registry_name_type_confusion_is_rejected(self):
        source = get_capabilities()
        bad = (replace(source[0], name=None),) + source[1:]
        with self.assertRaises(ValueError):
            snapshot_manifest(bad)

    def test_actual_registry_unicode_metadata_type_confusion_is_rejected(self):
        source = get_capabilities()
        bad = (replace(source[0], description=123),) + source[1:]
        with self.assertRaises(ValueError):
            snapshot_manifest(bad)


if __name__ == "__main__":
    unittest.main()
