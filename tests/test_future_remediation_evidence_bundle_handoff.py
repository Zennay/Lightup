from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_dict,
    future_remediation_evidence_bundle_from_json,
    load_and_validate_future_remediation_evidence_bundle,
)


class FutureRemediationEvidenceBundleHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _bundle(self, classification, *, suffix: str):
        return self.base._bundle(classification, suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            _,
        ) = produced
        return load_and_validate_future_remediation_evidence_bundle(
            persisted,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_real_producer_round_trips_and_is_immediately_live_validated(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                produced = self._bundle(
                    classification,
                    suffix=f"bundle-handoff-{classification.value}",
                )
                bundle = produced[-1]

                self.assertEqual(
                    future_remediation_evidence_bundle_from_json(bundle.to_json()),
                    bundle,
                )
                self.assertEqual(
                    future_remediation_evidence_bundle_from_dict(
                        json.loads(bundle.to_json())
                    ),
                    bundle,
                )
                self.assertEqual(self._consume(bundle.to_json(), produced), bundle)
                self.assertFalse(bundle.execution_allowed)
                self.assertFalse(bundle.code_change_authorized)
                self.assertFalse(bundle.target_interaction_allowed)
                self.assertFalse(bundle.deployment_authorized)
                self.assertFalse(bundle.attack_path_mutation_allowed)
                self.assertEqual(bundle.future_semantics, "unresolved")
                self.assertEqual(bundle.security_verdict, "not_evaluated")

    def test_empty_gap_bundle_round_trips_without_inventing_authoring_readiness(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="bundle-handoff-gap",
        )
        bundle = produced[-1]

        parsed = future_remediation_evidence_bundle_from_json(bundle.to_json())

        self.assertEqual(parsed, bundle)
        self.assertEqual(parsed.items, ())
        self.assertEqual(parsed.remediation_item_count, 0)
        self.assertEqual(parsed.blocking_evidence_gap_count, 1)
        self.assertFalse(parsed.remediation_authoring_ready)
        self.assertEqual(self._consume(bundle.to_json(), produced), bundle)

    def test_malformed_duplicate_nonobject_and_schema_drift_fail_closed(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-handoff-json",
        )
        bundle = produced[-1]

        with self.assertRaisesRegex(ValueError, "JSON is invalid"):
            future_remediation_evidence_bundle_from_json("{")

        with self.assertRaisesRegex(ValueError, "payload must be an object"):
            future_remediation_evidence_bundle_from_json("[]")

        duplicate_top = bundle.to_json()[:-1] + ',"bundle_sha256":"' + (
            "0" * 64
        ) + '"}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_evidence_bundle_from_json(duplicate_top)

        duplicate_nested = bundle.to_json().replace(
            '"remediation_required":true',
            '"remediation_required":true,"remediation_required":true',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_evidence_bundle_from_json(duplicate_nested)

        unknown = json.loads(bundle.to_json())
        unknown["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_evidence_bundle_from_dict(unknown)

    def test_type_confusion_and_positive_authority_flags_fail_closed(self):
        produced = self._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-handoff-types",
        )
        payload = json.loads(produced[-1].to_json())

        bad_version = copy.deepcopy(payload)
        bad_version["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_remediation_evidence_bundle_from_dict(bad_version)

        bad_ready = copy.deepcopy(payload)
        bad_ready["remediation_authoring_ready"] = 1
        with self.assertRaisesRegex(ValueError, "must be boolean"):
            future_remediation_evidence_bundle_from_dict(bad_ready)

        positive_authority = copy.deepcopy(payload)
        positive_authority["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "must remain false"):
            future_remediation_evidence_bundle_from_dict(positive_authority)

        wrong_semantics = copy.deepcopy(payload)
        wrong_semantics["future_semantics"] = "accepted"
        with self.assertRaisesRegex(ValueError, "must remain unresolved"):
            future_remediation_evidence_bundle_from_dict(wrong_semantics)

    def test_item_evidence_and_digest_semantics_fail_closed(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-handoff-integrity",
        )
        payload = json.loads(produced[-1].to_json())

        wrong_classification = copy.deepcopy(payload)
        wrong_classification["items"][0]["classification"] = (
            AttackPathTransitionClassification.IMPROVED.value
        )
        with self.assertRaisesRegex(ValueError, "not remediation-authoring eligible"):
            future_remediation_evidence_bundle_from_dict(wrong_classification)

        false_required = copy.deepcopy(payload)
        false_required["items"][0]["remediation_required"] = False
        with self.assertRaisesRegex(ValueError, "must remain true"):
            future_remediation_evidence_bundle_from_dict(false_required)

        duplicated_evidence = copy.deepcopy(payload)
        duplicated_evidence["items"][0]["evidence"].append(
            copy.deepcopy(duplicated_evidence["items"][0]["evidence"][0])
        )
        with self.assertRaisesRegex(ValueError, "evidence IDs must be unique"):
            future_remediation_evidence_bundle_from_dict(duplicated_evidence)

        manifest_drift = copy.deepcopy(payload)
        original = manifest_drift["items"][0]["evidence"][0]["sha256"]
        manifest_drift["items"][0]["evidence"][0]["sha256"] = (
            "f" * 64 if original != "f" * 64 else "e" * 64
        )
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            future_remediation_evidence_bundle_from_dict(manifest_drift)

        bundle_drift = copy.deepcopy(payload)
        bundle_drift["bundle_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "bundle digest mismatch"):
            future_remediation_evidence_bundle_from_dict(bundle_drift)

    def test_authoring_readiness_cannot_be_forged(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="bundle-handoff-forged-ready",
        )
        payload = json.loads(produced[-1].to_json())
        payload["remediation_authoring_ready"] = True

        with self.assertRaisesRegex(ValueError, "authoring readiness is inconsistent"):
            future_remediation_evidence_bundle_from_dict(payload)

    def test_live_ledger_drift_rejects_canonical_persisted_bundle(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-handoff-live-drift",
        )
        bundle = produced[-1]
        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaisesRegex(
            ValueError,
            "does not match its live validated lineage",
        ):
            self._consume(bundle.to_json(), produced)

    def test_non_json_object_types_fail_before_live_validation(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-handoff-input-type",
        )
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)


if __name__ == "__main__":
    unittest.main()
