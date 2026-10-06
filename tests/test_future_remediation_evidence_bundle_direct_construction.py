from __future__ import annotations

import dataclasses
import unittest

import test_future_remediation_evidence_bundle_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureRemediationEvidenceBundleDirectConstructionAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationEvidenceBundleHandoffTest(
            "test_real_producer_round_trips_and_is_immediately_live_validated"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)
        produced = self.h._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-direct-construction",
        )
        self.bundle = produced[-1]
        self.item = self.bundle.items[0]
        self.evidence = self.item.evidence[0]

    def test_canonical_producer_objects_remain_the_positive_control(self):
        self.assertEqual(
            self.item.classification,
            AttackPathTransitionClassification.WORSENED,
        )
        self.assertTrue(self.item.current_attack_path_ids)
        self.assertTrue(self.item.effect_ids)
        self.assertTrue(self.item.capability_ids)
        self.assertTrue(self.item.evidence)
        self.assertTrue(self.bundle.remediation_authoring_ready)
        self.assertFalse(self.bundle.execution_allowed)

    def test_evidence_ref_direct_construction_rejects_impossible_state(self):
        cases = (
            ("evidence_id", ""),
            ("run_id", " run:forged "),
            ("capability_id", "capability:bad\ncontrol"),
            ("kind", "future-transition-observation"),
            ("sha256", "A" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field, value=repr(value)):
                with self.assertRaises(ValueError):
                    dataclasses.replace(self.evidence, **{field: value})

    def test_item_direct_construction_rejects_impossible_state(self):
        extra_capability = "capability:unevidenced-direct-construction"
        cases = (
            {
                "classification": AttackPathTransitionClassification.IMPROVED,
            },
            {
                "resolution_id": "resolution:" + ("a" * 24),
            },
            {
                "resolution_sha256": "A" * 64,
            },
            {
                "current_attack_path_ids": (),
            },
            {
                "current_attack_path_ids": list(
                    self.item.current_attack_path_ids
                ),
            },
            {
                "effect_ids": (),
            },
            {
                "effect_ids": (" effect:forged ",),
            },
            {
                "capability_ids": (),
            },
            {
                "capability_ids": tuple(
                    sorted((*self.item.capability_ids, extra_capability))
                ),
            },
            {
                "evidence": (),
            },
            {
                "evidence": ("not-an-evidence-ref",),
            },
            {
                "evidence_manifest_sha256": "A" * 64,
            },
            {
                "remediation_required": False,
            },
            {
                "future_state_retest_required": False,
            },
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    dataclasses.replace(self.item, **mutation)

    def test_bundle_direct_construction_rejects_impossible_state(self):
        cases = (
            {"schema_version": "future-remediation-evidence-bundle/v0"},
            {"client_id": ""},
            {"changeset_id": " changeset:forged "},
            {"current_twin_version": 0},
            {"twin_version": True},
            {"report_sha256": "A" * 64},
            {"items": list(self.bundle.items)},
            {"items": ("not-a-remediation-evidence-item",)},
            {"remediation_item_count": 0},
            {"blocking_evidence_gap_count": -1},
            {"blocking_evidence_gap_count": True},
            {"remediation_authoring_ready": False},
            {"bundle_sha256": "A" * 64},
            {"execution_allowed": True},
            {"code_change_authorized": True},
            {"target_interaction_allowed": True},
            {"deployment_authorized": True},
            {"attack_path_mutation_allowed": True},
            {"future_semantics": "resolved"},
            {"security_verdict": "secure"},
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    dataclasses.replace(self.bundle, **mutation)


if __name__ == "__main__":
    unittest.main()
