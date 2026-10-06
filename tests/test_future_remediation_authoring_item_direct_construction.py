from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_authoring_request as authoring_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureRemediationAuthoringItemDirectConstructionTest(unittest.TestCase):
    def setUp(self):
        self.base = authoring_tests.FutureRemediationAuthoringRequestTest(
            "test_introduced_and_worsened_create_bounded_text_authoring_requests"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        *_, self.request = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-item-direct-construction",
        )
        self.item = self.request.items[0]
        self.evidence = self.item.evidence[0]

    def test_valid_item_preserves_strict_authoring_contract(self):
        self.assertEqual(
            self.item.classification,
            AttackPathTransitionClassification.INTRODUCED,
        )
        self.assertEqual(self.item.requested_output, "remediation_text_proposal")
        self.assertTrue(self.item.remediation_required)
        self.assertTrue(self.item.future_state_retest_required)
        self.assertTrue(self.item.capability_ids)
        self.assertTrue(self.item.evidence)

    def test_direct_construction_rejects_lifecycle_and_output_forgery(self):
        cases = (
            ({"requested_output": "code_patch"}, "requested_output"),
            ({"remediation_required": False}, "remediation_required"),
            ({"future_state_retest_required": False}, "future_state_retest_required"),
            ({"remediation_required": 1}, "remediation_required"),
            ({"future_state_retest_required": 1}, "future_state_retest_required"),
        )
        for changes, expected in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, expected):
                    replace(self.item, **changes)

    def test_direct_construction_rejects_invalid_or_ineligible_classification(self):
        with self.assertRaisesRegex(
            ValueError,
            "AttackPathTransitionClassification",
        ):
            replace(self.item, classification="introduced")

        with self.assertRaisesRegex(ValueError, "not authoring eligible"):
            replace(
                self.item,
                classification=AttackPathTransitionClassification.IMPROVED,
            )

    def test_direct_construction_rejects_empty_identity_and_bad_digests(self):
        for field in ("change_node_id", "subject_node_id", "resolution_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.item, **{field: ""})

        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            replace(self.item, resolution_sha256="ABC")

        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            replace(self.item, evidence_manifest_sha256="ABC")

        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            replace(self.item, evidence_manifest_sha256="0" * 64)

    def test_direct_construction_rejects_noncanonical_lineage_collections(self):
        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(self.item, capability_ids=list(self.item.capability_ids))

        with self.assertRaisesRegex(ValueError, "must not be empty"):
            replace(self.item, capability_ids=())

        duplicate_capability = (
            self.item.capability_ids[0],
            self.item.capability_ids[0],
        )
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            replace(self.item, capability_ids=duplicate_capability)

        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(self.item, current_attack_path_ids=[])

        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(self.item, effect_ids=[])

    def test_direct_construction_rejects_malformed_evidence_container(self):
        with self.assertRaisesRegex(ValueError, "non-empty tuple"):
            replace(self.item, evidence=[])

        with self.assertRaisesRegex(ValueError, "non-empty tuple"):
            replace(self.item, evidence=())

        with self.assertRaisesRegex(ValueError, "RemediationAuthoringEvidenceRef"):
            replace(self.item, evidence=("forged",))

    def test_direct_construction_rejects_malformed_evidence_fields(self):
        for field in ("evidence_id", "run_id", "capability_id", "kind"):
            with self.subTest(field=field):
                forged = replace(self.evidence, **{field: ""})
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.item, evidence=(forged,))

        forged_sha = replace(self.evidence, sha256="ABC")
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            replace(self.item, evidence=(forged_sha,))

    def test_direct_construction_rejects_evidence_outside_capability_lineage(self):
        outside = replace(self.evidence, capability_id="outside-capability")
        with self.assertRaisesRegex(ValueError, "outside item lineage"):
            replace(self.item, evidence=(outside,))

    def test_direct_construction_rejects_duplicate_or_unordered_evidence(self):
        with self.assertRaisesRegex(ValueError, "IDs must be unique"):
            replace(self.item, evidence=(self.evidence, self.evidence))

        later = replace(
            self.evidence,
            evidence_id=self.evidence.evidence_id + "-zzz",
        )
        with self.assertRaisesRegex(ValueError, "canonically ordered"):
            replace(self.item, evidence=(later, self.evidence))


if __name__ == "__main__":
    unittest.main()
