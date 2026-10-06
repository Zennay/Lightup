from __future__ import annotations

import json
import unittest

import test_future_security_classification_reviewer_preflight as preflight_tests


_AUTHORITY_FLAGS = (
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityClassificationReviewerPreflightProducerSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = preflight_tests.FutureSecurityClassificationReviewerPreflightTest(
            "test_distinct_operator_creates_independent_eligibility_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _artifact(self, *, suffix: str):
        return self.base._preflight(suffix=suffix)[-1]

    def _assert_stop_line(self, preflight):
        self.assertTrue(preflight.independent_reviewer_verified)
        self.assertTrue(preflight.eligible_for_classification_review)
        self.assertFalse(preflight.classification_decision_created)
        self.assertFalse(preflight.classification_selected)
        self.assertFalse(preflight.transition_resolution_created)
        for field in _AUTHORITY_FLAGS:
            self.assertIs(getattr(preflight, field), False, field)
        self.assertEqual(preflight.future_semantics, "unresolved")
        self.assertEqual(preflight.security_verdict, "not_evaluated")

    def test_repeated_json_and_dict_snapshots_are_deterministic_and_detached(self):
        preflight = self._artifact(suffix="producer-snapshot-deterministic")
        canonical_json = preflight.to_json()

        self.assertEqual(preflight.to_json(), canonical_json)
        first = preflight.as_dict()
        second = preflight.as_dict()

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsInstance(first["candidate_evidence_ids"], tuple)
        self.assertIsInstance(first["candidate_capability_ids"], tuple)

        untouched_second = dict(second)
        first["client_id"] = "forged-client"
        first["candidate_evidence_ids"] = ("forged-evidence",)
        first["candidate_capability_ids"] = ("forged-capability",)
        first["candidate_classification_claim"] = "verified_because_snapshot"
        first["classification_reviewer_user_id"] = "forged-reviewer"
        first["independent_reviewer_verified"] = False
        first["eligible_for_classification_review"] = False
        first["classification_decision_created"] = True
        first["classification_selected"] = True
        first["transition_resolution_created"] = True
        for field in _AUTHORITY_FLAGS:
            first[field] = True
        first["future_semantics"] = "verified"
        first["security_verdict"] = "secure"

        self.assertEqual(second, untouched_second)
        self.assertEqual(preflight.to_json(), canonical_json)
        self.assertNotEqual(preflight.client_id, first["client_id"])
        self.assertNotEqual(
            preflight.classification_reviewer_user_id,
            first["classification_reviewer_user_id"],
        )
        self._assert_stop_line(preflight)

    def test_json_decoded_mutable_collections_cannot_mutate_typed_preflight(self):
        preflight = self._artifact(suffix="producer-snapshot-json")
        canonical_json = preflight.to_json()
        original_evidence_ids = preflight.candidate_evidence_ids
        original_capability_ids = preflight.candidate_capability_ids

        first = json.loads(canonical_json)
        second = json.loads(canonical_json)

        self.assertIsInstance(first["candidate_evidence_ids"], list)
        self.assertIsInstance(first["candidate_capability_ids"], list)
        self.assertIsNot(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )
        self.assertIsNot(
            first["candidate_capability_ids"],
            second["candidate_capability_ids"],
        )

        first["candidate_evidence_ids"].append("forged-evidence")
        first["candidate_capability_ids"].append("forged-capability")
        first["classification_reviewer_user_id"] = "forged-reviewer"
        first["classification_selected"] = True
        first["execution_allowed"] = True

        self.assertEqual(
            preflight.candidate_evidence_ids,
            original_evidence_ids,
        )
        self.assertEqual(
            preflight.candidate_capability_ids,
            original_capability_ids,
        )
        self.assertNotIn("forged-evidence", second["candidate_evidence_ids"])
        self.assertNotIn("forged-capability", second["candidate_capability_ids"])
        self.assertEqual(preflight.to_json(), canonical_json)
        self._assert_stop_line(preflight)

    def test_snapshot_replacement_cannot_rewrite_reviewer_independence(self):
        preflight = self._artifact(suffix="producer-snapshot-independence")
        snapshot = preflight.as_dict()
        original_reviewer = preflight.classification_reviewer_user_id
        original_verifier = preflight.sufficiency_verifier_user_id

        self.assertNotEqual(original_reviewer, original_verifier)
        snapshot["classification_reviewer_user_id"] = original_verifier
        snapshot["sufficiency_verifier_user_id"] = original_reviewer
        snapshot["independent_reviewer_verified"] = False
        snapshot["eligible_for_classification_review"] = False

        self.assertEqual(
            preflight.classification_reviewer_user_id,
            original_reviewer,
        )
        self.assertEqual(
            preflight.sufficiency_verifier_user_id,
            original_verifier,
        )
        self.assertNotEqual(
            preflight.classification_reviewer_user_id,
            preflight.sufficiency_verifier_user_id,
        )
        self._assert_stop_line(preflight)


if __name__ == "__main__":
    unittest.main()
