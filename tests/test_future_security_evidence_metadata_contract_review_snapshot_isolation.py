from __future__ import annotations

import json
import unittest

import test_future_security_evidence_metadata_contract_review_handoff as handoff_tests
from lightup.future_security_evidence_metadata_contract_review_handoff import (
    future_security_evidence_metadata_contract_review_from_dict,
)


_SAFETY_FALSE_FIELDS = (
    "evidence_sufficiency_evaluated",
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityEvidenceMetadataContractReviewSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        helper = handoff_tests.FutureSecurityEvidenceMetadataContractReviewHandoffTest(
            "test_round_trip_restores_exact_typed_review"
        )
        self.review = helper._review()

    def _persisted_dict(self):
        return json.loads(self.review.to_json())

    def test_json_is_byte_deterministic_and_json_derived_dict_round_trips(self):
        first = self.review.to_json()
        second = self.review.to_json()
        third = self.review.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        restored = future_security_evidence_metadata_contract_review_from_dict(
            json.loads(first)
        )
        self.assertEqual(restored, self.review)

    def test_producer_snapshot_mutation_cannot_change_source_review(self):
        original_json = self.review.to_json()
        snapshot = self.review.as_dict()

        snapshot["client_id"] = "forged-client"
        snapshot["candidate_evidence_ids"] = ("forged-evidence",)
        snapshot["candidate_capability_ids"] = ("forged-capability",)
        snapshot["metadata_contract_verified"] = False
        snapshot["freshness_check_passed"] = False
        snapshot["classification_selected"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.review.to_json(), original_json)
        self.assertTrue(self.review.metadata_contract_verified)
        self.assertTrue(self.review.freshness_check_passed)
        self.assertFalse(self.review.evidence_sufficiency_evaluated)
        self.assertFalse(self.review.classification_selected)
        self.assertEqual(self.review.future_semantics, "unresolved")
        self.assertEqual(self.review.security_verdict, "not_evaluated")

    def test_independent_producer_snapshots_do_not_alias(self):
        first = self.review.as_dict()
        second = self.review.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )
        self.assertIsNot(
            first["candidate_capability_ids"],
            second["candidate_capability_ids"],
        )

        first["candidate_evidence_ids"] = ("changed-only-in-first",)
        first["candidate_capability_ids"] = ("changed-only-in-first",)
        first["candidate_classification_claim"] = "forged"

        self.assertNotEqual(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )
        self.assertNotEqual(
            first["candidate_capability_ids"],
            second["candidate_capability_ids"],
        )
        self.assertNotEqual(
            first["candidate_classification_claim"],
            second["candidate_classification_claim"],
        )

    def test_parser_detaches_from_mutable_persisted_candidate_lists(self):
        persisted = self._persisted_dict()
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]
        parsed = future_security_evidence_metadata_contract_review_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        evidence_ids[0] = "forged-after-parse"
        evidence_ids.append("extra-after-parse")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability-after-parse")

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.review)
        self.assertNotIn("forged-after-parse", parsed.candidate_evidence_ids)
        self.assertNotIn(
            "forged-capability-after-parse",
            parsed.candidate_capability_ids,
        )

    def test_forged_verified_and_safety_snapshot_state_fails_closed(self):
        mutations = {
            "metadata_contract_verified": False,
            "freshness_check_passed": False,
            "future_semantics": "resolved",
            "security_verdict": "secure",
        }
        for field in _SAFETY_FALSE_FIELDS:
            mutations[field] = True

        for field, value in mutations.items():
            with self.subTest(field=field):
                persisted = self._persisted_dict()
                persisted[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_metadata_contract_review_from_dict(
                        persisted
                    )

    def test_forged_classification_claim_fails_closed(self):
        forged = self._persisted_dict()
        forged["candidate_classification_claim"] = "secure_by_metadata"
        with self.assertRaisesRegex(ValueError, "claim is unsupported"):
            future_security_evidence_metadata_contract_review_from_dict(forged)

        type_confused = self._persisted_dict()
        type_confused["candidate_classification_claim"] = True
        with self.assertRaisesRegex(ValueError, "claim must be a string"):
            future_security_evidence_metadata_contract_review_from_dict(
                type_confused
            )

    def test_post_parse_top_level_mutation_cannot_change_typed_review(self):
        persisted = self._persisted_dict()
        parsed = future_security_evidence_metadata_contract_review_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        persisted["client_id"] = "changed-after-parse"
        persisted["review_sha256"] = "0" * 64
        persisted["execution_allowed"] = True
        persisted["security_verdict"] = "secure"

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.review)
        self.assertFalse(parsed.execution_allowed)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
