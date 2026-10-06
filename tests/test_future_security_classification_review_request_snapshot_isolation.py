from __future__ import annotations

import json
import unittest

import test_future_security_classification_review_request_handoff as handoff_tests
from lightup.future_security_classification_review_request_handoff import (
    future_security_classification_review_request_from_dict,
)


_TRUE_REVIEW_FLAGS = (
    "evidence_sufficient",
    "classification_claim_justified",
    "sufficiency_decision_created",
    "evidence_sufficiency_evaluated",
    "classification_justification_evaluated",
    "eligible_for_classification_review",
    "classification_review_required",
)

_FALSE_SAFETY_FLAGS = (
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


class FutureSecurityClassificationReviewRequestSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityClassificationReviewRequestHandoffTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        *_, self.request = self.base._producer(
            suffix="classification-review-request-snapshot"
        )

    def test_to_json_is_byte_deterministic_and_json_snapshot_round_trips(self):
        first = self.request.to_json()
        second = self.request.to_json()
        third = self.request.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_security_classification_review_request_from_dict(
                json.loads(first)
            ),
            self.request,
        )

    def test_as_dict_mutation_cannot_change_source_request(self):
        original_json = self.request.to_json()
        snapshot = self.request.as_dict()

        snapshot["verifier_user_id"] = "forged-verifier"
        snapshot["candidate_evidence_ids"] = ("evidence-z",)
        snapshot["candidate_capability_ids"] = ("capability-z",)
        snapshot["candidate_classification_claim"] = "secure"
        snapshot["evidence_sufficient"] = False
        snapshot["classification_review_required"] = False
        snapshot["classification_selected"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.request.to_json(), original_json)
        self.assertTrue(self.request.evidence_sufficient)
        self.assertTrue(self.request.classification_review_required)
        self.assertFalse(self.request.classification_selected)
        self.assertFalse(self.request.execution_allowed)
        self.assertEqual(self.request.future_semantics, "unresolved")
        self.assertEqual(self.request.security_verdict, "not_evaluated")

    def test_separate_as_dict_snapshots_do_not_alias(self):
        first = self.request.as_dict()
        second = self.request.as_dict()

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

        self.assertEqual(
            second["candidate_evidence_ids"],
            self.request.candidate_evidence_ids,
        )
        self.assertEqual(
            second["candidate_capability_ids"],
            self.request.candidate_capability_ids,
        )

    def test_parser_detaches_from_caller_owned_mutable_lists(self):
        persisted = json.loads(self.request.to_json())
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]

        parsed = future_security_classification_review_request_from_dict(persisted)
        parsed_json = parsed.to_json()

        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability")

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.request)
        self.assertEqual(parsed.candidate_evidence_ids, self.request.candidate_evidence_ids)
        self.assertEqual(
            parsed.candidate_capability_ids,
            self.request.candidate_capability_ids,
        )

    def test_forged_review_eligibility_and_authority_state_fail_closed(self):
        for field in _TRUE_REVIEW_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.request.to_json())
                payload[field] = False
                with self.assertRaises(ValueError):
                    future_security_classification_review_request_from_dict(payload)

        for field in _FALSE_SAFETY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.request.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_security_classification_review_request_from_dict(payload)

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self.request.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_classification_review_request_from_dict(payload)

    def test_classification_claim_remains_claim_only_and_snapshot_mutation_is_local(self):
        original_json = self.request.to_json()
        snapshot = self.request.as_dict()
        snapshot["candidate_classification_claim"] = "secure"

        self.assertEqual(self.request.to_json(), original_json)
        self.assertFalse(self.request.classification_selected)

        persisted = json.loads(original_json)
        persisted["candidate_classification_claim"] = "secure"
        with self.assertRaisesRegex(ValueError, "classification claim is unsupported"):
            future_security_classification_review_request_from_dict(persisted)


if __name__ == "__main__":
    unittest.main()
