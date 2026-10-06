from __future__ import annotations

import json
import unittest

import test_future_security_evidence_sufficiency_review_request_handoff as handoff_tests
from lightup.future_security_evidence_sufficiency_review_request_handoff import (
    future_security_evidence_sufficiency_review_request_from_dict,
)


_FALSE_SAFETY_FLAGS = (
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

_TRUE_REVIEW_FLAGS = (
    "metadata_contract_verified",
    "freshness_check_passed",
    "independent_verifier_required",
    "review_required",
)


class FutureSecurityEvidenceSufficiencyReviewRequestSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityEvidenceSufficiencyReviewRequestHandoffTest()
        self.request = self.base._request()

    def test_to_json_is_byte_deterministic_and_json_snapshot_round_trips(self):
        first = self.request.to_json()
        second = self.request.to_json()
        third = self.request.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_security_evidence_sufficiency_review_request_from_dict(
                json.loads(first)
            ),
            self.request,
        )

    def test_as_dict_mutation_cannot_change_source_request(self):
        original_json = self.request.to_json()
        snapshot = self.request.as_dict()

        snapshot["client_id"] = "forged-client"
        snapshot["candidate_evidence_ids"] = ("evidence-z",)
        snapshot["candidate_capability_ids"] = ("capability-z",)
        snapshot["required_checks"] = ("execute_now",)
        snapshot["candidate_classification_claim"] = "introduced"
        snapshot["evidence_sufficiency_evaluated"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.request.to_json(), original_json)
        self.assertEqual(self.request.client_id, "client-1")
        self.assertFalse(self.request.evidence_sufficiency_evaluated)
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
        self.assertIsNot(first["required_checks"], second["required_checks"])

        first["candidate_evidence_ids"] = ("changed-only-in-first",)
        first["required_checks"] = ("changed-only-in-first",)

        self.assertEqual(
            second["candidate_evidence_ids"],
            self.request.candidate_evidence_ids,
        )
        self.assertEqual(second["required_checks"], self.request.required_checks)

    def test_parser_detaches_from_caller_owned_mutable_lists(self):
        persisted = json.loads(self.request.to_json())
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]
        required_checks = persisted["required_checks"]

        parsed = future_security_evidence_sufficiency_review_request_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability")
        required_checks[0] = "execute_now"
        required_checks.append("deploy_now")

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.request)
        self.assertEqual(parsed.candidate_evidence_ids, self.request.candidate_evidence_ids)
        self.assertEqual(
            parsed.candidate_capability_ids,
            self.request.candidate_capability_ids,
        )
        self.assertEqual(parsed.required_checks, self.request.required_checks)

    def test_forged_snapshot_review_and_authority_state_fail_closed(self):
        for field in _TRUE_REVIEW_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.request.to_json())
                payload[field] = False
                with self.assertRaises(ValueError):
                    future_security_evidence_sufficiency_review_request_from_dict(
                        payload
                    )

        for field in _FALSE_SAFETY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.request.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_security_evidence_sufficiency_review_request_from_dict(
                        payload
                    )

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self.request.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_sufficiency_review_request_from_dict(
                        payload
                    )

    def test_classification_claim_remains_claim_only_and_snapshot_mutation_is_local(self):
        original_json = self.request.to_json()
        snapshot = self.request.as_dict()
        snapshot["candidate_classification_claim"] = "secure"

        self.assertEqual(self.request.to_json(), original_json)
        self.assertFalse(self.request.classification_selected)

        persisted = json.loads(original_json)
        persisted["candidate_classification_claim"] = "secure"
        with self.assertRaisesRegex(ValueError, "claim is unsupported"):
            future_security_evidence_sufficiency_review_request_from_dict(
                persisted
            )


if __name__ == "__main__":
    unittest.main()
