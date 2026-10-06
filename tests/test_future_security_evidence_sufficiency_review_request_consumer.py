from __future__ import annotations

import json
import unittest

import test_future_security_evidence_sufficiency_review_request as request_tests
from lightup.future_security_evidence_sufficiency_review_request_consumer import (
    load_and_validate_future_security_evidence_sufficiency_review_request,
)


class FutureSecurityEvidenceSufficiencyReviewRequestConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityEvidenceSufficiencyReviewRequestTest(
            "test_live_metadata_review_becomes_bounded_independent_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._request(suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            admission,
            review,
            _,
        ) = produced
        return load_and_validate_future_security_evidence_sufficiency_review_request(
            persisted,
            review,
            admission,
            constraints,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )

    def test_real_producer_json_is_strictly_parsed_and_live_validated(self):
        produced = self._producer(suffix="sufficiency-request-consumer-roundtrip")
        request = produced[-1]
        consumed = self._consume(request.to_json(), produced)

        self.assertEqual(consumed, request)
        self.assertTrue(consumed.metadata_contract_verified)
        self.assertTrue(consumed.freshness_check_passed)
        self.assertTrue(consumed.independent_verifier_required)
        self.assertTrue(consumed.review_required)
        self.assertFalse(consumed.evidence_sufficiency_evaluated)
        self.assertFalse(consumed.classification_selected)
        self.assertFalse(consumed.transition_resolution_created)
        self.assertFalse(consumed.execution_allowed)
        self.assertFalse(consumed.target_interaction_allowed)
        self.assertFalse(consumed.remediation_authoring_allowed)
        self.assertFalse(consumed.future_state_retest_allowed)
        self.assertFalse(consumed.deployment_authorized)
        self.assertFalse(consumed.attack_path_mutation_allowed)

    def test_invalid_duplicate_and_non_object_json_fail_closed(self):
        produced = self._producer(suffix="sufficiency-request-consumer-json")
        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)
        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume('{"schema_version":"a","schema_version":"b"}', produced)
        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_digest_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="sufficiency-request-consumer-tamper")
        request = produced[-1]
        payload = json.loads(request.to_json())
        payload["sufficiency_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_object_input_cannot_bypass_strict_review_obligations(self):
        produced = self._producer(suffix="sufficiency-request-consumer-object")
        request = produced[-1]
        payload = json.loads(request.to_json())
        payload["review_required"] = False

        with self.assertRaisesRegex(ValueError, "review_required must remain true"):
            self._consume(payload, produced)

    def test_live_candidate_capability_drift_fails_after_strict_parse(self):
        produced = self._producer(suffix="sufficiency-request-consumer-live-drift")
        admission = produced[10]
        request = produced[-1]
        evidence_id = admission.candidate_evidence_ids[0]
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET capability_id=? WHERE evidence_id=?",
                ("drifted-capability", evidence_id),
            )

        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            self._consume(request.to_json(), produced)


if __name__ == "__main__":
    unittest.main()
