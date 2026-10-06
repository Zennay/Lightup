from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_classification_review_request as request_tests
from lightup.future_security_classification_review_request_consumer import (
    load_and_validate_future_security_classification_review_request,
)
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)


class FutureSecurityClassificationReviewRequestConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityClassificationReviewRequestTest(
            "test_positive_attestation_creates_bounded_deterministic_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._build(
            disposition=(
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED
            ),
            suffix=suffix,
        )

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            collection_request,
            constraints,
            candidate_context,
            admission,
            review,
            sufficiency_request,
            verifier,
            preflight,
            attestation,
            _,
        ) = produced
        return load_and_validate_future_security_classification_review_request(
            persisted,
            attestation,
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
            candidate_context=candidate_context,
            request=collection_request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )

    def test_real_producer_json_is_parsed_and_live_validated_as_one_boundary(self):
        produced = self._producer(suffix="classification-consumer-roundtrip")
        request = produced[-1]

        consumed = self._consume(request.to_json(), produced)

        self.assertEqual(consumed, request)
        self.assertTrue(consumed.classification_review_required)
        self.assertFalse(consumed.classification_selected)
        self.assertFalse(consumed.transition_resolution_created)
        self.assertFalse(consumed.execution_allowed)
        self.assertFalse(consumed.target_interaction_allowed)
        self.assertFalse(consumed.remediation_authoring_allowed)
        self.assertFalse(consumed.future_state_retest_allowed)
        self.assertFalse(consumed.deployment_authorized)
        self.assertFalse(consumed.attack_path_mutation_allowed)
        self.assertEqual(consumed.future_semantics, "unresolved")
        self.assertEqual(consumed.security_verdict, "not_evaluated")

    def test_invalid_duplicate_and_non_object_persisted_json_fail_closed(self):
        produced = self._producer(suffix="classification-consumer-json")

        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)

        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume('{"schema_version":"a","schema_version":"b"}', produced)

        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)

        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_serialization_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="classification-consumer-tamper")
        request = produced[-1]
        payload = json.loads(request.to_json())
        payload["classification_review_request_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_live_attestation_drift_fails_after_strict_parse(self):
        produced = list(
            self._producer(suffix="classification-consumer-live-drift")
        )
        request = produced[-1]
        attestation = produced[-2]
        produced[-2] = dataclasses.replace(
            attestation,
            attestation_sha256="0" * 64,
        )

        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            self._consume(request.to_json(), tuple(produced))


if __name__ == "__main__":
    unittest.main()
