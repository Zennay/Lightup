from __future__ import annotations

import json
import unittest

import test_future_security_evidence_metadata_contract_review as review_tests
from lightup.future_security_evidence_metadata_contract_review_consumer import (
    load_and_validate_future_security_evidence_metadata_contract_review,
)


class FutureSecurityEvidenceMetadataContractReviewConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureSecurityEvidenceMetadataContractReviewTest(
            "test_valid_metadata_contract_is_reviewed_without_selecting_classification"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._review(suffix=suffix)

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
            _,
        ) = produced
        return load_and_validate_future_security_evidence_metadata_contract_review(
            persisted,
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
        produced = self._producer(suffix="metadata-review-consumer-roundtrip")
        review = produced[-1]
        consumed = self._consume(review.to_json(), produced)

        self.assertEqual(consumed, review)
        self.assertTrue(consumed.metadata_contract_verified)
        self.assertTrue(consumed.freshness_check_passed)
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
        produced = self._producer(suffix="metadata-review-consumer-json")
        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)
        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(
                '{"schema_version":"a","schema_version":"b"}',
                produced,
            )
        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_digest_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="metadata-review-consumer-tamper")
        review = produced[-1]
        payload = json.loads(review.to_json())
        payload["review_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_live_metadata_drift_fails_after_strict_parse(self):
        produced = self._producer(suffix="metadata-review-consumer-live-drift")
        admission = produced[10]
        review = produced[-1]
        evidence_id = admission.candidate_evidence_ids[0]
        record = self.state.get_evidence(evidence_id)
        metadata = dict(record.metadata)
        metadata["proposal_sha256"] = "0" * 64
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET metadata_json=? WHERE evidence_id=?",
                (
                    json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                    evidence_id,
                ),
            )

        with self.assertRaisesRegex(ValueError, "metadata contract mismatch"):
            self._consume(review.to_json(), produced)


if __name__ == "__main__":
    unittest.main()
