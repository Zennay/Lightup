from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_classification_review_request as request_tests
from lightup.future_security_classification_review_request import (
    validate_future_security_classification_review_request,
)
from lightup.future_security_classification_review_request_handoff import (
    future_security_classification_review_request_from_dict,
)
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)


class FutureSecurityClassificationReviewRequestHandoffTest(unittest.TestCase):
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

    def test_exact_round_trip_preserves_fail_closed_semantics(self):
        *_, request = self._producer(suffix="classification-handoff-roundtrip")
        parsed = future_security_classification_review_request_from_dict(
            json.loads(request.to_json())
        )
        self.assertEqual(parsed, request)
        self.assertTrue(parsed.evidence_sufficient)
        self.assertTrue(parsed.classification_claim_justified)
        self.assertTrue(parsed.eligible_for_classification_review)
        self.assertTrue(parsed.classification_review_required)
        self.assertFalse(parsed.classification_selected)
        self.assertFalse(parsed.transition_resolution_created)
        self.assertFalse(parsed.execution_allowed)
        self.assertFalse(parsed.remediation_authoring_allowed)
        self.assertFalse(parsed.deployment_authorized)
        self.assertEqual(parsed.future_semantics, "unresolved")
        self.assertEqual(parsed.security_verdict, "not_evaluated")

    def test_missing_extra_noncanonical_and_unsupported_fields_fail_closed(self):
        *_, request = self._producer(suffix="classification-handoff-shape")
        payload = json.loads(request.to_json())

        missing = dict(payload)
        missing.pop("client_id")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_security_classification_review_request_from_dict(missing)

        extra = dict(payload)
        extra["unexpected"] = "forbidden"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_security_classification_review_request_from_dict(extra)

        malformed_id = dict(payload)
        malformed_id["verifier_user_id"] = " verifier "
        with self.assertRaisesRegex(ValueError, "canonical"):
            future_security_classification_review_request_from_dict(malformed_id)

        uppercase_sha = dict(payload)
        uppercase_sha["attestation_sha256"] = "A" * 64
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            future_security_classification_review_request_from_dict(uppercase_sha)

        duplicate_evidence = dict(payload)
        evidence_id = payload["candidate_evidence_ids"][0]
        duplicate_evidence["candidate_evidence_ids"] = [evidence_id, evidence_id]
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_classification_review_request_from_dict(
                duplicate_evidence
            )

        unsupported_claim = dict(payload)
        unsupported_claim["candidate_classification_claim"] = "verified_because_json"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            future_security_classification_review_request_from_dict(
                unsupported_claim
            )

    def test_forged_positive_or_authority_semantics_fail_closed(self):
        *_, request = self._producer(suffix="classification-handoff-semantics")
        payload = json.loads(request.to_json())

        true_fields = (
            "evidence_sufficient",
            "classification_claim_justified",
            "sufficiency_decision_created",
            "evidence_sufficiency_evaluated",
            "classification_justification_evaluated",
            "eligible_for_classification_review",
            "classification_review_required",
        )
        for field in true_fields:
            with self.subTest(field=field):
                forged = dict(payload)
                forged[field] = False
                with self.assertRaisesRegex(ValueError, "must remain true"):
                    future_security_classification_review_request_from_dict(forged)

        false_fields = (
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
        for field in false_fields:
            with self.subTest(field=field):
                forged = dict(payload)
                forged[field] = True
                with self.assertRaisesRegex(ValueError, "must remain false"):
                    future_security_classification_review_request_from_dict(forged)

        forged_semantics = dict(payload)
        forged_semantics["future_semantics"] = "verified"
        with self.assertRaisesRegex(ValueError, "must remain unresolved"):
            future_security_classification_review_request_from_dict(
                forged_semantics
            )

        forged_verdict = dict(payload)
        forged_verdict["security_verdict"] = "pass"
        with self.assertRaisesRegex(ValueError, "must not claim"):
            future_security_classification_review_request_from_dict(
                forged_verdict
            )

    def test_digest_tampering_fails_closed(self):
        *_, request = self._producer(suffix="classification-handoff-digest")
        payload = json.loads(request.to_json())
        payload["classification_review_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_classification_review_request_from_dict(payload)

    def test_real_producer_round_trip_still_requires_live_validation(self):
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
            request,
        ) = self._producer(suffix="classification-handoff-live")

        parsed = future_security_classification_review_request_from_dict(
            json.loads(request.to_json())
        )
        validated = validate_future_security_classification_review_request(
            parsed,
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
        self.assertEqual(validated, request)

        drifted_attestation = dataclasses.replace(
            attestation,
            attestation_sha256="0" * 64,
        )
        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            validate_future_security_classification_review_request(
                parsed,
                drifted_attestation,
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


if __name__ == "__main__":
    unittest.main()
