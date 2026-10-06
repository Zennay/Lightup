from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_sufficiency_attestation as attestation_tests
from lightup.future_security_classification_review_request import (
    CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION,
    build_future_security_classification_review_request,
    validate_future_security_classification_review_request,
)
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)


class FutureSecurityClassificationReviewRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = attestation_tests.FutureSecurityEvidenceSufficiencyAttestationTest(
            "test_all_dispositions_derive_exact_fail_closed_semantics"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _build(
        self,
        *,
        disposition: EvidenceSufficiencyAttestationDisposition,
        suffix: str,
    ):
        (
            current,
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
            sufficiency_request,
            verifier,
            preflight,
            attestation,
        ) = self.base._attest(disposition, suffix=suffix)
        before = dataclasses.asdict(current)
        classification_request = build_future_security_classification_review_request(
            attestation,
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
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
        self.assertEqual(dataclasses.asdict(current), before)
        return (
            current,
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
            sufficiency_request,
            verifier,
            preflight,
            attestation,
            classification_request,
        )

    def test_positive_attestation_creates_bounded_deterministic_request(self):
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
            sufficiency_request,
            verifier,
            preflight,
            attestation,
            first,
        ) = self._build(
            disposition=(
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED
            ),
            suffix="classification-review-positive",
        )
        second = build_future_security_classification_review_request(
            attestation,
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
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
        self.assertEqual(first, second)
        self.assertEqual(
            first.schema_version,
            CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(first.attestation_sha256, attestation.attestation_sha256)
        self.assertEqual(
            first.evidence_collection_request_sha256,
            sufficiency_request.request_sha256,
        )
        self.assertEqual(
            first.freshness_constraints_sha256,
            sufficiency_request.constraints_sha256,
        )
        self.assertTrue(first.evidence_sufficient)
        self.assertTrue(first.classification_claim_justified)
        self.assertTrue(first.sufficiency_decision_created)
        self.assertTrue(first.evidence_sufficiency_evaluated)
        self.assertTrue(first.classification_justification_evaluated)
        self.assertTrue(first.eligible_for_classification_review)
        self.assertTrue(first.classification_review_required)
        self.assertFalse(first.classification_selected)
        self.assertFalse(first.transition_resolution_created)
        self.assertFalse(first.collection_authorized)
        self.assertFalse(first.tool_call_created)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.target_interaction_allowed)
        self.assertFalse(first.remediation_authoring_allowed)
        self.assertFalse(first.future_state_retest_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")
        self.assertEqual(len(first.classification_review_request_sha256), 64)
        int(first.classification_review_request_sha256, 16)

        exported = json.loads(first.to_json())
        for forbidden in (
            "metadata",
            "payload",
            "source",
            "target",
            "arguments",
            "credentials",
            "password",
            "session",
        ):
            self.assertNotIn(forbidden, exported)

    def test_noneligible_attestations_fail_closed(self):
        for disposition in (
            EvidenceSufficiencyAttestationDisposition.INSUFFICIENT_FOR_CLASSIFICATION,
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_UNJUSTIFIED,
        ):
            with self.subTest(disposition=disposition.value):
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
                    sufficiency_request,
                    verifier,
                    preflight,
                    attestation,
                ) = self.base._attest(
                    disposition,
                    suffix=f"classification-review-reject-{disposition.value}",
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "requires a sufficient, justified live attestation",
                ):
                    build_future_security_classification_review_request(
                        attestation,
                        preflight,
                        sufficiency_request,
                        review,
                        admission,
                        constraints,
                        verifier=verifier,
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

    def test_persisted_request_rejects_forged_authority_and_digest(self):
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
            sufficiency_request,
            verifier,
            preflight,
            attestation,
            classification_request,
        ) = self._build(
            disposition=(
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED
            ),
            suffix="classification-review-persisted",
        )

        validated = validate_future_security_classification_review_request(
            classification_request,
            attestation,
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
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
        self.assertEqual(validated, classification_request)

        forged = (
            dataclasses.replace(classification_request, classification_selected=True),
            dataclasses.replace(
                classification_request,
                transition_resolution_created=True,
            ),
            dataclasses.replace(classification_request, execution_allowed=True),
            dataclasses.replace(
                classification_request,
                remediation_authoring_allowed=True,
            ),
            dataclasses.replace(
                classification_request,
                classification_review_required=False,
            ),
            dataclasses.replace(
                classification_request,
                classification_review_request_sha256="0" * 64,
            ),
        )
        for tampered in forged:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    ValueError,
                    "does not match live validated lineage",
                ):
                    validate_future_security_classification_review_request(
                        tampered,
                        attestation,
                        preflight,
                        sufficiency_request,
                        review,
                        admission,
                        constraints,
                        verifier=verifier,
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

    def test_attestation_drift_fails_before_request_use(self):
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
            sufficiency_request,
            verifier,
            preflight,
            attestation,
            classification_request,
        ) = self._build(
            disposition=(
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED
            ),
            suffix="classification-review-attestation-drift",
        )
        drifted = dataclasses.replace(attestation, attestation_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            validate_future_security_classification_review_request(
                classification_request,
                drifted,
                preflight,
                sufficiency_request,
                review,
                admission,
                constraints,
                verifier=verifier,
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


if __name__ == "__main__":
    unittest.main()
