from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_metadata_contract_review as review_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_sufficiency_review_request import (
    REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
    SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
    build_future_security_evidence_sufficiency_review_request,
    validate_future_security_evidence_sufficiency_review_request,
)


class FutureSecurityEvidenceSufficiencyReviewRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureSecurityEvidenceMetadataContractReviewTest(
            "test_valid_metadata_contract_is_reviewed_without_selecting_classification"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _request(self, *, suffix: str):
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
        ) = self.base._review(suffix=suffix)
        current_before = dataclasses.asdict(current)
        result = build_future_security_evidence_sufficiency_review_request(
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
        self.assertEqual(dataclasses.asdict(current), current_before)
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
            result,
        )

    def test_live_metadata_review_becomes_bounded_independent_review_request(self):
        (
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            request,
            constraints,
            candidate_context,
            admission,
            review,
            result,
        ) = self._request(suffix="sufficiency-request-live")

        self.assertEqual(
            result.schema_version,
            SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(result.request_sha256, request.request_sha256)
        self.assertEqual(result.constraints_sha256, constraints.constraints_sha256)
        self.assertEqual(result.admission_sha256, admission.admission_sha256)
        self.assertEqual(result.metadata_review_sha256, review.review_sha256)
        self.assertEqual(result.candidate_run_id, candidate_context.run_id)
        self.assertEqual(
            result.candidate_classification_claim,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )
        self.assertEqual(
            result.required_checks,
            REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
        )
        self.assertTrue(result.metadata_contract_verified)
        self.assertTrue(result.freshness_check_passed)
        self.assertTrue(result.independent_verifier_required)
        self.assertTrue(result.review_required)
        self.assertFalse(result.evidence_sufficiency_evaluated)
        self.assertFalse(result.classification_selected)
        self.assertFalse(result.transition_resolution_created)
        self.assertFalse(result.collection_authorized)
        self.assertFalse(result.tool_call_created)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.remediation_authoring_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)
        self.assertEqual(result.future_semantics, "unresolved")
        self.assertEqual(result.security_verdict, "not_evaluated")

        exported = json.loads(result.to_json())
        self.assertEqual(
            exported["candidate_classification_claim"],
            "insufficient_evidence",
        )
        self.assertEqual(
            exported["required_checks"],
            list(REQUIRED_SUFFICIENCY_REVIEW_CHECKS),
        )
        for forbidden in (
            "metadata",
            "payload",
            "source",
            "target",
            "arguments",
            "credentials",
        ):
            self.assertNotIn(forbidden, exported)

    def test_request_is_deterministic(self):
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
            first,
        ) = self._request(suffix="sufficiency-request-deterministic")
        second = build_future_security_evidence_sufficiency_review_request(
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
        self.assertEqual(first, second)
        self.assertEqual(len(first.sufficiency_request_sha256), 64)
        int(first.sufficiency_request_sha256, 16)

    def test_tampered_metadata_review_fails_closed_before_request(self):
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
        ) = self._request(suffix="sufficiency-request-tampered-review")
        tampered = dataclasses.replace(review, review_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            build_future_security_evidence_sufficiency_review_request(
                tampered,
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

    def test_live_candidate_lineage_drift_fails_closed(self):
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
        ) = self._request(suffix="sufficiency-request-lineage-drift")
        evidence_id = admission.candidate_evidence_ids[0]
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET capability_id=? WHERE evidence_id=?",
                ("drifted-capability", evidence_id),
            )

        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            build_future_security_evidence_sufficiency_review_request(
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

    def test_persisted_request_cannot_forge_review_or_authority_semantics(self):
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
            result,
        ) = self._request(suffix="sufficiency-request-forged-semantics")

        forged = (
            dataclasses.replace(result, evidence_sufficiency_evaluated=True),
            dataclasses.replace(result, classification_selected=True),
            dataclasses.replace(result, execution_allowed=True),
            dataclasses.replace(
                result,
                required_checks=("evidence_sufficiency",),
            ),
        )
        for tampered in forged:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(ValueError, "live validated lineage"):
                    validate_future_security_evidence_sufficiency_review_request(
                        tampered,
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

    def test_persisted_request_must_match_live_rebuilt_lineage(self):
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
            result,
        ) = self._request(suffix="sufficiency-request-persisted")

        validated = validate_future_security_evidence_sufficiency_review_request(
            result,
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
        self.assertEqual(validated, result)

        tampered = dataclasses.replace(
            result,
            sufficiency_request_sha256="0" * 64,
        )
        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            validate_future_security_evidence_sufficiency_review_request(
                tampered,
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


if __name__ == "__main__":
    unittest.main()
