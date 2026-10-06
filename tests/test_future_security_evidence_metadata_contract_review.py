from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_freshness as freshness_tests
from lightup.ai.orchestration import RunContext
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    future_attack_path_transition_evidence_contract,
)
from lightup.future_security_evidence_freshness_admission import (
    admit_future_security_evidence_freshness,
)
from lightup.future_security_evidence_metadata_contract_review import (
    REVIEW_SCHEMA_VERSION,
    review_future_security_evidence_metadata_contract,
    validate_future_security_evidence_metadata_contract_review,
)


class FutureSecurityEvidenceMetadataContractReviewTest(unittest.TestCase):
    def setUp(self):
        self.base = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _fixture(
        self,
        *,
        suffix: str,
        metadata_overrides: tuple[dict, ...] | None = None,
        kind: str = "future-transition-verification",
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
        ) = self.base._constraints(suffix=suffix)

        run_id = self.state.create_run(
            target=f"127.0.0.1-{suffix}",
            activation_mode="lab_autonomous",
        )
        candidate_context = RunContext.for_lab(
            run_id,
            engagement_id=source_context.engagement_id,
            client_id=source_context.client_id,
        )
        base_metadata = future_attack_path_transition_evidence_contract(
            proposal,
            change_node_id=resolution.change_node_id,
            classification=AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            context=candidate_context,
        )
        overrides = metadata_overrides or ({},)
        evidence_ids = []
        for index, override in enumerate(overrides):
            metadata = dict(base_metadata)
            metadata.update(override)
            evidence_ids.append(
                self.state.add_evidence(
                    run_id,
                    "web",
                    kind,
                    f"test://{suffix}/{index}",
                    f"candidate-{suffix}-{index}".encode("utf-8"),
                    metadata=metadata,
                )
            )
        evidence_ids = tuple(sorted(evidence_ids))
        admission = admit_future_security_evidence_freshness(
            constraints,
            source_resolution_id=resolution.resolution_id,
            candidate_evidence_ids=evidence_ids,
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
        )

    def _review(self, *, suffix: str):
        fixture = self._fixture(suffix=suffix)
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
        ) = fixture
        review = review_future_security_evidence_metadata_contract(
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
        return fixture + (review,)

    def test_valid_metadata_contract_is_reviewed_without_selecting_classification(self):
        (
            current,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            admission,
            review,
        ) = self._review(suffix="metadata-review-valid")
        current_before = dataclasses.asdict(current)

        self.assertEqual(review.schema_version, REVIEW_SCHEMA_VERSION)
        self.assertEqual(review.admission_sha256, admission.admission_sha256)
        self.assertEqual(
            review.candidate_classification_claim,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )
        self.assertTrue(review.metadata_contract_verified)
        self.assertTrue(review.freshness_check_passed)
        self.assertFalse(review.evidence_sufficiency_evaluated)
        self.assertFalse(review.classification_selected)
        self.assertFalse(review.transition_resolution_created)
        self.assertFalse(review.collection_authorized)
        self.assertFalse(review.tool_call_created)
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.remediation_authoring_allowed)
        self.assertFalse(review.future_state_retest_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)
        self.assertEqual(review.security_verdict, "not_evaluated")
        self.assertEqual(dataclasses.asdict(current), current_before)

        exported = json.loads(review.to_json())
        self.assertEqual(
            exported["candidate_classification_claim"],
            "insufficient_evidence",
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

    def test_non_transition_kind_and_missing_contract_metadata_fail_closed(self):
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
        ) = self._fixture(
            suffix="metadata-review-kind",
            kind="freshness-candidate",
        )
        with self.assertRaisesRegex(ValueError, "kind is not transition-verification"):
            review_future_security_evidence_metadata_contract(
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

        fixture = self._fixture(suffix="metadata-review-missing")
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
        ) = fixture
        evidence_id = admission.candidate_evidence_ids[0]
        record = self.state.get_evidence(evidence_id)
        metadata = dict(record.metadata)
        del metadata["proposal_sha256"]
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET metadata_json=? WHERE evidence_id=?",
                (
                    json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                    evidence_id,
                ),
            )

        with self.assertRaisesRegex(ValueError, "metadata contract mismatch"):
            review_future_security_evidence_metadata_contract(
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

    def test_mixed_or_unsupported_classification_claims_fail_closed(self):
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
        ) = self._fixture(
            suffix="metadata-review-mixed",
            metadata_overrides=(
                {},
                {"classification": "introduced"},
            ),
        )
        with self.assertRaisesRegex(ValueError, "one consistent classification claim"):
            review_future_security_evidence_metadata_contract(
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
        ) = self._fixture(
            suffix="metadata-review-unsupported",
            metadata_overrides=({"classification": "not-a-classification"},),
        )
        with self.assertRaisesRegex(ValueError, "claim is unsupported"):
            review_future_security_evidence_metadata_contract(
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

    def test_review_is_deterministic_and_live_validator_rejects_metadata_drift(self):
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
            first,
        ) = self._review(suffix="metadata-review-deterministic")
        second = review_future_security_evidence_metadata_contract(
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
        self.assertEqual(len(first.review_sha256), 64)
        int(first.review_sha256, 16)

        validated = validate_future_security_evidence_metadata_contract_review(
            first,
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
        self.assertEqual(validated, first)

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
            validate_future_security_evidence_metadata_contract_review(
                first,
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
