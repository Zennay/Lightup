from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests
from lightup.future_remediation_text_review import (
    RemediationTextReviewDecision,
)
from lightup.future_remediation_text_review_request import (
    REQUIRED_REVIEW_CHECKS,
)


class FutureRemediationRevisionDirectStructureTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.final_review = self.base.review
        self.revised_review_request = self.base.base.base.request
        self.revised_proposal = self.base.base.base.base.base.proposal
        self.revision_request = (
            self.base.base.base.base.base.base.revision_request
        )

    def test_valid_revision_chain_preserves_canonical_structure(self):
        self.assertTrue(self.revision_request.revision_checks)
        self.assertEqual(
            self.revised_review_request.required_checks,
            REQUIRED_REVIEW_CHECKS,
        )
        self.assertEqual(
            self.final_review.decision,
            RemediationTextReviewDecision.APPROVED,
        )
        self.assertTrue(self.final_review.remediation_accepted)

    def test_revision_request_rejects_schema_and_digest_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.revision_request,
                schema_version="st5.remediation_text_revision_request.v2",
            )

        for field in (
            "review_sha256",
            "review_request_sha256",
            "proposal_sha256",
            "content_sha256",
            "revision_request_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.revision_request, **{field: "ABC"})

        with self.assertRaisesRegex(ValueError, "revision request digest mismatch"):
            replace(self.revision_request, revision_request_sha256="0" * 64)

    def test_revision_request_rejects_noncanonical_revision_checks(self):
        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(
                self.revision_request,
                revision_checks=list(self.revision_request.revision_checks),
            )

        with self.assertRaisesRegex(ValueError, "must be non-empty"):
            replace(self.revision_request, revision_checks=())

        with self.assertRaisesRegex(ValueError, "must contain strings"):
            replace(self.revision_request, revision_checks=(1,))

        first = self.revision_request.revision_checks[0]
        with self.assertRaisesRegex(ValueError, "must be unique"):
            replace(self.revision_request, revision_checks=(first, first))

        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            replace(self.revision_request, revision_checks=(first, "unknown_check"))

    def test_revised_proposal_rejects_schema_provenance_and_digest_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.revised_proposal,
                schema_version="st5.remediation_text_revision_proposal.v2",
            )

        for field in (
            "revision_request_sha256",
            "prior_review_sha256",
            "prior_proposal_sha256",
            "prior_content_sha256",
            "content_sha256",
            "revision_proposal_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.revised_proposal, **{field: "ABC"})

        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.revised_proposal, **{field: ""})

    def test_revised_proposal_rejects_noncanonical_content(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            replace(self.revised_proposal, content="   ")

        with self.assertRaisesRegex(ValueError, "canonical trimmed text"):
            replace(self.revised_proposal, content=" padded ")

        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(self.revised_proposal, content="safe\x00unsafe")

        with self.assertRaisesRegex(ValueError, "bounded output size"):
            replace(self.revised_proposal, content="x" * 16001)

        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            replace(self.revised_proposal, content_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "revision proposal digest mismatch"):
            replace(self.revised_proposal, revision_proposal_sha256="0" * 64)

    def test_revised_review_request_rejects_schema_provenance_and_rubric_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.revised_review_request,
                schema_version="st5.remediation_text_revision_review_request.v2",
            )

        for field in (
            "revision_proposal_sha256",
            "revision_request_sha256",
            "prior_review_sha256",
            "content_sha256",
            "review_request_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.revised_review_request, **{field: "ABC"})

        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.revised_review_request, **{field: ""})

        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(
                self.revised_review_request,
                required_checks=list(REQUIRED_REVIEW_CHECKS),
            )

        with self.assertRaisesRegex(ValueError, "required_checks mismatch"):
            replace(
                self.revised_review_request,
                required_checks=tuple(reversed(REQUIRED_REVIEW_CHECKS)),
            )

        with self.assertRaisesRegex(ValueError, "review request digest mismatch"):
            replace(self.revised_review_request, review_request_sha256="0" * 64)

    def test_revised_review_rejects_schema_digest_and_reviewer_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.final_review,
                schema_version="st5.remediation_text_revision_review.v2",
            )

        for field in (
            "review_request_sha256",
            "revision_proposal_sha256",
            "revision_request_sha256",
            "prior_review_sha256",
            "content_sha256",
            "review_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.final_review, **{field: "ABC"})

        for field in ("reviewer_provider_id", "reviewer_model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.final_review, **{field: ""})

    def test_revised_review_rejects_check_shape_order_and_result_forgery(self):
        with self.assertRaisesRegex(ValueError, "checks must be a tuple"):
            replace(self.final_review, checks=list(self.final_review.checks))

        with self.assertRaisesRegex(ValueError, "checks count mismatch"):
            replace(self.final_review, checks=self.final_review.checks[:-1])

        with self.assertRaisesRegex(ValueError, "check order or name mismatch"):
            replace(
                self.final_review,
                checks=tuple(reversed(self.final_review.checks)),
            )

        bad_result = replace(self.final_review.checks[0], result="bogus")
        with self.assertRaisesRegex(ValueError, "result .* is invalid"):
            replace(
                self.final_review,
                checks=(bad_result,) + self.final_review.checks[1:],
            )

    def test_revised_review_rejects_decision_check_incoherence(self):
        failed = replace(self.final_review.checks[0], result="fail")
        failed_checks = (failed,) + self.final_review.checks[1:]

        with self.assertRaisesRegex(ValueError, "every check to pass"):
            replace(self.final_review, checks=failed_checks)

        with self.assertRaisesRegex(ValueError, "requires a non-pass check"):
            replace(
                self.final_review,
                decision=RemediationTextReviewDecision.REVISION_REQUIRED,
                remediation_accepted=False,
            )

        with self.assertRaisesRegex(ValueError, "requires an unclear check"):
            replace(
                self.final_review,
                decision=RemediationTextReviewDecision.INSUFFICIENT_EVIDENCE,
                remediation_accepted=False,
                checks=failed_checks,
            )

    def test_revised_review_rejects_noncanonical_summary_and_digest(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            replace(self.final_review, summary="   ")

        with self.assertRaisesRegex(ValueError, "canonical trimmed text"):
            replace(self.final_review, summary=" padded ")

        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(self.final_review, summary="safe\x00unsafe")

        with self.assertRaisesRegex(ValueError, "bounded size"):
            replace(self.final_review, summary="x" * 4001)

        with self.assertRaisesRegex(ValueError, "review digest mismatch"):
            replace(self.final_review, review_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
