from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review import (
    RemediationTextReviewDecision,
)
from lightup.future_remediation_text_review_request import (
    REQUIRED_REVIEW_CHECKS,
)


class FutureRemediationTextDirectStructureTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.proposal = self.base.base.proposal
        self.review_request = self.base.base.review_request
        self.review = self.base.review

    def test_valid_chain_artifacts_preserve_canonical_structure(self):
        self.assertGreater(self.proposal.item_count, 0)
        self.assertEqual(
            self.review_request.required_checks,
            REQUIRED_REVIEW_CHECKS,
        )
        self.assertEqual(
            self.review.decision,
            RemediationTextReviewDecision.APPROVED,
        )
        self.assertTrue(self.review.remediation_accepted)

    def test_proposal_rejects_schema_count_and_provenance_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.proposal,
                schema_version="st5.remediation_text_proposal.v2",
            )

        for value in (0, True):
            with self.subTest(item_count=value):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    replace(self.proposal, item_count=value)

        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.proposal, **{field: ""})

    def test_proposal_rejects_digest_and_content_forgery(self):
        for field in (
            "request_sha256",
            "bundle_sha256",
            "content_sha256",
            "proposal_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.proposal, **{field: "ABC"})

        with self.assertRaisesRegex(ValueError, "non-empty string"):
            replace(self.proposal, content="   ")

        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(self.proposal, content="safe\x00unsafe")

        with self.assertRaisesRegex(ValueError, "bounded output size"):
            replace(self.proposal, content="x" * 16001)

        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            replace(self.proposal, content_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "proposal digest mismatch"):
            replace(self.proposal, proposal_sha256="0" * 64)

    def test_review_request_rejects_schema_count_and_provenance_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.review_request,
                schema_version="st5.remediation_text_review_request.v2",
            )

        for value in (0, True):
            with self.subTest(item_count=value):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    replace(self.review_request, item_count=value)

        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.review_request, **{field: ""})

    def test_review_request_rejects_digest_and_rubric_forgery(self):
        for field in (
            "request_sha256",
            "bundle_sha256",
            "proposal_sha256",
            "content_sha256",
            "review_request_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.review_request, **{field: "ABC"})

        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(
                self.review_request,
                required_checks=list(REQUIRED_REVIEW_CHECKS),
            )

        with self.assertRaisesRegex(ValueError, "required_checks mismatch"):
            replace(
                self.review_request,
                required_checks=tuple(reversed(REQUIRED_REVIEW_CHECKS)),
            )

        with self.assertRaisesRegex(ValueError, "review request digest mismatch"):
            replace(self.review_request, review_request_sha256="0" * 64)

    def test_review_rejects_schema_digest_and_reviewer_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.review,
                schema_version="st5.remediation_text_review.v2",
            )

        for field in (
            "review_request_sha256",
            "proposal_sha256",
            "content_sha256",
            "review_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.review, **{field: "ABC"})

        for field in ("reviewer_provider_id", "reviewer_model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.review, **{field: ""})

    def test_review_rejects_check_shape_order_and_result_forgery(self):
        with self.assertRaisesRegex(ValueError, "checks must be a tuple"):
            replace(self.review, checks=list(self.review.checks))

        with self.assertRaisesRegex(ValueError, "checks count mismatch"):
            replace(self.review, checks=self.review.checks[:-1])

        with self.assertRaisesRegex(ValueError, "check order or name mismatch"):
            replace(self.review, checks=tuple(reversed(self.review.checks)))

        bad_result = replace(self.review.checks[0], result="bogus")
        with self.assertRaisesRegex(ValueError, "result .* is invalid"):
            replace(
                self.review,
                checks=(bad_result,) + self.review.checks[1:],
            )

    def test_review_rejects_decision_check_incoherence(self):
        failed = replace(self.review.checks[0], result="fail")
        checks = (failed,) + self.review.checks[1:]

        with self.assertRaisesRegex(ValueError, "every check to pass"):
            replace(self.review, checks=checks)

        with self.assertRaisesRegex(ValueError, "requires a non-pass check"):
            replace(
                self.review,
                decision=RemediationTextReviewDecision.REVISION_REQUIRED,
                remediation_accepted=False,
            )

        with self.assertRaisesRegex(ValueError, "requires an unclear check"):
            replace(
                self.review,
                decision=RemediationTextReviewDecision.INSUFFICIENT_EVIDENCE,
                remediation_accepted=False,
                checks=checks,
            )

    def test_review_rejects_noncanonical_summary_and_digest(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            replace(self.review, summary="   ")

        with self.assertRaisesRegex(ValueError, "canonical trimmed text"):
            replace(self.review, summary=" padded ")

        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(self.review, summary="safe\x00unsafe")

        with self.assertRaisesRegex(ValueError, "bounded size"):
            replace(self.review, summary="x" * 4001)

        with self.assertRaisesRegex(ValueError, "review digest mismatch"):
            replace(self.review, review_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
