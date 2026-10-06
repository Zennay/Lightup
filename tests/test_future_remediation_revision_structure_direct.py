from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests
from lightup.future_remediation_text_review import (
    RemediationTextReviewCheck,
    RemediationTextReviewDecision,
)
from lightup.future_remediation_text_review_request import REQUIRED_REVIEW_CHECKS


class FutureRemediationRevisionStructureDirectTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _artifacts(self):
        final_review = self.base.review
        revised_review_request = self.base.base.base.request
        revised_proposal = self.base.base.base.base.base.proposal
        revision_request = self.base.base.base.base.base.base.revision_request
        return (
            revision_request,
            revised_proposal,
            revised_review_request,
            final_review,
        )

    def test_valid_chain_is_structurally_canonical(self):
        revision_request, proposal, review_request, review = self._artifacts()

        self.assertTrue(revision_request.revision_checks)
        self.assertEqual(proposal.content, proposal.content.strip())
        self.assertEqual(review_request.required_checks, REQUIRED_REVIEW_CHECKS)
        self.assertEqual(
            tuple(check.check for check in review.checks),
            REQUIRED_REVIEW_CHECKS,
        )
        self.assertEqual(review.summary, review.summary.strip())

    def test_revision_request_rejects_schema_and_digest_shape_forgery(self):
        request = self._artifacts()[0]
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(request, schema_version="st5.remediation_text_revision_request.v0")

        for field in (
            "review_sha256",
            "review_request_sha256",
            "proposal_sha256",
            "content_sha256",
            "revision_request_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(request, **{field: "ABC"})

    def test_revision_request_rejects_noncanonical_revision_checks(self):
        request = self._artifacts()[0]

        with self.assertRaisesRegex(ValueError, "non-empty tuple"):
            replace(request, revision_checks=[])
        with self.assertRaisesRegex(ValueError, "non-empty tuple"):
            replace(request, revision_checks=())
        with self.assertRaisesRegex(ValueError, "must be unique"):
            replace(
                request,
                revision_checks=(request.revision_checks[0], request.revision_checks[0]),
            )
        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            replace(request, revision_checks=("unknown-check",))

        if len(REQUIRED_REVIEW_CHECKS) >= 2:
            with self.assertRaisesRegex(ValueError, "invalid or out of order"):
                replace(
                    request,
                    revision_checks=(
                        REQUIRED_REVIEW_CHECKS[1],
                        REQUIRED_REVIEW_CHECKS[0],
                    ),
                )

    def test_revision_request_recomputes_digest(self):
        request = self._artifacts()[0]
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(request, revision_request_sha256="0" * 64)

        replacement = "f" * 64
        if replacement == request.review_sha256:
            replacement = "e" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(request, review_sha256=replacement)

    def test_revision_proposal_rejects_schema_lineage_and_provenance_forgery(self):
        proposal = self._artifacts()[1]
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                proposal,
                schema_version="st5.remediation_text_revision_proposal.v0",
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
                    replace(proposal, **{field: "ABC"})

        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(proposal, **{field: "   "})

    def test_revision_proposal_rejects_noncanonical_content(self):
        proposal = self._artifacts()[1]

        padded = " " + proposal.content
        padded_sha = sha256(padded.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "canonical trimmed text"):
            replace(proposal, content=padded, content_sha256=padded_sha)

        nul = proposal.content + "\x00"
        nul_sha = sha256(nul.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(proposal, content=nul, content_sha256=nul_sha)

        oversized = "x" * 16001
        oversized_sha = sha256(oversized.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "bounded output size"):
            replace(proposal, content=oversized, content_sha256=oversized_sha)

        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            replace(proposal, content=proposal.content + " changed")

    def test_revision_proposal_recomputes_full_digest(self):
        proposal = self._artifacts()[1]
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(proposal, revision_proposal_sha256="0" * 64)

        changed = proposal.content + " changed"
        changed_sha = sha256(changed.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(
                proposal,
                content=changed,
                content_sha256=changed_sha,
            )

    def test_revision_review_request_rejects_structure_and_provenance_forgery(self):
        request = self._artifacts()[2]

        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                request,
                schema_version="st5.remediation_text_revision_review_request.v0",
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
                    replace(request, **{field: "ABC"})

        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(request, **{field: "   "})

        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(request, required_checks=list(REQUIRED_REVIEW_CHECKS))
        with self.assertRaisesRegex(ValueError, "required_checks mismatch"):
            replace(request, required_checks=REQUIRED_REVIEW_CHECKS[:-1])

    def test_revision_review_request_recomputes_digest(self):
        request = self._artifacts()[2]
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(request, review_request_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(request, provider_id=request.provider_id + "-other")

    def test_final_review_rejects_schema_digest_and_provenance_forgery(self):
        review = self._artifacts()[3]

        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(review, schema_version="st5.remediation_text_revision_review.v0")

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
                    replace(review, **{field: "ABC"})

        for field in ("reviewer_provider_id", "reviewer_model_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(review, **{field: "   "})

    def test_final_review_rejects_noncanonical_checks(self):
        review = self._artifacts()[3]

        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            replace(review, checks=list(review.checks))
        with self.assertRaisesRegex(ValueError, "checks count mismatch"):
            replace(review, checks=review.checks[:-1])
        with self.assertRaisesRegex(ValueError, "RemediationTextReviewCheck"):
            replace(review, checks=("forged",) + review.checks[1:])

        reversed_checks = tuple(reversed(review.checks))
        with self.assertRaisesRegex(ValueError, "order or name mismatch"):
            replace(review, checks=reversed_checks)

        invalid = replace(review.checks[0], result="maybe")
        with self.assertRaisesRegex(ValueError, "result .* is invalid"):
            replace(review, checks=(invalid,) + review.checks[1:])

    def test_final_review_rejects_decision_check_incoherence(self):
        review = self._artifacts()[3]
        failed = replace(review.checks[0], result="fail")
        with self.assertRaisesRegex(ValueError, "every check to pass"):
            replace(review, checks=(failed,) + review.checks[1:])

        with self.assertRaisesRegex(ValueError, "requires an unclear check"):
            replace(
                review,
                decision=RemediationTextReviewDecision.INSUFFICIENT_EVIDENCE,
                remediation_accepted=False,
            )

    def test_final_review_rejects_noncanonical_summary(self):
        review = self._artifacts()[3]

        with self.assertRaisesRegex(ValueError, "non-empty string"):
            replace(review, summary="   ")
        with self.assertRaisesRegex(ValueError, "canonical trimmed text"):
            replace(review, summary=" " + review.summary)
        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(review, summary=review.summary + "\x00")
        with self.assertRaisesRegex(ValueError, "bounded size"):
            replace(review, summary="x" * 4001)

    def test_final_review_recomputes_digest(self):
        review = self._artifacts()[3]

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(review, review_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(review, reviewer_model_id=review.reviewer_model_id + "-other")


if __name__ == "__main__":
    unittest.main()
