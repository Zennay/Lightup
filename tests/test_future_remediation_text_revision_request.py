from __future__ import annotations

import unittest

import test_future_remediation_text_review as review_tests
from lightup.future_remediation_text_revision_request import (
    REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
    build_future_remediation_text_revision_request,
)


class FutureRemediationTextRevisionRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _review(self, content: str):
        gateway, _ = self.base._review_gateway(content)
        return self.base._review(gateway)

    def _build(self, review):
        return build_future_remediation_text_revision_request(
            review.to_json(),
            self.base.review_request.to_json(),
            self.base.proposal.to_json(),
            self.base.base.request,
            self.base.base.bundle,
            self.base.base.plan,
            self.base.base.report,
            self.base.base.preview,
            self.base.base.transition_proposal,
            (self.base.base.resolution,),
            (self.base.base.context,),
            self.base.base.state,
        )

    def test_revision_required_creates_bounded_non_executable_request(self):
        review = self._review(
            review_tests._review_json(
                decision="revision_required",
                unsupported_claims="fail",
            )
        )

        request = self._build(review)

        self.assertEqual(
            request.schema_version,
            REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(request.review_sha256, review.review_sha256)
        self.assertEqual(
            request.review_request_sha256,
            review.review_request_sha256,
        )
        self.assertEqual(request.proposal_sha256, review.proposal_sha256)
        self.assertEqual(request.content_sha256, review.content_sha256)
        self.assertEqual(request.review_decision, "revision_required")
        self.assertEqual(request.revision_checks, ("unsupported_claims",))
        self.assertTrue(request.revision_requested)
        self.assertFalse(request.remediation_accepted)
        self.assertFalse(request.code_change_authorized)
        self.assertFalse(request.tool_call_created)
        self.assertFalse(request.execution_allowed)
        self.assertFalse(request.target_interaction_allowed)
        self.assertFalse(request.future_state_retest_allowed)
        self.assertFalse(request.deployment_authorized)
        self.assertFalse(request.attack_path_mutation_allowed)
        self.assertEqual(request.future_semantics, "unresolved")
        self.assertEqual(request.security_verdict, "not_evaluated")
        self.assertEqual(len(request.revision_request_sha256), 64)

    def test_revision_checks_preserve_canonical_review_order(self):
        review = self._review(
            review_tests._review_json(
                decision="revision_required",
                evidence_alignment="unclear",
                unsupported_claims="fail",
                future_retest_separation="fail",
            )
        )

        request = self._build(review)

        self.assertEqual(
            request.revision_checks,
            (
                "evidence_alignment",
                "unsupported_claims",
                "future_retest_separation",
            ),
        )

    def test_approved_review_cannot_enter_revision_path(self):
        review = self._review(review_tests._review_json())

        with self.assertRaisesRegex(ValueError, "approved remediation text"):
            self._build(review)

    def test_insufficient_evidence_must_return_to_evidence_collection(self):
        review = self._review(
            review_tests._review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            )
        )

        with self.assertRaisesRegex(ValueError, "requires fresh evidence"):
            self._build(review)

    def test_live_evidence_drift_fails_before_request_creation(self):
        review = self._review(
            review_tests._review_json(
                decision="revision_required",
                least_privilege="fail",
            )
        )
        evidence_id = self.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._build(review)

    def test_tampered_persisted_review_fails_closed(self):
        review = self._review(
            review_tests._review_json(
                decision="revision_required",
                least_privilege="fail",
            )
        )
        persisted = review.as_dict()
        persisted["execution_allowed"] = True

        with self.assertRaisesRegex(ValueError, "authority flag"):
            build_future_remediation_text_revision_request(
                persisted,
                self.base.review_request.to_json(),
                self.base.proposal.to_json(),
                self.base.base.request,
                self.base.base.bundle,
                self.base.base.plan,
                self.base.base.report,
                self.base.base.preview,
                self.base.base.transition_proposal,
                (self.base.base.resolution,),
                (self.base.base.context,),
                self.base.base.state,
            )

    def test_same_review_lineage_produces_same_revision_request(self):
        content = review_tests._review_json(
            decision="revision_required",
            unsupported_claims="fail",
        )
        first = self._build(self._review(content))
        second = self._build(self._review(content))

        self.assertEqual(first.revision_request_sha256, second.revision_request_sha256)
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
