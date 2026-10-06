from __future__ import annotations

import unittest

import test_future_remediation_text_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_text_revision_review_request import (
    REMEDIATION_TEXT_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
    build_future_remediation_text_revision_review_request,
)
from lightup.future_remediation_text_review_request import REQUIRED_REVIEW_CHECKS


class FutureRemediationTextRevisionReviewRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionProposalHandoffTest(
            "test_round_trip_requires_complete_live_revision_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _build(self, persisted=None):
        return build_future_remediation_text_revision_review_request(
            self.base.proposal.to_json() if persisted is None else persisted,
            self.base.base.revision_request.to_json(),
            self.base.base.review.to_json(),
            self.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.request,
            self.base.base.base.base.base.bundle,
            self.base.base.base.base.base.plan,
            self.base.base.base.base.base.report,
            self.base.base.base.base.base.preview,
            self.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.context,),
            self.base.base.base.base.base.state,
        )

    def test_live_revision_proposal_requests_independent_review_only(self):
        request = self._build()
        proposal = self.base.proposal

        self.assertEqual(
            request.schema_version,
            REMEDIATION_TEXT_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(
            request.revision_proposal_sha256,
            proposal.revision_proposal_sha256,
        )
        self.assertEqual(
            request.revision_request_sha256,
            proposal.revision_request_sha256,
        )
        self.assertEqual(request.prior_review_sha256, proposal.prior_review_sha256)
        self.assertEqual(request.content_sha256, proposal.content_sha256)
        self.assertEqual(request.provider_id, proposal.provider_id)
        self.assertEqual(request.model_id, proposal.model_id)
        self.assertEqual(request.required_checks, REQUIRED_REVIEW_CHECKS)
        self.assertTrue(request.review_requested)
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
        self.assertEqual(len(request.review_request_sha256), 64)

    def test_same_revision_proposal_produces_same_review_request(self):
        first = self._build()
        second = self._build()

        self.assertEqual(first.review_request_sha256, second.review_request_sha256)
        self.assertEqual(first.to_json(), second.to_json())

    def test_live_evidence_drift_fails_before_review_request_creation(self):
        evidence_id = self.base.base.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._build()

    def test_tampered_revision_proposal_fails_closed(self):
        persisted = self.base.proposal.as_dict()
        persisted["remediation_accepted"] = True

        with self.assertRaisesRegex(ValueError, "remediation_accepted"):
            self._build(persisted)


if __name__ == "__main__":
    unittest.main()
