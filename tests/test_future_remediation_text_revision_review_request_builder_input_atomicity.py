from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_text_revision_review_request as request_tests
from lightup.future_remediation_text_revision_review_request import (
    build_future_remediation_text_revision_review_request,
)


class FutureRemediationTextRevisionReviewRequestBuilderInputAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationTextRevisionReviewRequestTest(
            "test_live_revision_proposal_requests_independent_review_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _upstream(self):
        return self.base.base.base.base.base.base

    def _snapshot_lineage(self) -> tuple:
        upstream = self._upstream()
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.base.base.proposal,
                self.base.base.base.revision_request,
                self.base.base.base.review,
                self.base.base.base.base.base.review_request,
                self.base.base.base.base.base.proposal,
                upstream.request,
                upstream.bundle,
                upstream.plan,
                upstream.report,
                upstream.preview,
                upstream.transition_proposal,
                upstream.resolution,
                upstream.context,
            )
        )

    def _persisted_payloads(self) -> tuple[dict, dict, dict, dict, dict]:
        return (
            json.loads(self.base.base.proposal.to_json()),
            json.loads(self.base.base.base.revision_request.to_json()),
            json.loads(self.base.base.base.review.to_json()),
            json.loads(self.base.base.base.base.base.review_request.to_json()),
            json.loads(self.base.base.base.base.base.proposal.to_json()),
        )

    def _build(self, payloads: tuple[dict, dict, dict, dict, dict]):
        (
            revision_proposal_payload,
            revision_request_payload,
            review_payload,
            prior_review_request_payload,
            prior_proposal_payload,
        ) = payloads
        upstream = self._upstream()
        return build_future_remediation_text_revision_review_request(
            revision_proposal_payload,
            revision_request_payload,
            review_payload,
            prior_review_request_payload,
            prior_proposal_payload,
            upstream.request,
            upstream.bundle,
            upstream.plan,
            upstream.report,
            upstream.preview,
            upstream.transition_proposal,
            (upstream.resolution,),
            (upstream.context,),
            upstream.state,
        )

    def _write_sentinels(self):
        state = self._upstream().state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError(
                    "revised review-request builder must not create runs"
                ),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError(
                    "revised review-request builder must not acquire leases"
                ),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError(
                    "revised review-request builder must not add evidence"
                ),
            ),
        )

    def test_successful_build_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        upstream = self._upstream()
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(upstream.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._build(payloads)
            second = self._build(payloads)

        self.assertEqual(first, second)
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.review_requested)
        self.assertFalse(first.remediation_accepted)
        self.assertFalse(first.code_change_authorized)
        self.assertFalse(first.tool_call_created)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.target_interaction_allowed)
        self.assertFalse(first.future_state_retest_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_live_rejection_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        upstream = self._upstream()
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        current_sha = upstream.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with upstream.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            upstream.state.get_evidence(evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                with self.assertRaises(ValueError) as caught:
                    self._build(payloads)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
