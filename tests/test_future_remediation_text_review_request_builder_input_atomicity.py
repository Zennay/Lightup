from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_text_review_request as request_tests
from lightup.future_remediation_text_review_request import (
    build_future_remediation_text_review_request,
)


class FutureRemediationTextReviewRequestBuilderInputAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationTextReviewRequestTest(
            "test_live_valid_proposal_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _snapshot_lineage(self) -> tuple:
        upstream = self.base.base
        return tuple(
            self._snapshot_value(value)
            for value in (
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

    def _build(self, persisted_proposal: dict):
        upstream = self.base.base
        return build_future_remediation_text_review_request(
            persisted_proposal,
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
        state = self.base.base.state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError(
                    "review-request builder must not create runs"
                ),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError(
                    "review-request builder must not acquire leases"
                ),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError(
                    "review-request builder must not add evidence"
                ),
            ),
        )

    def test_successful_build_is_repeatable_and_input_atomic(self):
        persisted_proposal = json.loads(self.base.proposal.to_json())
        persisted_before = copy.deepcopy(persisted_proposal)
        lineage_before = self._snapshot_lineage()

        upstream = self.base.base
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(upstream.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._build(persisted_proposal)
            second = self._build(persisted_proposal)

        self.assertEqual(first, second)
        self.assertEqual(first, self.base.review_request if hasattr(self.base, "review_request") else self.base._build())
        self.assertEqual(persisted_proposal, persisted_before)
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
        persisted_proposal = json.loads(self.base.proposal.to_json())
        persisted_before = copy.deepcopy(persisted_proposal)
        lineage_before = self._snapshot_lineage()

        upstream = self.base.base
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
                    self._build(persisted_proposal)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(persisted_proposal, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
