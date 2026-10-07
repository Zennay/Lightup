from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review_handoff import (
    load_and_validate_future_remediation_text_review,
)


class FutureRemediationTextReviewLiveValidationAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _snapshot_lineage(self) -> tuple:
        review_base = self.base.base
        upstream = review_base.base
        return tuple(
            self._snapshot_value(value)
            for value in (
                review_base.review_request,
                review_base.proposal,
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

    def _persisted_payloads(self) -> tuple[dict, dict, dict]:
        return (
            json.loads(self.base.review.to_json()),
            json.loads(self.base.base.review_request.to_json()),
            json.loads(self.base.base.proposal.to_json()),
        )

    def _load(
        self,
        review_payload: dict,
        review_request_payload: dict,
        proposal_payload: dict,
    ):
        review_base = self.base.base
        upstream = review_base.base
        return load_and_validate_future_remediation_text_review(
            review_payload,
            review_request_payload,
            proposal_payload,
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
        state = self.base.base.base.state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError("review validation must not create runs"),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError("review validation must not acquire leases"),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError("review validation must not add evidence"),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        review_payload, review_request_payload, proposal_payload = (
            self._persisted_payloads()
        )
        persisted_before = copy.deepcopy(
            (review_payload, review_request_payload, proposal_payload)
        )
        lineage_before = self._snapshot_lineage()

        upstream = self.base.base.base
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(upstream.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._load(
                review_payload,
                review_request_payload,
                proposal_payload,
            )
            second = self._load(
                review_payload,
                review_request_payload,
                proposal_payload,
            )

        self.assertEqual(first, self.base.review)
        self.assertEqual(second, self.base.review)
        self.assertEqual(
            (review_payload, review_request_payload, proposal_payload),
            persisted_before,
        )
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.review_completed)
        self.assertTrue(first.remediation_accepted)
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
        review_payload, review_request_payload, proposal_payload = (
            self._persisted_payloads()
        )
        persisted_before = copy.deepcopy(
            (review_payload, review_request_payload, proposal_payload)
        )
        lineage_before = self._snapshot_lineage()

        upstream = self.base.base.base
        bundle = upstream.bundle
        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
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
                    self._load(
                        review_payload,
                        review_request_payload,
                        proposal_payload,
                    )
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(
            (review_payload, review_request_payload, proposal_payload),
            persisted_before,
        )
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
