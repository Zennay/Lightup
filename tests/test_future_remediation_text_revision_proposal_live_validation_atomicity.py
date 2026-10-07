from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_text_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    load_and_validate_future_remediation_text_revision_proposal,
)


class FutureRemediationTextRevisionProposalLiveValidationAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionProposalHandoffTest(
            "test_round_trip_requires_complete_live_revision_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _upstream(self):
        return self.base.base.base.base.base

    def _snapshot_lineage(self) -> tuple:
        revision = self.base.base
        review_layer = revision.base
        prior_review_layer = review_layer.base
        upstream = self._upstream()
        return tuple(
            self._snapshot_value(value)
            for value in (
                revision.revision_request,
                revision.review,
                prior_review_layer.review_request,
                prior_review_layer.proposal,
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
        revision = self.base.base
        prior_review_layer = revision.base.base
        return (
            json.loads(self.base.proposal.to_json()),
            json.loads(revision.revision_request.to_json()),
            json.loads(revision.review.to_json()),
            json.loads(prior_review_layer.review_request.to_json()),
            json.loads(prior_review_layer.proposal.to_json()),
        )

    def _load(self, payloads: tuple[dict, dict, dict, dict, dict]):
        (
            revision_proposal_payload,
            revision_request_payload,
            review_payload,
            review_request_payload,
            proposal_payload,
        ) = payloads
        upstream = self._upstream()
        return load_and_validate_future_remediation_text_revision_proposal(
            revision_proposal_payload,
            revision_request_payload,
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
        state = self._upstream().state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError(
                    "revision-proposal validation must not create runs"
                ),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError(
                    "revision-proposal validation must not acquire leases"
                ),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError(
                    "revision-proposal validation must not add evidence"
                ),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        upstream = self._upstream()
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(upstream.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._load(payloads)
            second = self._load(payloads)

        self.assertEqual(first, self.base.proposal)
        self.assertEqual(second, self.base.proposal)
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.remediation_revision_proposal_created)
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
                    self._load(payloads)
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
