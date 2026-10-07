from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_implementation_plan_review_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    load_and_validate_future_remediation_implementation_plan_review_request,
)


class FutureRemediationImplementationPlanReviewRequestLiveValidationAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanReviewRequestHandoffTest(
                "test_json_and_dict_round_trip_require_live_plan_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _lineage(self):
        review_request_test = self.base.base
        plan_handoff = review_request_test.base
        plan_producer = plan_handoff.base
        planning_request_test = plan_producer.base
        remediation_review_test = planning_request_test.base
        remediation_proposal_test = remediation_review_test.base
        return (
            review_request_test,
            plan_handoff,
            plan_producer,
            planning_request_test,
            remediation_review_test,
            remediation_proposal_test,
        )

    def _persisted_payloads(self) -> tuple[dict, dict, dict, dict, dict, dict]:
        (
            _,
            plan_handoff,
            plan_producer,
            planning_request_test,
            remediation_review_test,
            _,
        ) = self._lineage()
        return (
            json.loads(self.base.request.to_json()),
            json.loads(plan_handoff.plan.to_json()),
            json.loads(plan_producer.planning_request.to_json()),
            json.loads(planning_request_test.review.to_json()),
            json.loads(remediation_review_test.review_request.to_json()),
            json.loads(remediation_review_test.proposal.to_json()),
        )

    def _snapshot_lineage(self) -> tuple:
        (
            _,
            plan_handoff,
            plan_producer,
            planning_request_test,
            remediation_review_test,
            remediation_proposal_test,
        ) = self._lineage()
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.base.request,
                plan_handoff.plan,
                plan_producer.planning_request,
                planning_request_test.review,
                remediation_review_test.review_request,
                remediation_review_test.proposal,
                remediation_proposal_test.request,
                remediation_proposal_test.bundle,
                remediation_proposal_test.plan,
                remediation_proposal_test.report,
                remediation_proposal_test.preview,
                remediation_proposal_test.transition_proposal,
                remediation_proposal_test.resolution,
                remediation_proposal_test.context,
            )
        )

    def _load(self, payloads: tuple[dict, dict, dict, dict, dict, dict]):
        (
            review_request_payload,
            plan_payload,
            planning_request_payload,
            review_payload,
            remediation_review_request_payload,
            proposal_payload,
        ) = payloads
        *_, remediation_proposal_test = self._lineage()
        return load_and_validate_future_remediation_implementation_plan_review_request(
            review_request_payload,
            plan_payload,
            planning_request_payload,
            review_payload,
            remediation_review_request_payload,
            proposal_payload,
            remediation_proposal_test.request,
            remediation_proposal_test.bundle,
            remediation_proposal_test.plan,
            remediation_proposal_test.report,
            remediation_proposal_test.preview,
            remediation_proposal_test.transition_proposal,
            (remediation_proposal_test.resolution,),
            (remediation_proposal_test.context,),
            remediation_proposal_test.state,
        )

    def _write_sentinels(self):
        *_, remediation_proposal_test = self._lineage()
        state = remediation_proposal_test.state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError(
                    "implementation-plan review-request validation must not create runs"
                ),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError(
                    "implementation-plan review-request validation must not acquire leases"
                ),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError(
                    "implementation-plan review-request validation must not add evidence"
                ),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        *_, remediation_proposal_test = self._lineage()
        evidence_id = remediation_proposal_test.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(
            remediation_proposal_test.state.get_evidence(evidence_id)
        )

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._load(payloads)
            second = self._load(payloads)

        self.assertEqual(first, self.base.request)
        self.assertEqual(second, self.base.request)
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(remediation_proposal_test.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.implementation_plan_review_requested)
        self.assertFalse(first.implementation_plan_accepted)
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

        *_, remediation_proposal_test = self._lineage()
        evidence = remediation_proposal_test.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with remediation_proposal_test.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            remediation_proposal_test.state.get_evidence(evidence.evidence_id)
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
            dataclasses.asdict(
                remediation_proposal_test.state.get_evidence(evidence.evidence_id)
            ),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
