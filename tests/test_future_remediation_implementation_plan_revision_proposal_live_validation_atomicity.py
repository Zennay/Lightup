from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_implementation_plan_revision_proposal_handoff as handoff_tests
from lightup.ai.gateway import ModelGateway
from lightup.future_remediation_implementation_plan_revision_proposal_handoff import (
    load_and_validate_future_remediation_implementation_plan_revision_proposal,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationImplementationPlanRevisionProposalLiveValidationAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanRevisionProposalHandoffTest(
                "test_json_and_dict_round_trip_require_live_revision_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.revised_plan = self.base.revised_plan

    @property
    def producer(self):
        return self.base.base

    @property
    def root(self):
        return self.producer.root

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _persisted_payloads(self) -> tuple[dict, ...]:
        return (
            json.loads(self.revised_plan.to_json()),
            json.loads(self.producer.revision_request.to_json()),
            json.loads(self.producer.review.to_json()),
            json.loads(self.producer.plan_review_request.to_json()),
            json.loads(self.producer.prior_plan.to_json()),
            json.loads(self.producer.planning_request.to_json()),
            json.loads(self.producer.remediation_review.to_json()),
            json.loads(self.producer.remediation_review_request.to_json()),
            json.loads(self.producer.proposal.to_json()),
        )

    def _snapshot_lineage(self) -> tuple:
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.revised_plan,
                self.producer.revision_request,
                self.producer.review,
                self.producer.plan_review_request,
                self.producer.prior_plan,
                self.producer.planning_request,
                self.producer.remediation_review,
                self.producer.remediation_review_request,
                self.producer.proposal,
                self.root.request,
                self.root.bundle,
                self.root.plan,
                self.root.report,
                self.root.preview,
                self.root.transition_proposal,
                self.root.resolution,
                self.root.context,
            )
        )

    def _load(self, payloads: tuple[dict, ...]):
        (
            revised_plan_payload,
            revision_request_payload,
            review_payload,
            review_request_payload,
            prior_plan_payload,
            planning_request_payload,
            remediation_review_payload,
            remediation_review_request_payload,
            proposal_payload,
        ) = payloads
        return load_and_validate_future_remediation_implementation_plan_revision_proposal(
            revised_plan_payload,
            revision_request_payload,
            review_payload,
            review_request_payload,
            prior_plan_payload,
            planning_request_payload,
            remediation_review_payload,
            remediation_review_request_payload,
            proposal_payload,
            self.root.request,
            self.root.bundle,
            self.root.plan,
            self.root.report,
            self.root.preview,
            self.root.transition_proposal,
            (self.root.resolution,),
            (self.root.context,),
            self.root.state,
        )

    def _write_sentinels(self):
        return (
            mock.patch.object(
                self.root.state,
                "create_run",
                side_effect=AssertionError(
                    "revised-plan validation must not create runs"
                ),
            ),
            mock.patch.object(
                self.root.state,
                "acquire_lease",
                side_effect=AssertionError(
                    "revised-plan validation must not acquire leases"
                ),
            ),
            mock.patch.object(
                self.root.state,
                "add_evidence",
                side_effect=AssertionError(
                    "revised-plan validation must not add evidence"
                ),
            ),
            mock.patch.object(
                ModelGateway,
                "complete",
                side_effect=AssertionError(
                    "revised-plan consumer validation must not invoke a model"
                ),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        evidence_id = self.root.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(
            self.root.state.get_evidence(evidence_id)
        )

        run_patch, lease_patch, evidence_patch, model_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch, model_patch:
            first = self._load(payloads)
            second = self._load(payloads)

        self.assertEqual(first, self.revised_plan)
        self.assertEqual(second, self.revised_plan)
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.root.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.revised_implementation_plan_created)
        self.assertFalse(first.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(first, field))
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_live_rejection_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        evidence = self.root.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.root.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            self.root.state.get_evidence(evidence.evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch, model_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch, model_patch:
            for _ in range(2):
                with self.assertRaises(ValueError) as caught:
                    self._load(payloads)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(
                self.root.state.get_evidence(evidence.evidence_id)
            ),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
