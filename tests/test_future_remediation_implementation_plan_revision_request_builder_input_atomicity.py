from __future__ import annotations

import copy
import dataclasses
import unittest
from unittest import mock

import test_future_remediation_implementation_plan_review as review_tests
import test_future_remediation_implementation_plan_review_handoff as handoff_tests
from lightup.ai.gateway import ModelGateway
from lightup.future_remediation_implementation_plan_revision_request import (
    build_future_remediation_implementation_plan_revision_request,
)


class FutureRemediationImplementationPlanRevisionRequestBuilderInputAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.handoff_fixture = (
            handoff_tests.FutureRemediationImplementationPlanReviewHandoffTest(
                "test_revision_and_insufficient_evidence_reviews_round_trip_unaccepted"
            )
        )
        self.handoff_fixture.setUp()
        self.addCleanup(self.handoff_fixture.tearDown)

        self.review_fixture = self.handoff_fixture.base
        gateway, _ = self.review_fixture._review_gateway(
            review_tests._review_json(
                decision="revision_required",
                rollback_sufficiency="fail",
            )
        )
        self.revision_review = self.review_fixture._review(gateway)

        fixture = self.review_fixture
        self.persisted_plan_review = self.revision_review.to_json()
        self.persisted_plan_review_request = fixture.review_request.to_json()
        self.persisted_plan = fixture.implementation_plan.to_json()
        self.persisted_planning_request = (
            fixture.base.base.base.base.planning_request.to_json()
        )
        self.persisted_remediation_review = (
            fixture.base.base.base.base.base.review.to_json()
        )
        self.persisted_remediation_review_request = (
            fixture.base.base.base.base.base.base.review_request.to_json()
        )
        self.persisted_proposal = (
            fixture.base.base.base.base.base.base.proposal.to_json()
        )
        self.lineage = fixture.base.base.base.base.base.base.base

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _snapshot_persisted(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            self.persisted_plan_review,
            self.persisted_plan_review_request,
            self.persisted_plan,
            self.persisted_planning_request,
            self.persisted_remediation_review,
            self.persisted_remediation_review_request,
            self.persisted_proposal,
        )

    def _snapshot_lineage(self) -> tuple:
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.lineage.request,
                self.lineage.bundle,
                self.lineage.plan,
                self.lineage.report,
                self.lineage.preview,
                self.lineage.transition_proposal,
                self.lineage.resolution,
                self.lineage.context,
            )
        )

    def _build(self):
        return build_future_remediation_implementation_plan_revision_request(
            self.persisted_plan_review,
            self.persisted_plan_review_request,
            self.persisted_plan,
            self.persisted_planning_request,
            self.persisted_remediation_review,
            self.persisted_remediation_review_request,
            self.persisted_proposal,
            self.lineage.request,
            self.lineage.bundle,
            self.lineage.plan,
            self.lineage.report,
            self.lineage.preview,
            self.lineage.transition_proposal,
            (self.lineage.resolution,),
            (self.lineage.context,),
            self.lineage.state,
        )

    def _write_sentinels(self):
        return (
            mock.patch.object(
                self.lineage.state,
                "create_run",
                side_effect=AssertionError(
                    "implementation-plan revision-request builder must not create runs"
                ),
            ),
            mock.patch.object(
                self.lineage.state,
                "acquire_lease",
                side_effect=AssertionError(
                    "implementation-plan revision-request builder must not acquire leases"
                ),
            ),
            mock.patch.object(
                self.lineage.state,
                "add_evidence",
                side_effect=AssertionError(
                    "implementation-plan revision-request builder must not add evidence"
                ),
            ),
            mock.patch.object(
                ModelGateway,
                "complete",
                side_effect=AssertionError(
                    "implementation-plan revision-request builder must not invoke models"
                ),
            ),
        )

    def test_successful_build_is_repeatable_and_input_atomic(self):
        persisted_before = self._snapshot_persisted()
        lineage_before = self._snapshot_lineage()
        evidence = self.lineage.bundle.items[0].evidence[0]
        evidence_before = dataclasses.asdict(
            self.lineage.state.get_evidence(evidence.evidence_id)
        )

        run_patch, lease_patch, evidence_patch, model_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch, model_patch:
            first = self._build()
            second = self._build()

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.required_revisions, ("rollback_sufficiency",))
        self.assertEqual(self._snapshot_persisted(), persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(
                self.lineage.state.get_evidence(evidence.evidence_id)
            ),
            evidence_before,
        )

        self.assertTrue(first.implementation_plan_revision_requested)
        self.assertFalse(first.revised_implementation_plan_created)
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
        persisted_before = self._snapshot_persisted()
        lineage_before = self._snapshot_lineage()
        evidence = self.lineage.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.lineage.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            self.lineage.state.get_evidence(evidence.evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch, model_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch, model_patch:
            for _ in range(2):
                with self.assertRaises(ValueError) as caught:
                    self._build()
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(self._snapshot_persisted(), persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(
                self.lineage.state.get_evidence(evidence.evidence_id)
            ),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
