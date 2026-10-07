from __future__ import annotations

import copy
import dataclasses
import unittest
from unittest import mock

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_review import (
    review_future_remediation_implementation_plan,
)


class FutureRemediationImplementationPlanReviewerProducerInputAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.review_fixture = (
            review_tests.FutureRemediationImplementationPlanReviewTest(
                "test_all_pass_review_accepts_plan_without_action_authority"
            )
        )
        self.review_fixture.setUp()
        self.addCleanup(self.review_fixture.tearDown)

        fixture = self.review_fixture
        self.persisted_review_request = fixture.review_request.to_json()
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

    def _snapshot_persisted(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.persisted_review_request,
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

    def _review(self, gateway):
        return review_future_remediation_implementation_plan(
            self.persisted_review_request,
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
            gateway,
        )

    def _write_sentinels(self):
        return (
            mock.patch.object(
                self.lineage.state,
                "create_run",
                side_effect=AssertionError(
                    "implementation-plan reviewer must not create runs"
                ),
            ),
            mock.patch.object(
                self.lineage.state,
                "acquire_lease",
                side_effect=AssertionError(
                    "implementation-plan reviewer must not acquire leases"
                ),
            ),
            mock.patch.object(
                self.lineage.state,
                "add_evidence",
                side_effect=AssertionError(
                    "implementation-plan reviewer must not add evidence"
                ),
            ),
        )

    def test_successful_review_is_repeatable_and_input_atomic(self):
        persisted_before = self._snapshot_persisted()
        lineage_before = self._snapshot_lineage()
        evidence = self.lineage.bundle.items[0].evidence[0]
        evidence_before = dataclasses.asdict(
            self.lineage.state.get_evidence(evidence.evidence_id)
        )

        first_gateway, first_provider = self.review_fixture._review_gateway(
            review_tests._review_json()
        )
        second_gateway, second_provider = self.review_fixture._review_gateway(
            review_tests._review_json()
        )

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._review(first_gateway)
            second = self._review(second_gateway)

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(len(first_provider.requests), 1)
        self.assertEqual(len(second_provider.requests), 1)
        self.assertEqual(self._snapshot_persisted(), persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(
                self.lineage.state.get_evidence(evidence.evidence_id)
            ),
            evidence_before,
        )

        self.assertTrue(first.implementation_plan_review_completed)
        self.assertTrue(first.implementation_plan_accepted)
        self.assertFalse(first.code_change_authorized)
        self.assertFalse(first.tool_call_created)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.target_interaction_allowed)
        self.assertFalse(first.future_state_retest_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_live_rejection_is_repeatable_atomic_and_pre_model(self):
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
        providers = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                gateway, provider = self.review_fixture._review_gateway(
                    review_tests._review_json()
                )
                providers.append(provider)
                with self.assertRaises(ValueError) as caught:
                    self._review(gateway)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertTrue(all(provider.requests == [] for provider in providers))
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
