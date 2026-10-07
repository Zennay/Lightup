from __future__ import annotations

import copy
import dataclasses
import unittest
from unittest import mock

import test_future_remediation_implementation_plan as plan_tests
from lightup.future_remediation_implementation_plan import (
    generate_future_remediation_implementation_plan,
)


class FutureRemediationImplementationPlanProducerInputAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

        self.persisted_planning_request = self.base.planning_request.to_json()
        self.persisted_review = self.base.base.review.to_json()
        self.persisted_review_request = self.base.base.base.review_request.to_json()
        self.persisted_proposal = self.base.base.base.proposal.to_json()

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _snapshot_persisted(self) -> tuple[str, str, str, str]:
        return (
            self.persisted_planning_request,
            self.persisted_review,
            self.persisted_review_request,
            self.persisted_proposal,
        )

    def _snapshot_lineage(self) -> tuple:
        lineage = (
            self.base.base.base.base.request,
            self.base.base.base.base.bundle,
            self.base.base.base.base.plan,
            self.base.base.base.base.report,
            self.base.base.base.base.preview,
            self.base.base.base.base.transition_proposal,
            self.base.base.base.base.resolution,
            self.base.base.base.base.context,
        )
        return tuple(self._snapshot_value(value) for value in lineage)

    def _generate(self, gateway):
        return generate_future_remediation_implementation_plan(
            self.persisted_planning_request,
            self.persisted_review,
            self.persisted_review_request,
            self.persisted_proposal,
            self.base.base.base.base.request,
            self.base.base.base.base.bundle,
            self.base.base.base.base.plan,
            self.base.base.base.base.report,
            self.base.base.base.base.preview,
            self.base.base.base.base.transition_proposal,
            (self.base.base.base.base.resolution,),
            (self.base.base.base.base.context,),
            self.base.base.base.base.state,
            gateway,
        )

    def _write_sentinels(self):
        state = self.base.base.base.base.state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError(
                    "implementation-plan producer must not create runs"
                ),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError(
                    "implementation-plan producer must not acquire leases"
                ),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError(
                    "implementation-plan producer must not add evidence"
                ),
            ),
        )

    def test_successful_generation_is_repeatable_and_input_atomic(self):
        persisted_before = self._snapshot_persisted()
        lineage_before = self._snapshot_lineage()
        evidence_id = self.base.base.base.base.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(
            self.base.base.base.base.state.get_evidence(evidence_id)
        )

        first_gateway, first_provider = self.base._gateway()
        second_gateway, second_provider = self.base._gateway()

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._generate(first_gateway)
            second = self._generate(second_gateway)

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(len(first_provider.requests), 1)
        self.assertEqual(len(second_provider.requests), 1)
        self.assertEqual(self._snapshot_persisted(), persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(
                self.base.base.base.base.state.get_evidence(evidence_id)
            ),
            evidence_before,
        )

        self.assertTrue(first.implementation_plan_created)
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
        evidence_id = self.base.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            self.base.base.base.base.state.get_evidence(evidence_id)
        )

        messages: list[str] = []
        providers = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                gateway, provider = self.base._gateway()
                providers.append(provider)
                with self.assertRaises(ValueError) as caught:
                    self._generate(gateway)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertTrue(all(provider.requests == [] for provider in providers))
        self.assertEqual(self._snapshot_persisted(), persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(
                self.base.base.base.base.state.get_evidence(evidence_id)
            ),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
