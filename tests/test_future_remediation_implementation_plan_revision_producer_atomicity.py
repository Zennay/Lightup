from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

import test_future_remediation_implementation_plan_revision_proposal as revision_tests
from lightup.future_remediation_implementation_plan_revision_proposal import (
    generate_future_remediation_implementation_plan_revision_proposal,
)


class FutureRemediationImplementationPlanRevisionProducerAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_tests.FutureRemediationImplementationPlanRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_revised_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _persisted_inputs(self) -> dict[str, object]:
        return {
            "revision_request": json.loads(self.base.revision_request.to_json()),
            "review": json.loads(self.base.review.to_json()),
            "plan_review_request": json.loads(self.base.plan_review_request.to_json()),
            "prior_plan": json.loads(self.base.prior_plan.to_json()),
            "planning_request": json.loads(self.base.planning_request.to_json()),
            "remediation_review": json.loads(self.base.remediation_review.to_json()),
            "remediation_review_request": json.loads(
                self.base.remediation_review_request.to_json()
            ),
            "proposal": json.loads(self.base.proposal.to_json()),
        }

    def _state_snapshot(self) -> tuple[tuple[str, tuple[tuple[object, ...], ...]], ...]:
        with self.base.root.state.connect() as con:
            rows = []
            for table, order_by in (
                ("runs", "run_id"),
                ("capability_leases", "run_id, capability_id"),
                ("evidence", "evidence_id"),
            ):
                table_rows = tuple(
                    tuple(row)
                    for row in con.execute(
                        f"SELECT * FROM {table} ORDER BY {order_by}"
                    ).fetchall()
                )
                rows.append((table, table_rows))
        return tuple(rows)

    def _generate(self, gateway, persisted):
        return generate_future_remediation_implementation_plan_revision_proposal(
            persisted["revision_request"],
            persisted["review"],
            persisted["plan_review_request"],
            persisted["prior_plan"],
            persisted["planning_request"],
            persisted["remediation_review"],
            persisted["remediation_review_request"],
            persisted["proposal"],
            self.base.root.request,
            self.base.root.bundle,
            self.base.root.plan,
            self.base.root.report,
            self.base.root.preview,
            self.base.root.transition_proposal,
            (self.base.root.resolution,),
            (self.base.root.context,),
            self.base.root.state,
            gateway,
        )

    def _write_sentinels(self):
        return (
            patch.object(
                self.base.root.state,
                "create_run",
                side_effect=AssertionError("producer must not create runs"),
            ),
            patch.object(
                self.base.root.state,
                "acquire_lease",
                side_effect=AssertionError("producer must not acquire leases"),
            ),
            patch.object(
                self.base.root.state,
                "add_evidence",
                side_effect=AssertionError("producer must not add evidence"),
            ),
        )

    def test_success_is_deterministic_and_input_state_atomic(self):
        persisted = self._persisted_inputs()
        original_persisted = copy.deepcopy(persisted)
        original_state = self._state_snapshot()

        first_gateway, first_provider = self.base._gateway()
        create_run, acquire_lease, add_evidence = self._write_sentinels()
        with create_run, acquire_lease, add_evidence:
            first = self._generate(first_gateway, persisted)

        self.assertEqual(persisted, original_persisted)
        self.assertEqual(self._state_snapshot(), original_state)
        self.assertEqual(len(first_provider.requests), 1)

        second_gateway, second_provider = self.base._gateway()
        create_run, acquire_lease, add_evidence = self._write_sentinels()
        with create_run, acquire_lease, add_evidence:
            second = self._generate(second_gateway, persisted)

        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(persisted, original_persisted)
        self.assertEqual(self._state_snapshot(), original_state)
        self.assertEqual(len(second_provider.requests), 1)

    def test_live_drift_rejection_is_repeatable_and_input_state_atomic(self):
        persisted = self._persisted_inputs()
        original_persisted = copy.deepcopy(persisted)
        evidence = self.base.root.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.base.root.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )
        drifted_state = self._state_snapshot()

        for _ in range(2):
            gateway, provider = self.base._gateway()
            create_run, acquire_lease, add_evidence = self._write_sentinels()
            with create_run, acquire_lease, add_evidence:
                with self.assertRaises(ValueError):
                    self._generate(gateway, persisted)

            self.assertEqual(provider.requests, [])
            self.assertEqual(persisted, original_persisted)
            self.assertEqual(self._state_snapshot(), drifted_state)


if __name__ == "__main__":
    unittest.main()
