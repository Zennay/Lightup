from __future__ import annotations

import copy
import dataclasses
from contextlib import ExitStack
import json
import unittest
from unittest import mock

import test_future_remediation_implementation_plan_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_handoff import (
    load_and_validate_future_remediation_implementation_plan,
)


class FutureRemediationImplementationPlanHandoffChainAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

        self.plan = self.base.plan
        self.plan_fixture = self.base.base
        self.review_fixture = self.plan_fixture.base
        self.review_request_fixture = self.review_fixture.base
        self.remediation_fixture = self.review_request_fixture.base
        self.state = self.remediation_fixture.state

    @staticmethod
    def _container_identities(value, path="root"):
        identities = {}

        if dataclasses.is_dataclass(value):
            for field in dataclasses.fields(value):
                identities.update(
                    FutureRemediationImplementationPlanHandoffChainAtomicityTest
                    ._container_identities(
                        getattr(value, field.name),
                        f"{path}.{field.name}",
                    )
                )
            return identities

        if isinstance(value, dict):
            identities[path] = id(value)
            for key, item in value.items():
                identities.update(
                    FutureRemediationImplementationPlanHandoffChainAtomicityTest
                    ._container_identities(item, f"{path}[{key!r}]")
                )
            return identities

        if isinstance(value, (tuple, list, set, frozenset)):
            identities[path] = id(value)
            for index, item in enumerate(value):
                identities.update(
                    FutureRemediationImplementationPlanHandoffChainAtomicityTest
                    ._container_identities(item, f"{path}[{index}]")
                )
            return identities

        return identities

    @staticmethod
    def _ordered_json(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)

    def _state_rows(self):
        with self.state.connect() as con:
            runs = tuple(
                tuple(row)
                for row in con.execute(
                    "SELECT run_id,target,authorization_ref,activation_mode,status,created_at "
                    "FROM runs ORDER BY run_id"
                )
            )
            leases = tuple(
                tuple(row)
                for row in con.execute(
                    "SELECT run_id,capability_id,worker_id,expires_at "
                    "FROM capability_leases ORDER BY run_id,capability_id"
                )
            )
            evidence = tuple(
                tuple(row)
                for row in con.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                    "metadata_json,created_at FROM evidence ORDER BY evidence_id"
                )
            )
        return runs, leases, evidence

    def _forbid_state_writes(self):
        stack = ExitStack()
        for method_name in ("create_run", "acquire_lease", "add_evidence"):
            stack.enter_context(
                mock.patch.object(
                    self.state,
                    method_name,
                    side_effect=AssertionError(
                        f"unexpected StateStore write API call: {method_name}"
                    ),
                )
            )
        return stack

    def _caller_inputs(self, *, remediation_plan=None):
        payload = json.loads(self.plan.to_json())
        typed = (
            self.remediation_fixture.request,
            self.remediation_fixture.bundle,
            (
                self.remediation_fixture.plan
                if remediation_plan is None
                else remediation_plan
            ),
            self.remediation_fixture.report,
            self.remediation_fixture.preview,
            self.remediation_fixture.transition_proposal,
            (self.remediation_fixture.resolution,),
            (self.remediation_fixture.context,),
        )
        return (payload, *typed)

    def _load(self, caller_inputs):
        (
            payload,
            request,
            bundle,
            remediation_plan,
            report,
            preview,
            transition_proposal,
            resolutions,
            contexts,
        ) = caller_inputs

        return load_and_validate_future_remediation_implementation_plan(
            payload,
            self.plan_fixture.planning_request.to_json(),
            self.review_fixture.review.to_json(),
            self.review_request_fixture.review_request.to_json(),
            self.review_request_fixture.proposal.to_json(),
            request,
            bundle,
            remediation_plan,
            report,
            preview,
            transition_proposal,
            resolutions,
            contexts,
            self.state,
        )

    def _assert_unchanged(
        self,
        caller_inputs,
        before_value,
        before_ids,
        payload_json,
        before_state,
    ):
        self.assertEqual(caller_inputs, before_value)
        self.assertEqual(
            self._container_identities(caller_inputs),
            before_ids,
        )
        self.assertEqual(self._ordered_json(caller_inputs[0]), payload_json)
        self.assertEqual(self._state_rows(), before_state)

    def test_dict_parse_then_live_validation_is_atomic_and_repeatable(self):
        caller_inputs = self._caller_inputs()
        before_value = copy.deepcopy(caller_inputs)
        before_ids = self._container_identities(caller_inputs)
        payload_json = self._ordered_json(caller_inputs[0])
        before_state = self._state_rows()

        with self._forbid_state_writes():
            first = self._load(caller_inputs)
            second = self._load(caller_inputs)

        self.assertEqual(first, self.plan)
        self.assertEqual(second, self.plan)
        self.assertEqual(first, second)
        self._assert_unchanged(
            caller_inputs,
            before_value,
            before_ids,
            payload_json,
            before_state,
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

    def test_stale_live_lineage_after_parse_is_atomic_and_repeatable(self):
        stale_plan = dataclasses.replace(
            self.remediation_fixture.plan,
            plan_sha256="0" * 64,
        )
        caller_inputs = self._caller_inputs(remediation_plan=stale_plan)
        before_value = copy.deepcopy(caller_inputs)
        before_ids = self._container_identities(caller_inputs)
        payload_json = self._ordered_json(caller_inputs[0])
        before_state = self._state_rows()

        messages = []
        with self._forbid_state_writes():
            for _ in range(2):
                with self.assertRaises(ValueError) as raised:
                    self._load(caller_inputs)
                messages.append(str(raised.exception))

        self.assertEqual(messages[0], messages[1])
        self._assert_unchanged(
            caller_inputs,
            before_value,
            before_ids,
            payload_json,
            before_state,
        )


if __name__ == "__main__":
    unittest.main()
