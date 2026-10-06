from __future__ import annotations

import copy
import dataclasses
from contextlib import ExitStack
import unittest
from unittest import mock

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    build_future_security_remediation_retest_plan,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    validate_future_security_remediation_retest_plan_handoff,
)


class FutureSecurityRemediationRetestPlanLiveValidationAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    @staticmethod
    def _container_identities(value, path="root"):
        identities = {}

        if dataclasses.is_dataclass(value):
            for field in dataclasses.fields(value):
                identities.update(
                    FutureSecurityRemediationRetestPlanLiveValidationAtomicityTest
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
                    FutureSecurityRemediationRetestPlanLiveValidationAtomicityTest
                    ._container_identities(item, f"{path}[{key!r}]")
                )
            return identities

        if isinstance(value, (tuple, list, set, frozenset)):
            identities[path] = id(value)
            for index, item in enumerate(value):
                identities.update(
                    FutureSecurityRemediationRetestPlanLiveValidationAtomicityTest
                    ._container_identities(item, f"{path}[{index}]")
                )
            return identities

        return identities

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

    def _produced(self, classification, *, suffix):
        _, proposal, context, resolution, preview = self.r._inputs(
            classification,
            suffix=suffix,
        )
        resolutions = (resolution,)
        contexts = (context,)
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            resolutions,
            contexts,
            self.state,
        )
        plan = build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            resolutions,
            contexts,
            self.state,
        )
        return plan, report, preview, proposal, resolutions, contexts

    def _assert_unchanged(self, inputs, before_values, before_ids, before_state):
        self.assertEqual(inputs, before_values)
        self.assertEqual(self._container_identities(inputs), before_ids)
        self.assertEqual(self._state_rows(), before_state)

    def test_successful_live_validation_is_input_atomic_for_all_classifications(self):
        classifications = (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )

        for classification in classifications:
            with self.subTest(classification=classification.value):
                inputs = self._produced(
                    classification,
                    suffix=f"handoff-live-atomic-{classification.value}",
                )
                plan, report, preview, proposal, resolutions, contexts = inputs
                before_values = copy.deepcopy(inputs)
                before_ids = self._container_identities(inputs)
                before_state = self._state_rows()

                with self._forbid_state_writes():
                    first = validate_future_security_remediation_retest_plan_handoff(
                        plan,
                        report,
                        preview,
                        proposal,
                        resolutions,
                        contexts,
                        self.state,
                    )
                    second = validate_future_security_remediation_retest_plan_handoff(
                        plan,
                        report,
                        preview,
                        proposal,
                        resolutions,
                        contexts,
                        self.state,
                    )

                self.assertEqual(first, plan)
                self.assertEqual(second, plan)
                self.assertEqual(first, second)
                self._assert_unchanged(
                    inputs,
                    before_values,
                    before_ids,
                    before_state,
                )
                self.assertFalse(plan.execution_allowed)
                self.assertFalse(plan.deployment_authorized)
                self.assertFalse(plan.attack_path_mutation_allowed)
                self.assertEqual(plan.future_semantics, "unresolved")
                self.assertEqual(plan.security_verdict, "not_evaluated")

    def test_cross_lineage_rejection_is_input_atomic_and_repeatable(self):
        first = self._produced(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="handoff-live-atomic-a",
        )
        second = self._produced(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="handoff-live-atomic-b",
        )
        plan = first[0]
        _, report, preview, proposal, resolutions, contexts = second
        inputs = (plan, report, preview, proposal, resolutions, contexts)
        before_values = copy.deepcopy(inputs)
        before_ids = self._container_identities(inputs)
        before_state = self._state_rows()

        with self._forbid_state_writes():
            for _ in range(2):
                with self.assertRaisesRegex(
                    ValueError,
                    "does not match its live validated lineage",
                ):
                    validate_future_security_remediation_retest_plan_handoff(
                        plan,
                        report,
                        preview,
                        proposal,
                        resolutions,
                        contexts,
                        self.state,
                    )

        self._assert_unchanged(
            inputs,
            before_values,
            before_ids,
            before_state,
        )
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertEqual(plan.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
