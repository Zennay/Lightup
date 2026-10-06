from __future__ import annotations

import copy
import dataclasses
from contextlib import ExitStack
import unittest
from unittest import mock

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request import (
    build_future_security_retest_request,
)


class FutureSecurityRetestRequestBuilderInputAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
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
                    FutureSecurityRetestRequestBuilderInputAtomicityTest
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
                    FutureSecurityRetestRequestBuilderInputAtomicityTest
                    ._container_identities(item, f"{path}[{key!r}]")
                )
            return identities

        if isinstance(value, (tuple, list, set, frozenset)):
            identities[path] = id(value)
            for index, item in enumerate(value):
                identities.update(
                    FutureSecurityRetestRequestBuilderInputAtomicityTest
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

    def _inputs(self, classification, *, suffix):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.r.p._plan(classification, suffix=suffix)
        return plan, report, preview, proposal, (resolution,), (context,)

    def _assert_unchanged(self, inputs, before_values, before_ids, before_state):
        self.assertEqual(inputs, before_values)
        self.assertEqual(self._container_identities(inputs), before_ids)
        self.assertEqual(self._state_rows(), before_state)

    def test_successful_builder_is_input_atomic_for_all_retest_classifications(self):
        classifications = (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        )

        for classification in classifications:
            with self.subTest(classification=classification.value):
                inputs = self._inputs(
                    classification,
                    suffix=f"retest-builder-atomic-{classification.value}",
                )
                plan, report, preview, proposal, resolutions, contexts = inputs
                before_values = copy.deepcopy(inputs)
                before_ids = self._container_identities(inputs)
                before_state = self._state_rows()

                with self._forbid_state_writes():
                    first = build_future_security_retest_request(
                        plan,
                        report,
                        preview,
                        proposal,
                        resolutions,
                        contexts,
                        self.state,
                    )
                    second = build_future_security_retest_request(
                        plan,
                        report,
                        preview,
                        proposal,
                        resolutions,
                        contexts,
                        self.state,
                    )

                self.assertEqual(first, second)
                self._assert_unchanged(
                    inputs,
                    before_values,
                    before_ids,
                    before_state,
                )
                self.assertTrue(first.isolated_future_state_required)
                self.assertFalse(first.execution_allowed)
                self.assertFalse(first.target_interaction_allowed)
                self.assertFalse(first.deployment_authorized)
                self.assertFalse(first.attack_path_mutation_allowed)
                self.assertEqual(first.future_semantics, "unresolved")
                self.assertEqual(first.security_verdict, "not_evaluated")

    def test_insufficient_evidence_rejection_is_input_atomic(self):
        inputs = self._inputs(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="retest-builder-atomic-insufficient",
        )
        plan, report, preview, proposal, resolutions, contexts = inputs
        before_values = copy.deepcopy(inputs)
        before_ids = self._container_identities(inputs)
        before_state = self._state_rows()

        with self._forbid_state_writes():
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "evidence-complete"):
                    build_future_security_retest_request(
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

    def test_stale_plan_rejection_after_live_rebuild_is_input_atomic(self):
        canonical_inputs = self._inputs(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="retest-builder-atomic-stale-plan",
        )
        plan, report, preview, proposal, resolutions, contexts = canonical_inputs
        tampered_plan = dataclasses.replace(plan, plan_sha256="0" * 64)
        inputs = (
            tampered_plan,
            report,
            preview,
            proposal,
            resolutions,
            contexts,
        )
        before_values = copy.deepcopy(inputs)
        before_ids = self._container_identities(inputs)
        before_state = self._state_rows()

        with self._forbid_state_writes():
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "remediation/retest plan is stale"):
                    build_future_security_retest_request(
                        tampered_plan,
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


if __name__ == "__main__":
    unittest.main()
