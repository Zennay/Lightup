from __future__ import annotations

import copy
import dataclasses
import unittest
from unittest import mock

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request import (
    build_future_remediation_authoring_request,
)


class FutureRemediationAuthoringRequestBuilderInputAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_introduced_and_worsened_create_bounded_text_authoring_requests"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        (
            self.current,
            self.transition_proposal,
            self.context,
            self.resolution,
            self.preview,
            self.report,
            self.plan,
            self.bundle,
        ) = self.base.base._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-request-builder-atomicity",
        )

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _snapshot_lineage(self) -> tuple:
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.bundle,
                self.plan,
                self.report,
                self.preview,
                self.transition_proposal,
                self.resolution,
                self.context,
            )
        )

    def _build(self):
        return build_future_remediation_authoring_request(
            self.bundle,
            self.plan,
            self.report,
            self.preview,
            self.transition_proposal,
            (self.resolution,),
            (self.context,),
            self.base.state,
        )

    def _write_sentinels(self):
        return (
            mock.patch.object(
                self.base.state,
                "create_run",
                side_effect=AssertionError(
                    "authoring-request builder must not create runs"
                ),
            ),
            mock.patch.object(
                self.base.state,
                "acquire_lease",
                side_effect=AssertionError(
                    "authoring-request builder must not acquire leases"
                ),
            ),
            mock.patch.object(
                self.base.state,
                "add_evidence",
                side_effect=AssertionError(
                    "authoring-request builder must not add evidence"
                ),
            ),
        )

    def test_successful_build_is_repeatable_and_input_atomic(self):
        lineage_before = self._snapshot_lineage()
        evidence_id = self.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(
            self.base.state.get_evidence(evidence_id)
        )

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._build()
            second = self._build()

        self.assertEqual(first, second)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.base.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.authoring_requested)
        self.assertFalse(first.remediation_proposal_created)
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
        lineage_before = self._snapshot_lineage()
        evidence_id = self.bundle.items[0].evidence[0].evidence_id
        current_sha = self.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            self.base.state.get_evidence(evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                with self.assertRaises(ValueError) as caught:
                    self._build()
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.base.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
