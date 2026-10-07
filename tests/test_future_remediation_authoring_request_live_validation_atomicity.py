from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    load_and_validate_future_remediation_authoring_request,
)


class FutureRemediationAuthoringRequestLiveValidationAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _request(self, classification, *, suffix: str):
        return self.base._request(classification, suffix=suffix)

    @staticmethod
    def _snapshot_lineage(produced: tuple) -> tuple:
        # proposal, context, resolution, preview, report, plan, bundle
        return tuple(
            dataclasses.asdict(value)
            if dataclasses.is_dataclass(value)
            else copy.deepcopy(value)
            for value in produced[1:8]
        )

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
            _,
        ) = produced
        return load_and_validate_future_remediation_authoring_request(
            persisted,
            bundle,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def _write_sentinels(self):
        return (
            mock.patch.object(
                self.state,
                "create_run",
                side_effect=AssertionError("live validation must not create runs"),
            ),
            mock.patch.object(
                self.state,
                "acquire_lease",
                side_effect=AssertionError("live validation must not acquire leases"),
            ),
            mock.patch.object(
                self.state,
                "add_evidence",
                side_effect=AssertionError("live validation must not add evidence"),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-live-validation-atomic-success",
        )
        request = produced[-1]
        bundle = produced[-2]
        payload = json.loads(request.to_json())
        payload_before = copy.deepcopy(payload)
        lineage_before = self._snapshot_lineage(produced)

        evidence_id = bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(self.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._consume(payload, produced)
            second = self._consume(payload, produced)

        self.assertEqual(first, request)
        self.assertEqual(second, request)
        self.assertEqual(payload, payload_before)
        self.assertEqual(self._snapshot_lineage(produced), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.state.get_evidence(evidence_id)),
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
        produced = self._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-live-validation-atomic-reject",
        )
        request = produced[-1]
        bundle = produced[-2]
        payload = json.loads(request.to_json())
        payload_before = copy.deepcopy(payload)
        lineage_before = self._snapshot_lineage(produced)

        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            self.state.get_evidence(evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                with self.assertRaisesRegex(
                    ValueError,
                    "does not match its live validated lineage",
                ) as caught:
                    self._consume(payload, produced)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(payload, payload_before)
        self.assertEqual(self._snapshot_lineage(produced), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
