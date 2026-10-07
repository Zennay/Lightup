from __future__ import annotations

import copy
import dataclasses
import unittest
from unittest import mock

import test_future_remediation_text_proposal_handoff as handoff_tests
from lightup.future_remediation_text_proposal_handoff import (
    load_and_validate_future_remediation_text_proposal,
)


class FutureRemediationTextProposalLiveValidationAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextProposalHandoffTest(
            "test_round_trip_requires_exact_live_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _snapshot_lineage(self) -> tuple:
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.base.base.request,
                self.base.base.bundle,
                self.base.base.plan,
                self.base.base.report,
                self.base.base.preview,
                self.base.base.transition_proposal,
                self.base.base.resolution,
                self.base.base.context,
            )
        )

    def _load(self, persisted):
        return load_and_validate_future_remediation_text_proposal(
            persisted,
            self.base.base.request,
            self.base.base.bundle,
            self.base.base.plan,
            self.base.base.report,
            self.base.base.preview,
            self.base.base.transition_proposal,
            (self.base.base.resolution,),
            (self.base.base.context,),
            self.base.base.state,
        )

    def _write_sentinels(self):
        state = self.base.base.state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError("proposal validation must not create runs"),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError("proposal validation must not acquire leases"),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError("proposal validation must not add evidence"),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        payload = self.base.proposal.as_dict()
        payload_before = copy.deepcopy(payload)
        lineage_before = self._snapshot_lineage()

        evidence_id = self.base.base.bundle.items[0].evidence[0].evidence_id
        state = self.base.base.state
        evidence_before = dataclasses.asdict(state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._load(payload)
            second = self._load(payload)

        self.assertEqual(first, self.base.proposal)
        self.assertEqual(second, self.base.proposal)
        self.assertEqual(payload, payload_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.remediation_proposal_created)
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
        payload = self.base.proposal.as_dict()
        payload_before = copy.deepcopy(payload)
        lineage_before = self._snapshot_lineage()

        bundle = self.base.base.bundle
        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        state = self.base.base.state
        with state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(state.get_evidence(evidence_id))

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                with self.assertRaises(ValueError) as caught:
                    self._load(payload)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(payload, payload_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
