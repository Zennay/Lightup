from __future__ import annotations

import copy
import dataclasses
import unittest
from unittest import mock

import test_future_remediation_text_proposal as proposal_tests


class FutureRemediationTextProposalProducerInputAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
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
                self.base.request,
                self.base.bundle,
                self.base.plan,
                self.base.report,
                self.base.preview,
                self.base.transition_proposal,
                self.base.resolution,
                self.base.context,
            )
        )

    def _write_sentinels(self):
        state = self.base.state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError("proposal producer must not create runs"),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError("proposal producer must not acquire leases"),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError("proposal producer must not add evidence"),
            ),
        )

    def test_successful_generation_is_repeatable_and_input_atomic(self):
        lineage_before = self._snapshot_lineage()
        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(self.base.state.get_evidence(evidence_id))

        content = "Apply the defensive control and perform a separate future retest."
        first_gateway, first_provider = self.base._gateway(content)
        second_gateway, second_provider = self.base._gateway(content)

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self.base._generate(first_gateway)
            second = self.base._generate(second_gateway)

        self.assertEqual(first, second)
        self.assertEqual(len(first_provider.requests), 1)
        self.assertEqual(len(second_provider.requests), 1)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.base.state.get_evidence(evidence_id)),
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

    def test_live_rejection_is_repeatable_atomic_and_pre_model(self):
        lineage_before = self._snapshot_lineage()
        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.bundle.items[0].evidence[0].sha256
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
        providers = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                gateway, provider = self.base._gateway()
                providers.append(provider)
                with self.assertRaises(ValueError) as caught:
                    self.base._generate(gateway)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertTrue(all(provider.requests == [] for provider in providers))
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.base.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
