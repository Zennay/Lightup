from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_text_review as review_tests
from lightup.future_remediation_text_review import review_future_remediation_text


class FutureRemediationTextReviewProducerInputAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _upstream(self):
        return self.base.base

    def _snapshot_lineage(self) -> tuple:
        upstream = self._upstream()
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.base.review_request,
                self.base.proposal,
                upstream.request,
                upstream.bundle,
                upstream.plan,
                upstream.report,
                upstream.preview,
                upstream.transition_proposal,
                upstream.resolution,
                upstream.context,
            )
        )

    def _persisted_payloads(self) -> tuple[dict, dict]:
        return (
            json.loads(self.base.review_request.to_json()),
            json.loads(self.base.proposal.to_json()),
        )

    def _review(self, payloads: tuple[dict, dict], gateway):
        review_request_payload, proposal_payload = payloads
        upstream = self._upstream()
        return review_future_remediation_text(
            review_request_payload,
            proposal_payload,
            upstream.request,
            upstream.bundle,
            upstream.plan,
            upstream.report,
            upstream.preview,
            upstream.transition_proposal,
            (upstream.resolution,),
            (upstream.context,),
            upstream.state,
            gateway,
        )

    def _write_sentinels(self):
        state = self._upstream().state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError("review producer must not create runs"),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError("review producer must not acquire leases"),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError("review producer must not add evidence"),
            ),
        )

    def test_successful_review_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        upstream = self._upstream()
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(upstream.state.get_evidence(evidence_id))

        first_gateway, first_provider = self.base._review_gateway(
            review_tests._review_json()
        )
        second_gateway, second_provider = self.base._review_gateway(
            review_tests._review_json()
        )

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._review(payloads, first_gateway)
            second = self._review(payloads, second_gateway)

        self.assertEqual(first, second)
        self.assertEqual(len(first_provider.requests), 1)
        self.assertEqual(len(second_provider.requests), 1)
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.review_completed)
        self.assertTrue(first.remediation_accepted)
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
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        upstream = self._upstream()
        evidence_id = upstream.bundle.items[0].evidence[0].evidence_id
        current_sha = upstream.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with upstream.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            upstream.state.get_evidence(evidence_id)
        )

        messages: list[str] = []
        providers = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                gateway, provider = self.base._review_gateway(
                    review_tests._review_json()
                )
                providers.append(provider)
                with self.assertRaises(ValueError) as caught:
                    self._review(payloads, gateway)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertTrue(all(provider.requests == [] for provider in providers))
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(upstream.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
