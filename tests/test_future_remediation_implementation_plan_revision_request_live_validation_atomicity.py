from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_revision_request import (
    build_future_remediation_implementation_plan_revision_request,
)
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    load_and_validate_future_remediation_implementation_plan_revision_request,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationImplementationPlanRevisionRequestLiveValidationAtomicityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_revision_and_insufficient_evidence_never_accept_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

        gateway, _ = self.base._review_gateway(
            review_tests._review_json(
                decision="revision_required",
                rollback_sufficiency="fail",
            )
        )
        self.review = self.base._review(gateway)

        root = self._root()
        self.revision_request = (
            build_future_remediation_implementation_plan_revision_request(
                self.review.to_json(),
                self.base.review_request.to_json(),
                self.base.implementation_plan.to_json(),
                self.base.base.base.base.base.planning_request.to_json(),
                self.base.base.base.base.base.base.review.to_json(),
                self.base.base.base.base.base.base.base.review_request.to_json(),
                self.base.base.base.base.base.base.base.proposal.to_json(),
                root.request,
                root.bundle,
                root.plan,
                root.report,
                root.preview,
                root.transition_proposal,
                (root.resolution,),
                (root.context,),
                root.state,
            )
        )

    def _root(self):
        return self.base.base.base.base.base.base.base.base

    @staticmethod
    def _snapshot_value(value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        return copy.deepcopy(value)

    def _persisted_payloads(self) -> tuple[dict, ...]:
        return (
            json.loads(self.revision_request.to_json()),
            json.loads(self.review.to_json()),
            json.loads(self.base.review_request.to_json()),
            json.loads(self.base.implementation_plan.to_json()),
            json.loads(self.base.base.base.base.base.planning_request.to_json()),
            json.loads(self.base.base.base.base.base.base.review.to_json()),
            json.loads(self.base.base.base.base.base.base.base.review_request.to_json()),
            json.loads(self.base.base.base.base.base.base.base.proposal.to_json()),
        )

    def _snapshot_lineage(self) -> tuple:
        root = self._root()
        return tuple(
            self._snapshot_value(value)
            for value in (
                self.revision_request,
                self.review,
                self.base.review_request,
                self.base.implementation_plan,
                self.base.base.base.base.base.planning_request,
                self.base.base.base.base.base.base.review,
                self.base.base.base.base.base.base.base.review_request,
                self.base.base.base.base.base.base.base.proposal,
                root.request,
                root.bundle,
                root.plan,
                root.report,
                root.preview,
                root.transition_proposal,
                root.resolution,
                root.context,
            )
        )

    def _load(self, payloads: tuple[dict, ...]):
        (
            revision_request_payload,
            review_payload,
            review_request_payload,
            plan_payload,
            planning_request_payload,
            remediation_review_payload,
            remediation_review_request_payload,
            proposal_payload,
        ) = payloads
        root = self._root()
        return load_and_validate_future_remediation_implementation_plan_revision_request(
            revision_request_payload,
            review_payload,
            review_request_payload,
            plan_payload,
            planning_request_payload,
            remediation_review_payload,
            remediation_review_request_payload,
            proposal_payload,
            root.request,
            root.bundle,
            root.plan,
            root.report,
            root.preview,
            root.transition_proposal,
            (root.resolution,),
            (root.context,),
            root.state,
        )

    def _write_sentinels(self):
        state = self._root().state
        return (
            mock.patch.object(
                state,
                "create_run",
                side_effect=AssertionError(
                    "implementation-plan revision-request validation must not create runs"
                ),
            ),
            mock.patch.object(
                state,
                "acquire_lease",
                side_effect=AssertionError(
                    "implementation-plan revision-request validation must not acquire leases"
                ),
            ),
            mock.patch.object(
                state,
                "add_evidence",
                side_effect=AssertionError(
                    "implementation-plan revision-request validation must not add evidence"
                ),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        root = self._root()
        evidence_id = root.bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(root.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._load(payloads)
            second = self._load(payloads)

        self.assertEqual(first, self.revision_request)
        self.assertEqual(second, self.revision_request)
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(root.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertTrue(first.implementation_plan_revision_requested)
        self.assertFalse(first.revised_implementation_plan_created)
        self.assertFalse(first.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(first, field))
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_live_rejection_is_repeatable_and_input_atomic(self):
        payloads = self._persisted_payloads()
        persisted_before = copy.deepcopy(payloads)
        lineage_before = self._snapshot_lineage()

        root = self._root()
        evidence = root.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with root.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            root.state.get_evidence(evidence.evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                with self.assertRaises(ValueError) as caught:
                    self._load(payloads)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(payloads, persisted_before)
        self.assertEqual(self._snapshot_lineage(), lineage_before)
        self.assertEqual(
            dataclasses.asdict(root.state.get_evidence(evidence.evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
