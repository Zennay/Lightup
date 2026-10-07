from __future__ import annotations

import copy
import unittest

import test_future_remediation_text_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_dict,
)


class FutureRemediationTextRevisionProposalSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionProposalHandoffTest(
            "test_round_trip_requires_complete_live_revision_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.proposal = self.base.proposal

    def test_repeated_json_and_independent_snapshots_are_deterministic(self):
        first_json = self.proposal.to_json()
        second_json = self.proposal.to_json()
        first = self.proposal.as_dict()
        second = self.proposal.as_dict()

        self.assertEqual(first_json, second_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_snapshot_mutation_cannot_rewrite_typed_proposal_or_later_json(self):
        before_json = self.proposal.to_json()
        before = self.proposal

        snapshot = self.proposal.as_dict()
        snapshot["revision_request_sha256"] = "0" * 64
        snapshot["provider_id"] = "mutated-provider"
        snapshot["content"] = "mutated snapshot content"
        snapshot["content_sha256"] = "0" * 64
        snapshot["execution_allowed"] = True
        snapshot["security_verdict"] = "forged"

        self.assertEqual(self.proposal, before)
        self.assertEqual(self.proposal.to_json(), before_json)
        self.assertFalse(self.proposal.execution_allowed)
        self.assertEqual(self.proposal.security_verdict, "not_evaluated")

    def test_untouched_programmatic_snapshot_round_trips_exactly(self):
        snapshot = self.proposal.as_dict()
        parsed = future_remediation_text_revision_proposal_from_dict(
            copy.deepcopy(snapshot)
        )

        self.assertEqual(parsed, self.proposal)

    def test_forged_snapshot_content_lineage_acceptance_and_authority_fail_closed(self):
        content = self.proposal.as_dict()
        content["content"] += " caller-forged"
        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            future_remediation_text_revision_proposal_from_dict(content)

        lineage = self.proposal.as_dict()
        lineage["revision_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_proposal_from_dict(lineage)

        accepted = self.proposal.as_dict()
        accepted["remediation_accepted"] = True
        with self.assertRaisesRegex(ValueError, "remediation_accepted"):
            future_remediation_text_revision_proposal_from_dict(accepted)

        widened = self.proposal.as_dict()
        widened["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "authority flag"):
            future_remediation_text_revision_proposal_from_dict(widened)

    def test_rejected_snapshot_inputs_are_not_mutated(self):
        for mutate, message in (
            (
                lambda payload: payload.__setitem__(
                    "content", payload["content"] + " caller-forged"
                ),
                "content digest mismatch",
            ),
            (
                lambda payload: payload.__setitem__(
                    "revision_request_sha256", "0" * 64
                ),
                "digest mismatch",
            ),
            (
                lambda payload: payload.__setitem__("execution_allowed", True),
                "authority flag",
            ),
        ):
            with self.subTest(message=message):
                payload = self.proposal.as_dict()
                mutate(payload)
                before = copy.deepcopy(payload)
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_text_revision_proposal_from_dict(payload)
                self.assertEqual(payload, before)

    def test_post_parse_caller_mutation_cannot_rewrite_parsed_proposal(self):
        caller_owned = self.proposal.as_dict()
        parsed = future_remediation_text_revision_proposal_from_dict(caller_owned)
        parsed_json = parsed.to_json()

        caller_owned["provider_id"] = "caller-mutated-provider"
        caller_owned["content"] = "caller-mutated-content"
        caller_owned["content_sha256"] = "0" * 64
        caller_owned["revision_proposal_sha256"] = "0" * 64
        caller_owned["execution_allowed"] = True
        caller_owned["security_verdict"] = "forged"

        self.assertEqual(parsed, self.proposal)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertFalse(parsed.execution_allowed)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
