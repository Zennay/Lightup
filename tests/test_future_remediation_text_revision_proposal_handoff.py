from __future__ import annotations

import unittest

import test_future_remediation_text_revision_proposal as revision_proposal_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_dict,
    future_remediation_text_revision_proposal_from_json,
    load_and_validate_future_remediation_text_revision_proposal,
)


class FutureRemediationTextRevisionProposalHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_proposal_tests.FutureRemediationTextRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)

    def _load(self, persisted=None):
        return load_and_validate_future_remediation_text_revision_proposal(
            self.proposal.to_json() if persisted is None else persisted,
            self.base.revision_request.to_json(),
            self.base.review.to_json(),
            self.base.base.base.review_request.to_json(),
            self.base.base.base.proposal.to_json(),
            self.base.base.base.base.request,
            self.base.base.base.base.bundle,
            self.base.base.base.base.plan,
            self.base.base.base.base.report,
            self.base.base.base.base.preview,
            self.base.base.base.base.transition_proposal,
            (self.base.base.base.base.resolution,),
            (self.base.base.base.base.context,),
            self.base.base.base.base.state,
        )

    def test_round_trip_requires_complete_live_revision_lineage(self):
        parsed = future_remediation_text_revision_proposal_from_json(
            self.proposal.to_json()
        )
        validated = self._load()

        self.assertEqual(parsed, self.proposal)
        self.assertEqual(validated, self.proposal)
        self.assertTrue(validated.remediation_revision_proposal_created)
        self.assertFalse(validated.remediation_accepted)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)

    def test_programmatic_and_json_forms_are_equivalent(self):
        from_dict = future_remediation_text_revision_proposal_from_dict(
            self.proposal.as_dict()
        )
        from_json = future_remediation_text_revision_proposal_from_json(
            self.proposal.to_json()
        )

        self.assertEqual(from_dict, from_json)
        self.assertEqual(from_dict, self.proposal)

    def test_content_digest_and_authority_tampering_fail_closed(self):
        content = self.proposal.as_dict()
        content["content"] += " tampered"
        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            future_remediation_text_revision_proposal_from_dict(content)

        digest = self.proposal.as_dict()
        digest["revision_proposal_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_proposal_from_dict(digest)

        for field in (
            "code_change_authorized",
            "tool_call_created",
            "execution_allowed",
            "target_interaction_allowed",
            "future_state_retest_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        ):
            with self.subTest(field=field):
                widened = self.proposal.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_revision_proposal_from_dict(widened)

    def test_duplicate_json_keys_are_rejected_before_decode(self):
        raw = self.proposal.to_json()
        duplicate = (
            raw[:-1]
            + ',"revision_proposal_sha256":"'
            + ("0" * 64)
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_text_revision_proposal_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_revision_proposal(self):
        evidence_id = self.base.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()

    def test_revision_request_substitution_invalidates_persisted_proposal(self):
        request = self.base.revision_request.as_dict()
        request["revision_request_sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            load_and_validate_future_remediation_text_revision_proposal(
                self.proposal.to_json(),
                request,
                self.base.review.to_json(),
                self.base.base.base.review_request.to_json(),
                self.base.base.base.proposal.to_json(),
                self.base.base.base.base.request,
                self.base.base.base.base.bundle,
                self.base.base.base.base.plan,
                self.base.base.base.base.report,
                self.base.base.base.base.preview,
                self.base.base.base.base.transition_proposal,
                (self.base.base.base.base.resolution,),
                (self.base.base.base.base.context,),
                self.base.base.base.base.state,
            )


if __name__ == "__main__":
    unittest.main()
