from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_review_request import (
    build_future_remediation_text_review_request,
)
from lightup.future_remediation_text_review_request_handoff import (
    future_remediation_text_review_request_from_dict,
    future_remediation_text_review_request_from_json,
    load_and_validate_future_remediation_text_review_request,
)


class FutureRemediationTextReviewRequestHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)
        self.review_request = build_future_remediation_text_review_request(
            self.proposal.to_json(),
            self.base.request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def _load(self, persisted=None, *, proposal=None):
        return load_and_validate_future_remediation_text_review_request(
            self.review_request.to_json() if persisted is None else persisted,
            self.proposal.to_json() if proposal is None else proposal,
            self.base.request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def test_round_trip_rebuilds_exact_live_review_request(self):
        parsed = future_remediation_text_review_request_from_json(
            self.review_request.to_json()
        )
        validated = self._load()

        self.assertEqual(parsed, self.review_request)
        self.assertEqual(validated, self.review_request)
        self.assertTrue(validated.review_requested)
        self.assertFalse(validated.remediation_accepted)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)

    def test_schema_primitive_and_review_rubric_drift_fail_closed(self):
        extra = self.review_request.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_text_review_request_from_dict(extra)

        bool_count = self.review_request.as_dict()
        bool_count["item_count"] = True
        with self.assertRaisesRegex(ValueError, "positive integer"):
            future_remediation_text_review_request_from_dict(bool_count)

        changed_checks = self.review_request.as_dict()
        changed_checks["required_checks"] = ["evidence_alignment"]
        with self.assertRaisesRegex(ValueError, "required_checks mismatch"):
            future_remediation_text_review_request_from_dict(changed_checks)

    def test_digest_and_authority_tampering_are_rejected(self):
        digest_tampered = self.review_request.as_dict()
        digest_tampered["review_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_review_request_from_dict(digest_tampered)

        accepted = self.review_request.as_dict()
        accepted["remediation_accepted"] = True
        with self.assertRaisesRegex(ValueError, "remediation_accepted"):
            future_remediation_text_review_request_from_dict(accepted)

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
                widened = self.review_request.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_review_request_from_dict(widened)

    def test_duplicate_json_keys_are_rejected(self):
        raw = self.review_request.to_json()
        duplicate = (
            raw[:-1]
            + ',"review_request_sha256":"'
            + ("0" * 64)
            + '"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_text_review_request_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_review_request(self):
        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()

    def test_proposal_substitution_invalidates_review_request(self):
        alternate = self.proposal.as_dict()
        alternate["content"] = "different remediation text"
        alternate["content_sha256"] = "0" * 64
        alternate["proposal_sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            self._load(proposal=alternate)


if __name__ == "__main__":
    unittest.main()
