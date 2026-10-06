from __future__ import annotations

import unittest

import test_future_remediation_text_revision_review_request as request_tests
from lightup.future_remediation_text_revision_review_request_handoff import (
    future_remediation_text_revision_review_request_from_dict,
    future_remediation_text_revision_review_request_from_json,
    load_and_validate_future_remediation_text_revision_review_request,
)


class FutureRemediationTextRevisionReviewRequestHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationTextRevisionReviewRequestTest(
            "test_live_revision_proposal_requests_independent_review_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base._build()

    def _load(self, persisted=None, *, revision_proposal=None):
        return load_and_validate_future_remediation_text_revision_review_request(
            self.request.to_json() if persisted is None else persisted,
            (
                self.base.base.proposal.to_json()
                if revision_proposal is None
                else revision_proposal
            ),
            self.base.base.base.revision_request.to_json(),
            self.base.base.base.review.to_json(),
            self.base.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.base.request,
            self.base.base.base.base.base.base.bundle,
            self.base.base.base.base.base.base.plan,
            self.base.base.base.base.base.base.report,
            self.base.base.base.base.base.base.preview,
            self.base.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.base.context,),
            self.base.base.base.base.base.base.state,
        )

    def test_round_trip_rebuilds_exact_live_review_request(self):
        parsed = future_remediation_text_revision_review_request_from_json(
            self.request.to_json()
        )
        validated = self._load()

        self.assertEqual(parsed, self.request)
        self.assertEqual(validated, self.request)
        self.assertTrue(validated.review_requested)
        self.assertFalse(validated.remediation_accepted)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)
        self.assertEqual(validated.future_semantics, "unresolved")
        self.assertEqual(validated.security_verdict, "not_evaluated")

    def test_programmatic_and_json_forms_are_equivalent(self):
        from_dict = future_remediation_text_revision_review_request_from_dict(
            self.request.as_dict()
        )
        from_json = future_remediation_text_revision_review_request_from_json(
            self.request.to_json()
        )

        self.assertEqual(from_dict, from_json)
        self.assertEqual(from_dict, self.request)

    def test_schema_rubric_digest_and_authority_tampering_fail_closed(self):
        extra = self.request.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_text_revision_review_request_from_dict(extra)

        changed_checks = self.request.as_dict()
        changed_checks["required_checks"] = ["evidence_alignment"]
        with self.assertRaisesRegex(ValueError, "required_checks mismatch"):
            future_remediation_text_revision_review_request_from_dict(
                changed_checks
            )

        digest = self.request.as_dict()
        digest["review_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_review_request_from_dict(digest)

        accepted = self.request.as_dict()
        accepted["remediation_accepted"] = True
        with self.assertRaisesRegex(ValueError, "remediation_accepted"):
            future_remediation_text_revision_review_request_from_dict(accepted)

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
                widened = self.request.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_revision_review_request_from_dict(
                        widened
                    )

    def test_provider_and_model_must_be_non_empty(self):
        for field in ("provider_id", "model_id"):
            with self.subTest(field=field):
                payload = self.request.as_dict()
                payload[field] = ""
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    future_remediation_text_revision_review_request_from_dict(
                        payload
                    )

    def test_duplicate_json_keys_are_rejected_before_decode(self):
        raw = self.request.to_json()
        duplicate = (
            raw[:-1]
            + ',"review_request_sha256":"'
            + ("0" * 64)
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_text_revision_review_request_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_review_request(self):
        evidence_id = (
            self.base.base.base.base.base.base.bundle.items[0].evidence[0].evidence_id
        )
        current_sha = (
            self.base.base.base.base.base.base.bundle.items[0].evidence[0].sha256
        )
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()

    def test_revised_proposal_substitution_invalidates_review_request(self):
        alternate = self.base.base.proposal.as_dict()
        alternate["content"] = "different revised remediation text"
        alternate["content_sha256"] = "0" * 64
        alternate["revision_proposal_sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            self._load(revision_proposal=alternate)


if __name__ == "__main__":
    unittest.main()
