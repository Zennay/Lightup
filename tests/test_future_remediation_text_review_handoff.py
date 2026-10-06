from __future__ import annotations

import unittest

import test_future_remediation_text_review as review_tests
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
    future_remediation_text_review_from_json,
    load_and_validate_future_remediation_text_review,
)


class FutureRemediationTextReviewHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def _load(self, persisted=None):
        return load_and_validate_future_remediation_text_review(
            self.review.to_json() if persisted is None else persisted,
            self.base.review_request.to_json(),
            self.base.proposal.to_json(),
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

    def test_approved_review_round_trips_without_action_authority(self):
        parsed = future_remediation_text_review_from_json(self.review.to_json())
        validated = self._load()

        self.assertEqual(parsed, self.review)
        self.assertEqual(validated, self.review)
        self.assertTrue(validated.review_completed)
        self.assertTrue(validated.remediation_accepted)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)
        self.assertEqual(validated.future_semantics, "unresolved")
        self.assertEqual(validated.security_verdict, "not_evaluated")

    def test_programmatic_as_dict_and_json_forms_are_equivalent(self):
        from_dict = future_remediation_text_review_from_dict(
            self.review.as_dict()
        )
        from_json = future_remediation_text_review_from_json(
            self.review.to_json()
        )

        self.assertEqual(from_dict, from_json)
        self.assertEqual(from_dict, self.review)

    def test_digest_summary_and_authority_tampering_fail_closed(self):
        digest_tampered = self.review.as_dict()
        digest_tampered["review_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_review_from_dict(digest_tampered)

        summary_tampered = self.review.as_dict()
        summary_tampered["summary"] += " changed"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_review_from_dict(summary_tampered)

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
                widened = self.review.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_review_from_dict(widened)

    def test_decision_check_and_acceptance_coherence_are_revalidated(self):
        bad_check = self.review.as_dict()
        bad_check["checks"][0]["result"] = "fail"
        with self.assertRaisesRegex(ValueError, "every check to pass"):
            future_remediation_text_review_from_dict(bad_check)

        bad_acceptance = self.review.as_dict()
        bad_acceptance["remediation_accepted"] = False
        with self.assertRaisesRegex(ValueError, "remediation_accepted mismatch"):
            future_remediation_text_review_from_dict(bad_acceptance)

    def test_duplicate_json_keys_are_rejected_before_decode(self):
        raw = self.review.to_json()
        duplicate = raw[:-1] + ',"review_sha256":"' + ("0" * 64) + '"}'

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_text_review_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_review(self):
        evidence_id = self.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()

    def test_revision_and_insufficient_evidence_reviews_round_trip_unaccepted(self):
        cases = (
            review_tests._review_json(
                decision="revision_required",
                unsupported_claims="fail",
            ),
            review_tests._review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            ),
        )
        for content in cases:
            with self.subTest(content=content):
                gateway, _ = self.base._review_gateway(content)
                review = self.base._review(gateway)
                validated = load_and_validate_future_remediation_text_review(
                    review.to_json(),
                    self.base.review_request.to_json(),
                    self.base.proposal.to_json(),
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
                self.assertFalse(validated.remediation_accepted)
                self.assertFalse(validated.execution_allowed)
                self.assertEqual(validated.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
