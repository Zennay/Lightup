from __future__ import annotations

import copy
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
)


class FutureRemediationTextReviewSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review = self.base.review

    def test_repeated_json_and_independent_snapshots_are_deterministic(self):
        first_json = self.review.to_json()
        second_json = self.review.to_json()
        first = self.review.as_dict()
        second = self.review.as_dict()

        self.assertEqual(first_json, second_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["checks"], second["checks"])
        self.assertIsNot(first["checks"][0], second["checks"][0])

    def test_snapshot_mutation_cannot_rewrite_typed_review_or_later_json(self):
        before_json = self.review.to_json()
        before = self.review

        snapshot = self.review.as_dict()
        snapshot["review_request_sha256"] = "0" * 64
        snapshot["reviewer_provider_id"] = "mutated-provider"
        snapshot["summary"] = "mutated snapshot summary"
        snapshot["checks"][0]["result"] = "fail"
        snapshot["remediation_accepted"] = False
        snapshot["execution_allowed"] = True
        snapshot["security_verdict"] = "forged"

        self.assertEqual(self.review, before)
        self.assertEqual(self.review.to_json(), before_json)
        self.assertEqual(self.review.checks[0].result, "pass")
        self.assertTrue(self.review.remediation_accepted)
        self.assertFalse(self.review.execution_allowed)
        self.assertEqual(self.review.security_verdict, "not_evaluated")

    def test_untouched_programmatic_snapshot_round_trips_exactly(self):
        snapshot = self.review.as_dict()
        parsed = future_remediation_text_review_from_dict(copy.deepcopy(snapshot))

        self.assertEqual(parsed, self.review)

    def test_forged_snapshot_checks_acceptance_lineage_and_authority_fail_closed(self):
        check = self.review.as_dict()
        check["checks"][0]["result"] = "fail"
        with self.assertRaisesRegex(ValueError, "every check to pass"):
            future_remediation_text_review_from_dict(check)

        accepted = self.review.as_dict()
        accepted["remediation_accepted"] = False
        with self.assertRaisesRegex(ValueError, "remediation_accepted mismatch"):
            future_remediation_text_review_from_dict(accepted)

        lineage = self.review.as_dict()
        lineage["review_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_review_from_dict(lineage)

        widened = self.review.as_dict()
        widened["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "authority flag"):
            future_remediation_text_review_from_dict(widened)

    def test_rejected_snapshot_inputs_are_not_mutated(self):
        for mutate, message in (
            (
                lambda payload: payload["checks"][0].__setitem__("result", "fail"),
                "every check to pass",
            ),
            (
                lambda payload: payload.__setitem__(
                    "remediation_accepted", False
                ),
                "remediation_accepted mismatch",
            ),
            (
                lambda payload: payload.__setitem__("execution_allowed", True),
                "authority flag",
            ),
        ):
            with self.subTest(message=message):
                payload = self.review.as_dict()
                mutate(payload)
                before = copy.deepcopy(payload)
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_text_review_from_dict(payload)
                self.assertEqual(payload, before)

    def test_post_parse_caller_mutation_cannot_rewrite_parsed_review(self):
        caller_owned = self.review.as_dict()
        parsed = future_remediation_text_review_from_dict(caller_owned)
        parsed_json = parsed.to_json()

        caller_owned["review_request_sha256"] = "0" * 64
        caller_owned["reviewer_provider_id"] = "caller-mutated-provider"
        caller_owned["summary"] = "caller-mutated-summary"
        caller_owned["checks"][0]["result"] = "fail"
        caller_owned["review_sha256"] = "0" * 64
        caller_owned["remediation_accepted"] = False
        caller_owned["execution_allowed"] = True
        caller_owned["security_verdict"] = "forged"

        self.assertEqual(parsed, self.review)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed.checks[0].result, "pass")
        self.assertTrue(parsed.remediation_accepted)
        self.assertFalse(parsed.execution_allowed)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
