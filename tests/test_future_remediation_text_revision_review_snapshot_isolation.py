from __future__ import annotations

import copy
import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests
from lightup.future_remediation_text_revision_review_handoff import (
    future_remediation_text_revision_review_from_dict,
)


class FutureRemediationTextRevisionReviewSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
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
        snapshot["review_sha256"] = "0" * 64
        snapshot["summary"] = "mutated snapshot summary"
        snapshot["checks"][0]["result"] = "fail"
        snapshot["execution_allowed"] = True
        snapshot["security_verdict"] = "forged"

        self.assertEqual(self.review, before)
        self.assertEqual(self.review.to_json(), before_json)
        self.assertFalse(self.review.execution_allowed)
        self.assertEqual(self.review.security_verdict, "not_evaluated")
        self.assertEqual(self.review.checks[0].result, "pass")

    def test_untouched_programmatic_snapshot_round_trips_exactly(self):
        snapshot = self.review.as_dict()
        parsed = future_remediation_text_revision_review_from_dict(
            copy.deepcopy(snapshot)
        )

        self.assertEqual(parsed, self.review)

    def test_forged_snapshot_authority_widening_fails_closed(self):
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
                snapshot = self.review.as_dict()
                snapshot[field] = True
                before = copy.deepcopy(snapshot)
                with self.assertRaises(ValueError):
                    future_remediation_text_revision_review_from_dict(snapshot)
                self.assertEqual(snapshot, before)

    def test_post_parse_caller_mutation_cannot_rewrite_parsed_review(self):
        caller_owned = self.review.as_dict()
        parsed = future_remediation_text_revision_review_from_dict(caller_owned)
        parsed_json = parsed.to_json()

        caller_owned["summary"] = "caller changed after parse"
        caller_owned["checks"][0]["result"] = "fail"
        caller_owned["review_sha256"] = "0" * 64
        caller_owned["execution_allowed"] = True

        self.assertEqual(parsed, self.review)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed.checks[0].result, "pass")
        self.assertFalse(parsed.execution_allowed)


if __name__ == "__main__":
    unittest.main()
