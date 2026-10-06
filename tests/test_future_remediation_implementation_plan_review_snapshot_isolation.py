from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_dict,
    future_remediation_implementation_plan_review_from_json,
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


class FutureRemediationImplementationPlanReviewSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def test_to_json_is_byte_deterministic_and_round_trips(self):
        first = self.review.to_json()
        second = self.review.to_json()
        third = self.review.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_remediation_implementation_plan_review_from_json(first),
            self.review,
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_from_dict(
                self.review.as_dict()
            ),
            self.review,
        )

    def test_top_level_snapshot_mutation_cannot_change_source_review(self):
        original_json = self.review.to_json()
        snapshot = self.review.as_dict()

        snapshot["summary"] = "forged summary"
        snapshot["implementation_plan_accepted"] = False
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.review.to_json(), original_json)
        self.assertTrue(self.review.implementation_plan_accepted)
        self.assertFalse(self.review.execution_allowed)
        self.assertEqual(self.review.future_semantics, "unresolved")
        self.assertEqual(self.review.security_verdict, "not_evaluated")

    def test_nested_check_snapshot_mutation_cannot_change_source_review(self):
        original_json = self.review.to_json()
        snapshot = self.review.as_dict()

        self.assertIsInstance(snapshot["checks"], tuple)
        snapshot["checks"][0]["result"] = "fail"
        snapshot["checks"][0]["check"] = "forged-check"

        self.assertEqual(self.review.to_json(), original_json)
        self.assertEqual(self.review.checks[0].result, "pass")
        self.assertNotEqual(self.review.checks[0].check, "forged-check")

    def test_separate_snapshots_do_not_alias(self):
        first = self.review.as_dict()
        second = self.review.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["checks"], second["checks"])
        self.assertIsNot(first["checks"][0], second["checks"][0])

        first["summary"] = "changed only in first"
        first["checks"][0]["result"] = "fail"

        self.assertNotEqual(first["summary"], second["summary"])
        self.assertEqual(second["checks"][0]["result"], "pass")
        self.assertEqual(self.review.checks[0].result, "pass")

    def test_forged_snapshot_authority_and_semantics_fail_closed(self):
        mutations = {}

        for field in _AUTHORITY_FLAGS:
            mutations[field] = True
        mutations["future_semantics"] = "resolved"
        mutations["security_verdict"] = "secure"
        mutations["implementation_plan_accepted"] = False

        for field, forged_value in mutations.items():
            with self.subTest(field=field):
                payload = self.review.as_dict()
                payload[field] = forged_value
                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_review_from_dict(payload)

    def test_forged_snapshot_review_outcome_fails_closed(self):
        nested_check = self.review.as_dict()
        nested_check["checks"][0]["result"] = "fail"
        with self.assertRaisesRegex(
            ValueError,
            "approved implementation plan review requires every check to pass",
        ):
            future_remediation_implementation_plan_review_from_dict(nested_check)

        decision = self.review.as_dict()
        decision["decision"] = "revision_required"
        with self.assertRaisesRegex(
            ValueError,
            "revision_required implementation plan review requires a non-pass check",
        ):
            future_remediation_implementation_plan_review_from_dict(decision)

    def test_parser_detaches_from_caller_owned_persisted_snapshot(self):
        persisted = self.review.as_dict()
        parsed = future_remediation_implementation_plan_review_from_dict(persisted)
        parsed_json = parsed.to_json()

        persisted["summary"] = "mutated after parse"
        persisted["checks"][0]["result"] = "fail"
        persisted["execution_allowed"] = True

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.review)
        self.assertEqual(parsed.checks[0].result, "pass")
        self.assertFalse(parsed.execution_allowed)


if __name__ == "__main__":
    unittest.main()
