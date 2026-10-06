from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
    future_remediation_implementation_plan_review_request_from_json,
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


class FutureRemediationImplementationPlanReviewRequestSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_to_json_is_byte_deterministic_and_round_trips(self):
        first = self.request.to_json()
        second = self.request.to_json()
        third = self.request.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_json(first),
            self.request,
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_dict(
                self.request.as_dict()
            ),
            self.request,
        )

    def test_snapshot_mutation_cannot_change_source_request(self):
        original_json = self.request.to_json()
        snapshot = self.request.as_dict()

        snapshot["planner_provider_id"] = "forged-provider"
        snapshot["plan_item_count"] = 999
        snapshot["implementation_plan_accepted"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"
        snapshot["required_checks"] = tuple(
            reversed(snapshot["required_checks"])
        )

        self.assertEqual(self.request.to_json(), original_json)
        self.assertFalse(self.request.implementation_plan_accepted)
        self.assertFalse(self.request.execution_allowed)
        self.assertEqual(self.request.future_semantics, "unresolved")
        self.assertEqual(self.request.security_verdict, "not_evaluated")

    def test_separate_snapshots_do_not_alias(self):
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["required_checks"], second["required_checks"])

        first["planner_model_id"] = "changed-only-in-first"
        first["required_checks"] = tuple(reversed(first["required_checks"]))

        self.assertNotEqual(first["planner_model_id"], second["planner_model_id"])
        self.assertNotEqual(first["required_checks"], second["required_checks"])
        self.assertEqual(
            tuple(second["required_checks"]),
            self.request.required_checks,
        )

    def test_forged_required_checks_fail_closed(self):
        reordered = self.request.as_dict()
        reordered["required_checks"] = tuple(
            reversed(reordered["required_checks"])
        )
        with self.assertRaisesRegex(ValueError, "required checks"):
            future_remediation_implementation_plan_review_request_from_dict(
                reordered
            )

        missing = self.request.as_dict()
        missing["required_checks"] = missing["required_checks"][:-1]
        with self.assertRaisesRegex(ValueError, "required checks"):
            future_remediation_implementation_plan_review_request_from_dict(
                missing
            )

    def test_forged_snapshot_authority_and_semantics_fail_closed(self):
        mutations = {field: True for field in _AUTHORITY_FLAGS}
        mutations.update(
            {
                "implementation_plan_accepted": True,
                "future_semantics": "resolved",
                "security_verdict": "secure",
            }
        )

        for field, forged_value in mutations.items():
            with self.subTest(field=field):
                payload = self.request.as_dict()
                payload[field] = forged_value
                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_review_request_from_dict(
                        payload
                    )

    def test_parser_detaches_from_caller_owned_persisted_snapshot(self):
        persisted = self.request.as_dict()
        parsed = future_remediation_implementation_plan_review_request_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        persisted["planner_provider_id"] = "mutated-after-parse"
        persisted["required_checks"] = tuple(
            reversed(persisted["required_checks"])
        )
        persisted["execution_allowed"] = True

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.request)
        self.assertEqual(parsed.required_checks, self.request.required_checks)
        self.assertFalse(parsed.execution_allowed)


if __name__ == "__main__":
    unittest.main()
