from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
    future_remediation_implementation_plan_revision_request_from_json,
)


class FutureRemediationImplementationPlanRevisionRequestSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = handoff_tests._request(
            required_revisions=tuple(
                REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[:2]
            )
        )

    def test_serialization_is_deterministic_and_snapshots_are_detached(self):
        before_json = self.request.to_json()
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertEqual(self.request.to_json(), before_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

        first["reviewer_model_id"] = "caller-mutated-model"
        first["required_revisions"] = [
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[1],
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],
        ]
        first["implementation_plan_accepted"] = True

        self.assertEqual(self.request.to_json(), before_json)
        self.assertEqual(
            self.request.required_revisions,
            tuple(REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[:2]),
        )
        self.assertFalse(self.request.implementation_plan_accepted)
        self.assertNotEqual(first, second)

    def test_canonical_untouched_snapshots_round_trip_exactly(self):
        from_dict = future_remediation_implementation_plan_revision_request_from_dict(
            self.request.as_dict()
        )
        from_json = future_remediation_implementation_plan_revision_request_from_json(
            self.request.to_json()
        )

        self.assertEqual(from_dict, self.request)
        self.assertEqual(from_json, self.request)
        self.assertEqual(from_dict.to_json(), self.request.to_json())
        self.assertEqual(from_json.to_json(), self.request.to_json())

    def test_forged_snapshots_fail_closed_without_mutating_source(self):
        before_json = self.request.to_json()

        cases = []

        reordered = self.request.as_dict()
        reordered["required_revisions"] = [
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[1],
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],
        ]
        cases.append((reordered, "invalid or out of order"))

        accepted = self.request.as_dict()
        accepted["implementation_plan_accepted"] = True
        cases.append((accepted, "implementation_plan_accepted"))

        widened = self.request.as_dict()
        widened["code_change_authorized"] = True
        cases.append((widened, "authority flag"))

        resolved = self.request.as_dict()
        resolved["future_semantics"] = "resolved"
        cases.append((resolved, "future_semantics"))

        verdict = self.request.as_dict()
        verdict["security_verdict"] = "secure"
        cases.append((verdict, "security_verdict"))

        for forged, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_implementation_plan_revision_request_from_dict(
                        forged
                    )
                self.assertEqual(self.request.to_json(), before_json)

    def test_post_parse_caller_mutation_cannot_change_parsed_request(self):
        payload = self.request.as_dict()
        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            payload
        )
        parsed_json = parsed.to_json()

        payload["reviewer_provider_id"] = "caller-mutated-provider"
        payload["required_revisions"] = []
        payload["execution_allowed"] = True
        payload["future_semantics"] = "resolved"
        payload["security_verdict"] = "secure"

        self.assertEqual(parsed, self.request)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed.to_json(), self.request.to_json())
        self.assertFalse(parsed.execution_allowed)
        self.assertEqual(parsed.future_semantics, "unresolved")
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
