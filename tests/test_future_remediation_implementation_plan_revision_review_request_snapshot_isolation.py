from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_review_request as review_request_tests
from lightup.future_remediation_implementation_plan_revision_review_request import (
    FutureRemediationImplementationPlanRevisionReviewRequest,
)


class FutureRemediationImplementationPlanRevisionReviewRequestSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            review_request_tests.FutureRemediationImplementationPlanRevisionReviewRequestTest(
                "test_live_valid_revised_plan_produces_review_only_request"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_serialization_is_deterministic_and_snapshots_are_detached(self):
        before_json = self.request.to_json()
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertEqual(self.request.to_json(), before_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

        first["planner_model_id"] = "caller-mutated-model"
        first["required_checks"] = tuple(reversed(first["required_checks"]))
        first["execution_allowed"] = True

        self.assertEqual(self.request.to_json(), before_json)
        self.assertNotEqual(first, second)
        self.assertFalse(self.request.execution_allowed)

    def test_canonical_untouched_snapshot_reconstructs_exact_request(self):
        reconstructed = FutureRemediationImplementationPlanRevisionReviewRequest(
            **self.request.as_dict()
        )

        self.assertEqual(reconstructed, self.request)
        self.assertEqual(reconstructed.to_json(), self.request.to_json())

    def test_forged_snapshots_fail_closed_without_mutating_source(self):
        before_json = self.request.to_json()
        cases = [
            ("revised_implementation_plan_accepted", True, "accepted"),
            ("execution_allowed", True, "authority flag"),
            ("future_semantics", "resolved", "future_semantics"),
            ("security_verdict", "secure", "security_verdict"),
        ]

        for field, value, message in cases:
            with self.subTest(field=field):
                forged = self.request.as_dict()
                forged[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    FutureRemediationImplementationPlanRevisionReviewRequest(
                        **forged
                    )
                self.assertEqual(self.request.to_json(), before_json)

    def test_post_reconstruction_caller_mutation_cannot_change_request(self):
        payload = self.request.as_dict()
        reconstructed = FutureRemediationImplementationPlanRevisionReviewRequest(
            **payload
        )
        reconstructed_json = reconstructed.to_json()

        payload["planner_provider_id"] = "caller-mutated-provider"
        payload["required_checks"] = ()
        payload["execution_allowed"] = True
        payload["future_semantics"] = "resolved"

        self.assertEqual(reconstructed, self.request)
        self.assertEqual(reconstructed.to_json(), reconstructed_json)
        self.assertEqual(reconstructed.to_json(), self.request.to_json())
        self.assertFalse(reconstructed.execution_allowed)


if __name__ == "__main__":
    unittest.main()
