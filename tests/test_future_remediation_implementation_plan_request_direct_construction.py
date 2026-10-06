from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_request as request_tests
from lightup.future_remediation_implementation_plan_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRequest,
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


class FutureRemediationImplementationPlanRequestDirectConstructionTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanRequestTest(
            "test_approved_review_requests_planning_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base._build()

    def test_canonical_request_can_be_reconstructed_directly(self):
        reconstructed = FutureRemediationImplementationPlanRequest(
            **self.request.as_dict()
        )

        self.assertEqual(reconstructed, self.request)
        self.assertEqual(
            reconstructed.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
        )

    def test_direct_construction_rejects_lifecycle_and_authority_widening(self):
        for field, value in (
            ("implementation_planning_requested", False),
            ("implementation_planning_requested", 1),
            ("implementation_plan_created", True),
            ("implementation_plan_created", 0),
            ("future_semantics", "resolved"),
            ("security_verdict", "pass"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    replace(self.request, **{field: value})

        for field in _AUTHORITY_FLAGS:
            for value in (True, 0):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, "authority flag"):
                        replace(self.request, **{field: value})

    def test_direct_construction_rejects_schema_and_primitive_confusion(self):
        cases = (
            ("schema_version", "st5.remediation_implementation_plan_request.v2"),
            ("reviewer_provider_id", ""),
            ("reviewer_model_id", " "),
            ("item_count", 0),
            ("item_count", True),
            ("item_count", 1.0),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    replace(self.request, **{field: value})

    def test_direct_construction_requires_canonical_lineage_digests(self):
        for field in (
            "review_sha256",
            "review_request_sha256",
            "proposal_sha256",
            "content_sha256",
            "implementation_request_sha256",
        ):
            for value in ("not-a-digest", "A" * 64):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, "canonical lowercase"):
                        replace(self.request, **{field: value})

    def test_direct_construction_recomputes_request_digest(self):
        alternate = (
            "0" * 64
            if self.request.review_sha256 != "0" * 64
            else "f" * 64
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, review_sha256=alternate)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, reviewer_model_id="forged-model")

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, item_count=self.request.item_count + 1)

    def test_as_dict_round_trip_keeps_planning_only_stop_line(self):
        reconstructed = FutureRemediationImplementationPlanRequest(
            **self.request.as_dict()
        )

        self.assertTrue(reconstructed.implementation_planning_requested)
        self.assertFalse(reconstructed.implementation_plan_created)
        self.assertEqual(reconstructed.future_semantics, "unresolved")
        self.assertEqual(reconstructed.security_verdict, "not_evaluated")
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(reconstructed, field))


if __name__ == "__main__":
    unittest.main()
