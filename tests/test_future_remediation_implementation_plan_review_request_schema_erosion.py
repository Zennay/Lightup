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


class FutureRemediationImplementationPlanReviewRequestSchemaErosionTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_canonical_json_and_dict_round_trip(self):
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_json(
                self.request.to_json()
            ),
            self.request,
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_dict(
                self.request.as_dict()
            ),
            self.request,
        )

    def test_top_level_non_object_and_schema_erosion_fail_closed(self):
        for raw in ("[]", "null", "42", '"request"'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "payload must be an object"):
                    future_remediation_implementation_plan_review_request_from_json(raw)

        for payload in ([], (), None, 42, "request"):
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaisesRegex(ValueError, "payload must be an object"):
                    future_remediation_implementation_plan_review_request_from_dict(
                        payload
                    )

        missing = self.request.as_dict()
        missing.pop("plan_sha256")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_request_from_dict(missing)

        widened = self.request.as_dict()
        widened["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_request_from_dict(widened)

    def test_required_checks_container_and_exact_rubric_fail_closed(self):
        for checks in (None, {}, "checks", 1):
            with self.subTest(checks=checks):
                payload = self.request.as_dict()
                payload["required_checks"] = checks
                with self.assertRaisesRegex(ValueError, "list or tuple"):
                    future_remediation_implementation_plan_review_request_from_dict(
                        payload
                    )

        canonical = tuple(self.request.required_checks)
        invalid = (
            (),
            canonical[:-1],
            canonical + ("extra_check",),
            tuple(reversed(canonical)),
            (True,) + canonical[1:],
        )
        for checks in invalid:
            with self.subTest(checks=checks):
                payload = self.request.as_dict()
                payload["required_checks"] = checks
                with self.assertRaisesRegex(ValueError, "required checks mismatch"):
                    future_remediation_implementation_plan_review_request_from_dict(
                        payload
                    )

    def test_planner_provenance_is_bounded_and_string_typed(self):
        invalid_values = ("", " ", "\x00provider", "x" * 257, True, 7, None)
        for field in ("planner_provider_id", "planner_model_id"):
            for value in invalid_values:
                with self.subTest(field=field, value=value):
                    payload = self.request.as_dict()
                    payload[field] = value
                    with self.assertRaises(ValueError):
                        future_remediation_implementation_plan_review_request_from_dict(
                            payload
                        )

    def test_plan_item_count_rejects_type_confusion_and_nonpositive_values(self):
        for value in (True, False, 0, -1, 1.0, "1", None):
            with self.subTest(value=value):
                payload = self.request.as_dict()
                payload["plan_item_count"] = value
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    future_remediation_implementation_plan_review_request_from_dict(
                        payload
                    )

    def test_lineage_digests_must_remain_canonical_lowercase_sha256(self):
        invalid_values = (True, None, "0" * 63, "A" * 64, "g" * 64)
        for field in (
            "implementation_request_sha256",
            "remediation_review_sha256",
            "proposal_sha256",
            "content_sha256",
            "plan_sha256",
            "review_request_sha256",
        ):
            for value in invalid_values:
                with self.subTest(field=field, value=value):
                    payload = self.request.as_dict()
                    payload[field] = value
                    with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                        future_remediation_implementation_plan_review_request_from_dict(
                            payload
                        )

    def test_lifecycle_authority_future_and_verdict_type_confusion_fail_closed(self):
        review_requested = self.request.as_dict()
        review_requested["implementation_plan_review_requested"] = False
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(
                review_requested
            )

        review_requested_int = self.request.as_dict()
        review_requested_int["implementation_plan_review_requested"] = 1
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(
                review_requested_int
            )

        false_fields = ("implementation_plan_accepted",) + _AUTHORITY_FLAGS
        for field in false_fields:
            for value in (True, 0):
                with self.subTest(field=field, value=value):
                    payload = self.request.as_dict()
                    payload[field] = value
                    with self.assertRaises(ValueError):
                        future_remediation_implementation_plan_review_request_from_dict(
                            payload
                        )

        future = self.request.as_dict()
        future["future_semantics"] = "resolved"
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(future)

        verdict = self.request.as_dict()
        verdict["security_verdict"] = "secure"
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(verdict)


if __name__ == "__main__":
    unittest.main()
