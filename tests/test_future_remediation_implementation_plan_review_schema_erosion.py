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


class FutureRemediationImplementationPlanReviewSchemaErosionTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    @staticmethod
    def _mutable_payload(review):
        payload = review.as_dict()
        payload["checks"] = [dict(item) for item in payload["checks"]]
        return payload

    def test_canonical_json_and_dict_round_trip(self):
        self.assertEqual(
            future_remediation_implementation_plan_review_from_json(
                self.review.to_json()
            ),
            self.review,
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_from_dict(
                self.review.as_dict()
            ),
            self.review,
        )

    def test_top_level_non_object_and_schema_erosion_fail_closed(self):
        for raw in ("[]", "null", "42", '"review"'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "payload must be an object"):
                    future_remediation_implementation_plan_review_from_json(raw)

        for payload in ([], (), None, 42, "review"):
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaisesRegex(ValueError, "payload must be an object"):
                    future_remediation_implementation_plan_review_from_dict(payload)

        missing = self.review.as_dict()
        missing.pop("summary")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(missing)

        widened = self.review.as_dict()
        widened["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(widened)

    def test_check_container_shape_and_count_fail_closed(self):
        cases = (
            (None, "list or tuple"),
            ({}, "list or tuple"),
            ("checks", "list or tuple"),
            ([], "count mismatch"),
            (list(self.review.as_dict()["checks"]) + [{"check": "extra", "result": "pass"}], "count mismatch"),
        )
        for checks, message in cases:
            with self.subTest(checks=checks):
                payload = self.review.as_dict()
                payload["checks"] = checks
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_implementation_plan_review_from_dict(payload)

    def test_nested_check_schema_erosion_fails_closed(self):
        missing_result = self._mutable_payload(self.review)
        missing_result["checks"][0].pop("result")
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(missing_result)

        missing_name = self._mutable_payload(self.review)
        missing_name["checks"][0].pop("check")
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(missing_name)

        widened = self._mutable_payload(self.review)
        widened["checks"][0]["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(widened)

        non_object = self._mutable_payload(self.review)
        non_object["checks"][0] = "evidence_alignment"
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(non_object)

    def test_nested_check_value_type_confusion_fails_closed(self):
        for result in (True, 1, None, "PASS", ""):
            with self.subTest(result=result):
                payload = self._mutable_payload(self.review)
                payload["checks"][0]["result"] = result
                with self.assertRaisesRegex(ValueError, "result .* is invalid"):
                    future_remediation_implementation_plan_review_from_dict(payload)

        wrong_name = self._mutable_payload(self.review)
        wrong_name["checks"][0]["check"] = wrong_name["checks"][1]["check"]
        with self.assertRaisesRegex(ValueError, "order or name mismatch"):
            future_remediation_implementation_plan_review_from_dict(wrong_name)

        for decision in (True, 1, None, "APPROVED", ""):
            with self.subTest(decision=decision):
                payload = self._mutable_payload(self.review)
                payload["decision"] = decision
                with self.assertRaisesRegex(ValueError, "decision is invalid"):
                    future_remediation_implementation_plan_review_from_dict(payload)

    def test_nonapproved_canonical_reviews_remain_supported_and_non_executable(self):
        cases = (
            review_tests._review_json(
                decision="revision_required",
                rollback_sufficiency="fail",
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
                from_json = future_remediation_implementation_plan_review_from_json(
                    review.to_json()
                )
                from_dict = future_remediation_implementation_plan_review_from_dict(
                    review.as_dict()
                )

                self.assertEqual(from_json, review)
                self.assertEqual(from_dict, review)
                self.assertFalse(review.implementation_plan_accepted)
                for field in _AUTHORITY_FLAGS:
                    self.assertIs(getattr(review, field), False)
                self.assertEqual(review.future_semantics, "unresolved")
                self.assertEqual(review.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
