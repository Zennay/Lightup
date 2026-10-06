from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
    future_remediation_implementation_plan_review_request_from_json,
    load_and_validate_future_remediation_implementation_plan_review_request,
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


class FutureRemediationImplementationPlanReviewRequestHandoffTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def _load(self, persisted=None, persisted_plan=None):
        return load_and_validate_future_remediation_implementation_plan_review_request(
            self.request.to_json() if persisted is None else persisted,
            self.base.base.plan.to_json()
            if persisted_plan is None
            else persisted_plan,
            self.base.base.base.planning_request.to_json(),
            self.base.base.base.base.review.to_json(),
            self.base.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.base.request,
            self.base.base.base.base.base.base.bundle,
            self.base.base.base.base.base.base.plan,
            self.base.base.base.base.base.base.report,
            self.base.base.base.base.base.base.preview,
            self.base.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.base.context,),
            self.base.base.base.base.base.base.state,
        )

    def test_json_and_dict_round_trip_require_live_plan_lineage(self):
        from_json = future_remediation_implementation_plan_review_request_from_json(
            self.request.to_json()
        )
        from_dict = future_remediation_implementation_plan_review_request_from_dict(
            self.request.as_dict()
        )
        validated = self._load()

        self.assertEqual(from_json, self.request)
        self.assertEqual(from_dict, self.request)
        self.assertEqual(validated, self.request)
        self.assertTrue(validated.implementation_plan_review_requested)
        self.assertFalse(validated.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(validated, field))

    def test_schema_digest_and_authority_tampering_fail_closed(self):
        extra = self.request.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_request_from_dict(extra)

        missing = self.request.as_dict()
        missing.pop("plan_sha256")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_request_from_dict(missing)

        digest = self.request.as_dict()
        digest["review_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_review_request_from_dict(digest)

        accepted = self.request.as_dict()
        accepted["implementation_plan_accepted"] = True
        with self.assertRaisesRegex(ValueError, "accepted"):
            future_remediation_implementation_plan_review_request_from_dict(accepted)

        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                widened = self.request.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_review_request_from_dict(
                        widened
                    )

    def test_required_checks_and_primitives_fail_closed(self):
        reordered = self.request.as_dict()
        reordered["required_checks"] = tuple(
            reversed(reordered["required_checks"])
        )
        with self.assertRaisesRegex(ValueError, "required checks"):
            future_remediation_implementation_plan_review_request_from_dict(reordered)

        bool_count = self.request.as_dict()
        bool_count["plan_item_count"] = True
        with self.assertRaisesRegex(ValueError, "positive integer"):
            future_remediation_implementation_plan_review_request_from_dict(bool_count)

        empty_model = self.request.as_dict()
        empty_model["planner_model_id"] = " "
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            future_remediation_implementation_plan_review_request_from_dict(empty_model)

    def test_duplicate_json_keys_are_rejected(self):
        raw = self.request.to_json()
        duplicate = (
            raw[:-1]
            + ',"review_request_sha256":"'
            + self.request.review_request_sha256
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_review_request_from_json(duplicate)

    def test_structural_parser_does_not_replace_live_evidence_validation(self):
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_json(
                self.request.to_json()
            ),
            self.request,
        )

        evidence = self.base.base.base.base.base.base.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_json(
                self.request.to_json()
            ),
            self.request,
        )
        with self.assertRaises(ValueError):
            self._load()

    def test_plan_tampering_invalidates_live_request_reuse(self):
        plan_payload = self.base.base.plan.as_dict()
        plan_payload["summary"] += " tampered"

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._load(persisted_plan=plan_payload)

    def test_persisted_value_type_must_be_json_or_object(self):
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._load(persisted=42)


if __name__ == "__main__":
    unittest.main()
