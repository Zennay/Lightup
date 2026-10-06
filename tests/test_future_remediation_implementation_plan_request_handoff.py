from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_request as request_tests
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_dict,
    future_remediation_implementation_plan_request_from_json,
    load_and_validate_future_remediation_implementation_plan_request,
)


class FutureRemediationImplementationPlanRequestHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanRequestTest(
            "test_approved_review_requests_planning_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base._build()

    def _load(self, persisted=None):
        return load_and_validate_future_remediation_implementation_plan_request(
            self.request.to_json() if persisted is None else persisted,
            self.base.review.to_json(),
            self.base.base.review_request.to_json(),
            self.base.base.proposal.to_json(),
            self.base.base.base.request,
            self.base.base.base.bundle,
            self.base.base.base.plan,
            self.base.base.base.report,
            self.base.base.base.preview,
            self.base.base.base.transition_proposal,
            (self.base.base.base.resolution,),
            (self.base.base.base.context,),
            self.base.base.base.state,
        )

    def test_round_trip_requires_exact_live_accepted_review(self):
        parsed = future_remediation_implementation_plan_request_from_json(
            self.request.to_json()
        )
        validated = self._load()

        self.assertEqual(parsed, self.request)
        self.assertEqual(validated, self.request)
        self.assertTrue(validated.implementation_planning_requested)
        self.assertFalse(validated.implementation_plan_created)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)

    def test_programmatic_dict_and_json_forms_are_equivalent(self):
        from_dict = future_remediation_implementation_plan_request_from_dict(
            self.request.as_dict()
        )
        from_json = future_remediation_implementation_plan_request_from_json(
            self.request.to_json()
        )

        self.assertEqual(from_dict, from_json)
        self.assertEqual(from_dict, self.request)

    def test_digest_and_authority_tampering_fail_closed(self):
        digest_tampered = self.request.as_dict()
        digest_tampered["implementation_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_request_from_dict(
                digest_tampered
            )

        created = self.request.as_dict()
        created["implementation_plan_created"] = True
        with self.assertRaisesRegex(ValueError, "implementation_plan_created"):
            future_remediation_implementation_plan_request_from_dict(created)

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
                widened = self.request.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_request_from_dict(
                        widened
                    )

    def test_schema_and_primitive_drift_fail_closed(self):
        extra = self.request.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_request_from_dict(extra)

        bool_count = self.request.as_dict()
        bool_count["item_count"] = True
        with self.assertRaisesRegex(ValueError, "positive integer"):
            future_remediation_implementation_plan_request_from_dict(bool_count)

        empty_model = self.request.as_dict()
        empty_model["reviewer_model_id"] = " "
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            future_remediation_implementation_plan_request_from_dict(empty_model)

    def test_duplicate_json_keys_are_rejected(self):
        raw = self.request.to_json()
        duplicate = (
            raw[:-1]
            + ',"implementation_request_sha256":"'
            + ("0" * 64)
            + '"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_request_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_request(self):
        evidence_id = self.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()


if __name__ == "__main__":
    unittest.main()
