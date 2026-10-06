from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_dict,
    future_remediation_implementation_plan_review_from_json,
    load_and_validate_future_remediation_implementation_plan_review,
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


class FutureRemediationImplementationPlanReviewHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def _load(self, persisted=None, persisted_plan=None):
        return load_and_validate_future_remediation_implementation_plan_review(
            self.review.to_json() if persisted is None else persisted,
            self.base.review_request.to_json(),
            self.base.implementation_plan.to_json()
            if persisted_plan is None
            else persisted_plan,
            self.base.base.base.base.base.planning_request.to_json(),
            self.base.base.base.base.base.base.review.to_json(),
            self.base.base.base.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.base.base.base.request,
            self.base.base.base.base.base.base.base.base.bundle,
            self.base.base.base.base.base.base.base.base.plan,
            self.base.base.base.base.base.base.base.base.report,
            self.base.base.base.base.base.base.base.base.preview,
            self.base.base.base.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.base.base.base.context,),
            self.base.base.base.base.base.base.base.base.state,
        )

    def test_approved_review_round_trips_without_action_authority(self):
        from_json = future_remediation_implementation_plan_review_from_json(
            self.review.to_json()
        )
        from_dict = future_remediation_implementation_plan_review_from_dict(
            self.review.as_dict()
        )
        validated = self._load()

        self.assertEqual(from_json, self.review)
        self.assertEqual(from_dict, self.review)
        self.assertEqual(validated, self.review)
        self.assertTrue(validated.implementation_plan_review_completed)
        self.assertTrue(validated.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(validated, field))
        self.assertEqual(validated.future_semantics, "unresolved")
        self.assertEqual(validated.security_verdict, "not_evaluated")

    def test_schema_digest_summary_and_authority_tampering_fail_closed(self):
        extra = self.review.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(extra)

        missing = self.review.as_dict()
        missing.pop("plan_sha256")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(missing)

        digest = self.review.as_dict()
        digest["review_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_review_from_dict(digest)

        summary = self.review.as_dict()
        summary["summary"] += " changed"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_review_from_dict(summary)

        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                widened = self.review.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_review_from_dict(
                        widened
                    )

    def test_decision_check_acceptance_and_lifecycle_coherence_revalidated(self):
        bad_check = self.review.as_dict()
        bad_check["checks"][0]["result"] = "fail"
        with self.assertRaisesRegex(ValueError, "every check to pass"):
            future_remediation_implementation_plan_review_from_dict(bad_check)

        bad_acceptance = self.review.as_dict()
        bad_acceptance["implementation_plan_accepted"] = False
        with self.assertRaisesRegex(ValueError, "accepted mismatch"):
            future_remediation_implementation_plan_review_from_dict(
                bad_acceptance
            )

        incomplete = self.review.as_dict()
        incomplete["implementation_plan_review_completed"] = False
        with self.assertRaisesRegex(ValueError, "review_completed"):
            future_remediation_implementation_plan_review_from_dict(incomplete)

        bad_future = self.review.as_dict()
        bad_future["future_semantics"] = "resolved"
        with self.assertRaisesRegex(ValueError, "future_semantics"):
            future_remediation_implementation_plan_review_from_dict(bad_future)

        bad_verdict = self.review.as_dict()
        bad_verdict["security_verdict"] = "pass"
        with self.assertRaisesRegex(ValueError, "security_verdict"):
            future_remediation_implementation_plan_review_from_dict(bad_verdict)

    def test_nested_check_schema_order_and_duplicate_keys_fail_closed(self):
        unknown = self.review.as_dict()
        unknown["checks"][0]["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_implementation_plan_review_from_dict(unknown)

        reordered = self.review.as_dict()
        reordered["checks"][0], reordered["checks"][1] = (
            reordered["checks"][1],
            reordered["checks"][0],
        )
        with self.assertRaisesRegex(ValueError, "order or name mismatch"):
            future_remediation_implementation_plan_review_from_dict(reordered)

        raw = self.review.to_json()
        duplicate = raw.replace(
            '"checks":[{',
            '"checks":[{"result":"fail",',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_review_from_json(duplicate)

    def test_duplicate_top_level_json_keys_are_rejected_before_decode(self):
        raw = self.review.to_json()
        duplicate = (
            raw[:-1]
            + ',"review_sha256":"'
            + self.review.review_sha256
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_review_from_json(duplicate)

    def test_structural_parser_does_not_replace_live_evidence_validation(self):
        self.assertEqual(
            future_remediation_implementation_plan_review_from_json(
                self.review.to_json()
            ),
            self.review,
        )

        evidence = (
            self.base.base.base.base.base.base.base.base.bundle.items[0].evidence[0]
        )
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        self.assertEqual(
            future_remediation_implementation_plan_review_from_json(
                self.review.to_json()
            ),
            self.review,
        )
        with self.assertRaises(ValueError):
            self._load()

    def test_plan_tampering_invalidates_persisted_review_reuse(self):
        plan_payload = self.base.implementation_plan.as_dict()
        plan_payload["summary"] += " tampered"

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._load(persisted_plan=plan_payload)

    def test_revision_and_insufficient_evidence_reviews_round_trip_unaccepted(self):
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
                validated = load_and_validate_future_remediation_implementation_plan_review(
                    review.to_json(),
                    self.base.review_request.to_json(),
                    self.base.implementation_plan.to_json(),
                    self.base.base.base.base.base.planning_request.to_json(),
                    self.base.base.base.base.base.base.review.to_json(),
                    self.base.base.base.base.base.base.base.review_request.to_json(),
                    self.base.base.base.base.base.base.base.proposal.to_json(),
                    self.base.base.base.base.base.base.base.base.request,
                    self.base.base.base.base.base.base.base.base.bundle,
                    self.base.base.base.base.base.base.base.base.plan,
                    self.base.base.base.base.base.base.base.base.report,
                    self.base.base.base.base.base.base.base.base.preview,
                    self.base.base.base.base.base.base.base.base.transition_proposal,
                    (self.base.base.base.base.base.base.base.base.resolution,),
                    (self.base.base.base.base.base.base.base.base.context,),
                    self.base.base.base.base.base.base.base.base.state,
                )
                self.assertFalse(validated.implementation_plan_accepted)
                for field in _AUTHORITY_FLAGS:
                    self.assertFalse(getattr(validated, field))
                self.assertEqual(validated.security_verdict, "not_evaluated")

    def test_persisted_value_type_must_be_json_or_object(self):
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._load(persisted=42)


if __name__ == "__main__":
    unittest.main()
