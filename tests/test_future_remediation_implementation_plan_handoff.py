from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan as plan_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_dict,
    future_remediation_implementation_plan_from_json,
    load_and_validate_future_remediation_implementation_plan,
)


class FutureRemediationImplementationPlanHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.plan = self.base._generate(gateway)

    def _load(self, persisted=None):
        return load_and_validate_future_remediation_implementation_plan(
            self.plan.to_json() if persisted is None else persisted,
            self.base.planning_request.to_json(),
            self.base.base.review.to_json(),
            self.base.base.base.review_request.to_json(),
            self.base.base.base.proposal.to_json(),
            self.base.base.base.base.request,
            self.base.base.base.base.bundle,
            self.base.base.base.base.plan,
            self.base.base.base.base.report,
            self.base.base.base.base.preview,
            self.base.base.base.base.transition_proposal,
            (self.base.base.base.base.resolution,),
            (self.base.base.base.base.context,),
            self.base.base.base.base.state,
        )

    def test_round_trip_requires_exact_live_planning_lineage(self):
        parsed = future_remediation_implementation_plan_from_json(
            self.plan.to_json()
        )
        validated = self._load()

        self.assertEqual(parsed, self.plan)
        self.assertEqual(validated, self.plan)
        self.assertTrue(validated.implementation_plan_created)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)

    def test_programmatic_dict_and_json_forms_are_equivalent(self):
        from_dict = future_remediation_implementation_plan_from_dict(
            self.plan.as_dict()
        )
        from_json = future_remediation_implementation_plan_from_json(
            self.plan.to_json()
        )

        self.assertEqual(from_dict, from_json)
        self.assertEqual(from_dict, self.plan)

    def test_digest_summary_and_authority_tampering_fail_closed(self):
        digest_tampered = self.plan.as_dict()
        digest_tampered["plan_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_from_dict(digest_tampered)

        summary_tampered = self.plan.as_dict()
        summary_tampered["summary"] += " changed"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_from_dict(summary_tampered)

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
                widened = self.plan.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_from_dict(widened)

    def test_plan_item_schema_and_identity_drift_fail_closed(self):
        extra = self.plan.as_dict()
        extra["plan_items"][0]["command"] = "apply"
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_remediation_implementation_plan_from_dict(extra)

        duplicate = self.plan.as_dict()
        duplicate["plan_items"] = (
            duplicate["plan_items"][0],
            dict(duplicate["plan_items"][0]),
        )
        with self.assertRaisesRegex(ValueError, "IDs must be unique"):
            future_remediation_implementation_plan_from_dict(duplicate)

        invalid_area = self.plan.as_dict()
        invalid_area["plan_items"][0]["change_area"] = "target_exploitation"
        with self.assertRaisesRegex(ValueError, "change_area is invalid"):
            future_remediation_implementation_plan_from_dict(invalid_area)

    def test_duplicate_json_keys_are_rejected(self):
        raw = self.plan.to_json()
        duplicate = raw[:-1] + ',"plan_sha256":"' + ("0" * 64) + '"}'

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_plan(self):
        evidence_id = self.base.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()


if __name__ == "__main__":
    unittest.main()
