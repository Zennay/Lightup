from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_proposal_handoff import (
    future_remediation_implementation_plan_revision_proposal_from_dict,
    future_remediation_implementation_plan_revision_proposal_from_json,
)


class FutureRemediationImplementationPlanRevisionProposalSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanRevisionProposalHandoffTest(
                "test_json_and_dict_round_trip_require_live_revision_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.revised_plan = self.base.revised_plan

    def test_serialization_is_deterministic_and_nested_snapshots_are_detached(self):
        before_json = self.revised_plan.to_json()
        first = self.revised_plan.as_dict()
        second = self.revised_plan.as_dict()

        self.assertEqual(self.revised_plan.to_json(), before_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["plan_items"][0], second["plan_items"][0])

        first["summary"] = "caller-mutated-summary"
        first["plan_items"][0]["intent"] = "caller-mutated-intent"
        first["implementation_plan_accepted"] = True

        self.assertEqual(self.revised_plan.to_json(), before_json)
        self.assertNotEqual(first, second)
        self.assertFalse(self.revised_plan.implementation_plan_accepted)

    def test_canonical_untouched_snapshots_round_trip_exactly(self):
        from_dict = future_remediation_implementation_plan_revision_proposal_from_dict(
            self.revised_plan.as_dict()
        )
        from_json = future_remediation_implementation_plan_revision_proposal_from_json(
            self.revised_plan.to_json()
        )

        self.assertEqual(from_dict, self.revised_plan)
        self.assertEqual(from_json, self.revised_plan)
        self.assertEqual(from_dict.to_json(), self.revised_plan.to_json())
        self.assertEqual(from_json.to_json(), self.revised_plan.to_json())

    def test_forged_snapshots_fail_closed_without_mutating_source(self):
        before_json = self.revised_plan.to_json()
        cases = []

        accepted = self.revised_plan.as_dict()
        accepted["implementation_plan_accepted"] = True
        cases.append((accepted, "implementation_plan_accepted"))

        widened = self.revised_plan.as_dict()
        widened["execution_allowed"] = True
        cases.append((widened, "authority flag"))

        resolved = self.revised_plan.as_dict()
        resolved["future_semantics"] = "resolved"
        cases.append((resolved, "future_semantics"))

        verdict = self.revised_plan.as_dict()
        verdict["security_verdict"] = "secure"
        cases.append((verdict, "security_verdict"))

        for forged, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_implementation_plan_revision_proposal_from_dict(
                        forged
                    )
                self.assertEqual(self.revised_plan.to_json(), before_json)

    def test_post_parse_nested_caller_mutation_cannot_change_parsed_plan(self):
        payload = self.revised_plan.as_dict()
        parsed = future_remediation_implementation_plan_revision_proposal_from_dict(
            payload
        )
        parsed_json = parsed.to_json()

        payload["summary"] = "caller-mutated-summary"
        payload["plan_items"][0]["intent"] = "caller-mutated-intent"
        payload["assumptions"] = ("caller-mutated-assumption",)
        payload["execution_allowed"] = True

        self.assertEqual(parsed, self.revised_plan)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed.to_json(), self.revised_plan.to_json())
        self.assertFalse(parsed.execution_allowed)


if __name__ == "__main__":
    unittest.main()
