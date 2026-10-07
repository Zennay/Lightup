from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_revision_proposal as revision_tests


class FutureRemediationImplementationPlanRevisionDirectAuthorityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = revision_tests.FutureRemediationImplementationPlanRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_revised_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.revised_plan = self.base._generate(gateway)

    def test_canonical_revised_plan_retains_planning_only_stop_line(self):
        plan = self.revised_plan

        self.assertTrue(plan.revised_implementation_plan_created)
        self.assertFalse(plan.implementation_plan_accepted)
        self.assertFalse(plan.code_change_authorized)
        self.assertFalse(plan.tool_call_created)
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.target_interaction_allowed)
        self.assertFalse(plan.future_state_retest_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertEqual(plan.security_verdict, "not_evaluated")

    def test_direct_construction_cannot_claim_acceptance_or_execution(self):
        with self.assertRaises(ValueError):
            replace(
                self.revised_plan,
                implementation_plan_accepted=True,
                execution_allowed=True,
            )

    def test_direct_construction_cannot_resolve_future_state_or_verdict(self):
        with self.assertRaises(ValueError):
            replace(
                self.revised_plan,
                future_semantics="resolved",
                security_verdict="secure",
            )


if __name__ == "__main__":
    unittest.main()
