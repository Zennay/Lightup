from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan as plan_tests


class FutureRemediationImplementationPlannerOutputJsonIntegrityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_canonical_model_output_still_generates_bounded_plan(self):
        gateway, _ = self.base._gateway()
        plan = self.base._generate(gateway)

        self.assertTrue(plan.implementation_plan_created)
        self.assertFalse(plan.code_change_authorized)
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.target_interaction_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertEqual(plan.security_verdict, "not_evaluated")

    def test_duplicate_top_level_model_output_keys_fail_closed(self):
        raw = plan_tests._plan_json()
        duplicate = raw[:-1] + ',"summary":"forged summary"}'
        gateway, provider = self.base._gateway(duplicate)

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.base._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_duplicate_nested_plan_item_keys_fail_closed(self):
        raw = plan_tests._plan_json()
        for field, value in (
            ("plan_item_id", "forged-id"),
            ("change_area", "unknown"),
            ("intent", "forged intent"),
            ("verification_intent", "forged verification"),
            ("rollback_intent", "forged rollback"),
        ):
            with self.subTest(field=field):
                duplicate = raw.replace(
                    '"plan_items":[{',
                    '"plan_items":[{"'
                    + field
                    + '":"'
                    + value
                    + '",',
                    1,
                )
                gateway, provider = self.base._gateway(duplicate)

                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    self.base._generate(gateway)

                self.assertEqual(len(provider.requests), 1)


if __name__ == "__main__":
    unittest.main()
