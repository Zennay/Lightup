from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_json,
)


class FutureRemediationImplementationPlanNestedJsonIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.plan = self.base.plan

    def test_canonical_json_still_round_trips(self):
        self.assertEqual(
            future_remediation_implementation_plan_from_json(
                self.plan.to_json()
            ),
            self.plan,
        )

    def test_nested_plan_item_duplicate_keys_fail_closed(self):
        raw = self.plan.to_json()
        for field, value in (
            ("intent", "forged intent"),
            ("change_area", "unknown"),
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
                self.assertNotEqual(duplicate, raw)
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    future_remediation_implementation_plan_from_json(duplicate)

    def test_nested_duplicate_primary_item_id_fails_before_identity_checks(self):
        raw = self.plan.to_json()
        duplicate = raw.replace(
            '"plan_items":[{',
            '"plan_items":[{"plan_item_id":"forged-id",',
            1,
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_from_json(duplicate)


if __name__ == "__main__":
    unittest.main()
