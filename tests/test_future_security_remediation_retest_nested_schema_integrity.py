from __future__ import annotations

import copy
import json
import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
    future_security_remediation_retest_plan_from_json,
)


class FutureSecurityRemediationRetestNestedSchemaIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self) -> tuple[object, dict]:
        plan = self.h._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="nested-schema-integrity",
        )
        return plan, json.loads(plan.to_json())

    def test_canonical_json_and_dict_still_round_trip(self):
        plan, payload = self._payload()

        self.assertEqual(
            future_security_remediation_retest_plan_from_dict(copy.deepcopy(payload)),
            plan,
        )
        self.assertEqual(
            future_security_remediation_retest_plan_from_json(plan.to_json()),
            plan,
        )

    def test_missing_or_unknown_nested_item_fields_fail_closed(self):
        _, payload = self._payload()

        missing = copy.deepcopy(payload)
        missing["items"][0].pop("resolution_id")
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_security_remediation_retest_plan_from_dict(missing)

        widened = copy.deepcopy(payload)
        widened["items"][0]["unexpected"] = "shadow"
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_security_remediation_retest_plan_from_dict(widened)

    def test_non_object_nested_item_fails_closed(self):
        _, payload = self._payload()

        substituted = copy.deepcopy(payload)
        substituted["items"][0] = ["not", "an", "object"]
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_security_remediation_retest_plan_from_dict(substituted)

    def test_nested_lineage_container_must_remain_a_list(self):
        _, payload = self._payload()

        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                eroded = copy.deepcopy(payload)
                eroded["items"][0][field] = {
                    value: True for value in eroded["items"][0][field]
                }
                with self.assertRaisesRegex(ValueError, "must be a string list"):
                    future_security_remediation_retest_plan_from_dict(eroded)


if __name__ == "__main__":
    unittest.main()
