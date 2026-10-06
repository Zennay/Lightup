from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_implementation_plan_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_dict,
)


class FutureRemediationImplementationPlanParserInputPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.plan = self.base.plan

    @staticmethod
    def _container_identities(value, path="root"):
        identities = {}
        if isinstance(value, dict):
            identities[path] = id(value)
            for key, item in value.items():
                identities.update(
                    FutureRemediationImplementationPlanParserInputPurityTest
                    ._container_identities(item, f"{path}[{key!r}]")
                )
        elif isinstance(value, list):
            identities[path] = id(value)
            for index, item in enumerate(value):
                identities.update(
                    FutureRemediationImplementationPlanParserInputPurityTest
                    ._container_identities(item, f"{path}[{index}]")
                )
        return identities

    @staticmethod
    def _ordered_json(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)

    def _assert_payload_unchanged(
        self,
        payload,
        before_value,
        before_json,
        before_ids,
    ):
        self.assertEqual(payload, before_value)
        self.assertEqual(self._ordered_json(payload), before_json)
        self.assertEqual(self._container_identities(payload), before_ids)

    def test_successful_parse_preserves_caller_payload_and_nested_identities(self):
        payload = json.loads(self.plan.to_json())
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        first = future_remediation_implementation_plan_from_dict(payload)
        second = future_remediation_implementation_plan_from_dict(payload)

        self.assertEqual(first, self.plan)
        self.assertEqual(second, self.plan)
        self.assertEqual(first, second)
        self._assert_payload_unchanged(
            payload,
            before_value,
            before_json,
            before_ids,
        )

        self.assertTrue(first.implementation_plan_created)
        self.assertFalse(first.code_change_authorized)
        self.assertFalse(first.tool_call_created)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.target_interaction_allowed)
        self.assertFalse(first.future_state_retest_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_schema_rejection_preserves_caller_payload_and_nested_identities(self):
        payload = json.loads(self.plan.to_json())
        payload["unexpected"] = {"nested": ["caller-owned", {"value": "keep"}]}
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        messages = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "schema mismatch") as raised:
                future_remediation_implementation_plan_from_dict(payload)
            messages.append(str(raised.exception))

        self.assertEqual(messages[0], messages[1])
        self._assert_payload_unchanged(
            payload,
            before_value,
            before_json,
            before_ids,
        )

    def test_deep_digest_rejection_preserves_caller_payload_and_nested_identities(self):
        payload = json.loads(self.plan.to_json())
        payload["plan_items"][0]["intent"] += " caller-controlled drift"
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        messages = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "digest mismatch") as raised:
                future_remediation_implementation_plan_from_dict(payload)
            messages.append(str(raised.exception))

        self.assertEqual(messages[0], messages[1])
        self._assert_payload_unchanged(
            payload,
            before_value,
            before_json,
            before_ids,
        )


if __name__ == "__main__":
    unittest.main()
