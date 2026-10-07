from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

import test_future_remediation_implementation_plan_handoff as handoff_tests
import lightup.future_remediation_implementation_plan_handoff as handoff_module


class _PersistedImplementationPlanText(str):
    pass


class _PersistedImplementationPlanDict(dict):
    pass


class ImplementationPlanConsumerPersistedTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_exact_builtin_persisted_forms_remain_supported(self):
        from_json = self.base._load(self.base.plan.to_json())
        from_dict = self.base._load(self.base.plan.as_dict())

        self.assertEqual(from_json, self.base.plan)
        self.assertEqual(from_dict, self.base.plan)
        self.assertTrue(from_json.implementation_plan_created)
        self.assertFalse(from_json.execution_allowed)
        self.assertFalse(from_json.target_interaction_allowed)
        self.assertFalse(from_json.future_state_retest_allowed)
        self.assertFalse(from_json.deployment_authorized)
        self.assertFalse(from_json.attack_path_mutation_allowed)

    def test_json_text_subclass_is_rejected_before_parser_dispatch(self):
        persisted = _PersistedImplementationPlanText(self.base.plan.to_json())
        before = str(persisted)

        with patch.object(
            handoff_module,
            "future_remediation_implementation_plan_from_json",
            side_effect=AssertionError("JSON parser must not see a str subclass"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must use exact built-in JSON text or object types",
            ):
                self.base._load(persisted)

        self.assertEqual(str(persisted), before)
        self.assertIs(type(persisted), _PersistedImplementationPlanText)

    def test_dict_subclass_is_rejected_before_parser_dispatch(self):
        persisted = _PersistedImplementationPlanDict(self.base.plan.as_dict())
        before = deepcopy(dict(persisted))
        key_order = tuple(persisted)

        with patch.object(
            handoff_module,
            "future_remediation_implementation_plan_from_dict",
            side_effect=AssertionError("dict parser must not see a dict subclass"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must use exact built-in JSON text or object types",
            ):
                self.base._load(persisted)

        self.assertEqual(dict(persisted), before)
        self.assertEqual(tuple(persisted), key_order)
        self.assertIs(type(persisted), _PersistedImplementationPlanDict)


if __name__ == "__main__":
    unittest.main()
