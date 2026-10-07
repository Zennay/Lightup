from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

import test_future_remediation_implementation_plan_request_handoff as handoff_tests
import lightup.future_remediation_implementation_plan_request_handoff as handoff_module


class _PersistedImplementationPlanningRequestText(str):
    pass


class _PersistedImplementationPlanningRequestDict(dict):
    pass


class ImplementationPlanningRequestConsumerPersistedTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanRequestHandoffTest(
            "test_round_trip_requires_exact_live_accepted_review"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_exact_builtin_persisted_forms_remain_supported(self):
        from_json = self.base._load(self.base.request.to_json())
        from_dict = self.base._load(self.base.request.as_dict())

        self.assertEqual(from_json, self.base.request)
        self.assertEqual(from_dict, self.base.request)
        self.assertTrue(from_json.implementation_planning_requested)\n        self.assertFalse(from_json.implementation_plan_created)
        self.assertFalse(from_json.execution_allowed)
        self.assertFalse(from_json.target_interaction_allowed)
        self.assertFalse(from_json.future_state_retest_allowed)
        self.assertFalse(from_json.deployment_authorized)
        self.assertFalse(from_json.attack_path_mutation_allowed)

    def test_json_text_subclass_is_rejected_before_parser_dispatch(self):
        persisted = _PersistedImplementationPlanningRequestText(self.base.request.to_json())
        before = str(persisted)

        with patch.object(
            handoff_module,
            "future_remediation_implementation_plan_request_from_json",
            side_effect=AssertionError("JSON parser must not see a str subclass"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must use exact built-in JSON text or object types",
            ):
                self.base._load(persisted)

        self.assertEqual(str(persisted), before)
        self.assertIs(type(persisted), _PersistedImplementationPlanningRequestText)

    def test_dict_subclass_is_rejected_before_parser_dispatch(self):
        persisted = _PersistedImplementationPlanningRequestDict(self.base.request.as_dict())
        before = deepcopy(dict(persisted))
        key_order = tuple(persisted)

        with patch.object(
            handoff_module,
            "future_remediation_implementation_plan_request_from_dict",
            side_effect=AssertionError("dict parser must not see a dict subclass"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must use exact built-in JSON text or object types",
            ):
                self.base._load(persisted)

        self.assertEqual(dict(persisted), before)
        self.assertEqual(tuple(persisted), key_order)
        self.assertIs(type(persisted), _PersistedImplementationPlanningRequestDict)


if __name__ == "__main__":
    unittest.main()
