from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
import lightup.future_remediation_implementation_plan_revision_request_handoff as handoff_module


class _PersistedRevisionRequestText(str):
    pass


class _PersistedRevisionRequestDict(dict):
    pass


class FutureRemediationImplementationPlanRevisionRequestConsumerPersistedTypeTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanRevisionRequestHandoffTest(
            "test_programmatic_and_json_forms_round_trip_exactly"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request
        self.args = [object() for _ in range(16)]

    def _load(self, persisted):
        with patch.object(
            handoff_module,
            "build_future_remediation_implementation_plan_revision_request",
            return_value=self.request,
        ):
            return handoff_module.load_and_validate_future_remediation_implementation_plan_revision_request(
                persisted,
                *self.args,
            )

    def test_exact_builtin_persisted_forms_remain_supported(self):
        from_json = self._load(self.request.to_json())
        from_dict = self._load(self.request.as_dict())

        self.assertEqual(from_json, self.request)
        self.assertEqual(from_dict, self.request)
        self.assertTrue(from_json.implementation_plan_revision_requested)
        self.assertFalse(from_json.revised_implementation_plan_created)
        self.assertFalse(from_json.implementation_plan_accepted)
        self.assertFalse(from_json.execution_allowed)
        self.assertFalse(from_json.target_interaction_allowed)
        self.assertFalse(from_json.future_state_retest_allowed)
        self.assertFalse(from_json.deployment_authorized)
        self.assertFalse(from_json.attack_path_mutation_allowed)

    def test_json_text_subclass_is_rejected_before_parser_dispatch(self):
        persisted = _PersistedRevisionRequestText(self.request.to_json())
        before = str(persisted)

        with patch.object(
            handoff_module,
            "future_remediation_implementation_plan_revision_request_from_json",
            side_effect=AssertionError("JSON parser must not see a str subclass"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must use exact built-in JSON text or object types",
            ):
                self._load(persisted)

        self.assertEqual(str(persisted), before)
        self.assertIs(type(persisted), _PersistedRevisionRequestText)

    def test_dict_subclass_is_rejected_before_parser_dispatch(self):
        persisted = _PersistedRevisionRequestDict(self.request.as_dict())
        before = deepcopy(dict(persisted))
        key_order = tuple(persisted)

        with patch.object(
            handoff_module,
            "future_remediation_implementation_plan_revision_request_from_dict",
            side_effect=AssertionError("dict parser must not see a dict subclass"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must use exact built-in JSON text or object types",
            ):
                self._load(persisted)

        self.assertEqual(dict(persisted), before)
        self.assertEqual(tuple(persisted), key_order)
        self.assertIs(type(persisted), _PersistedRevisionRequestDict)


if __name__ == "__main__":
    unittest.main()
