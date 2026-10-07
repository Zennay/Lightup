from __future__ import annotations

import copy
import unittest

import test_future_remediation_implementation_plan_request as request_tests
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_dict,
)


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanRequestSchemaKeyTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanRequestTest(
            "test_approved_review_requests_planning_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base._build()

    def test_real_producer_payload_uses_exact_builtin_schema_keys(self):
        payload = self.request.as_dict()

        parsed = future_remediation_implementation_plan_request_from_dict(payload)

        self.assertEqual(parsed, self.request)
        self.assertTrue(payload)
        self.assertTrue(all(type(key) is str for key in payload))

    def test_each_schema_key_subclass_is_rejected_without_input_mutation(self):
        canonical = self.request.as_dict()

        for key in tuple(canonical):
            with self.subTest(key=key):
                payload = copy.deepcopy(canonical)
                value = payload.pop(key)
                polymorphic_key = _StringSubclass(key)
                payload[polymorphic_key] = value
                before = copy.deepcopy(payload)

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_request_from_dict(payload)

                self.assertEqual(payload, before)
                stored_key = next(candidate for candidate in payload if candidate == key)
                self.assertIs(type(stored_key), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
