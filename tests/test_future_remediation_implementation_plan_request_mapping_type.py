from __future__ import annotations

import copy
import unittest

import test_future_remediation_implementation_plan_request as request_tests
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_dict,
)


class _DictSubclass(dict):
    pass


class FutureRemediationImplementationPlanRequestMappingTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanRequestTest(
            "test_approved_review_requests_planning_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base._build()

    def test_real_producer_payload_uses_exact_builtin_mapping_and_remains_valid(self):
        payload = self.request.as_dict()

        parsed = future_remediation_implementation_plan_request_from_dict(payload)

        self.assertEqual(parsed, self.request)
        self.assertIs(type(payload), dict)

    def test_mapping_subclass_is_rejected_without_input_mutation(self):
        adversarial = _DictSubclass(self.request.as_dict())
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_request_from_dict(adversarial)

        self.assertEqual(adversarial, before)
        self.assertIs(type(adversarial), _DictSubclass)


if __name__ == "__main__":
    unittest.main()
