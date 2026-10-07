from __future__ import annotations

import copy
import unittest

import test_future_remediation_implementation_plan_request as request_tests
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_dict,
)


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class FutureRemediationImplementationPlanRequestScalarTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanRequestTest(
            "test_approved_review_requests_planning_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base._build()

    def _payload(self) -> dict:
        return self.request.as_dict()

    def test_real_producer_payload_uses_exact_builtin_scalars_and_remains_valid(self):
        payload = self._payload()

        parsed = future_remediation_implementation_plan_request_from_dict(payload)

        self.assertEqual(parsed, self.request)
        for field in (
            "schema_version",
            "review_sha256",
            "reviewer_provider_id",
            "future_semantics",
            "security_verdict",
        ):
            self.assertIs(type(payload[field]), str)
        self.assertIs(type(payload["item_count"]), int)

    def test_string_subclasses_are_rejected_without_input_mutation(self):
        for field in (
            "schema_version",
            "review_sha256",
            "reviewer_provider_id",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                payload = self._payload()
                payload[field] = _StringSubclass(payload[field])
                before = copy.deepcopy(payload)

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_request_from_dict(payload)

                self.assertEqual(payload, before)
                self.assertIs(type(payload[field]), _StringSubclass)

    def test_item_count_integer_subclass_is_rejected_without_input_mutation(self):
        payload = self._payload()
        payload["item_count"] = _IntSubclass(payload["item_count"])
        before = copy.deepcopy(payload)

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_request_from_dict(payload)

        self.assertEqual(payload, before)
        self.assertIs(type(payload["item_count"]), _IntSubclass)


if __name__ == "__main__":
    unittest.main()
