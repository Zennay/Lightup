from __future__ import annotations

import copy
import unittest

import test_future_remediation_implementation_plan_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_dict,
)


class FutureRemediationImplementationPlanRequestParserInputPurityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanRequestHandoffTest(
            "test_round_trip_requires_exact_live_accepted_review"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.canonical = self.base.request.as_dict()

    @staticmethod
    def _snapshot(payload: dict) -> dict:
        return copy.deepcopy(payload)

    def _assert_repeated_rejection_is_input_pure(
        self,
        payload: dict,
        message: str,
    ) -> None:
        snapshot = self._snapshot(payload)
        messages: list[str] = []

        for _ in range(2):
            with self.assertRaises(ValueError) as caught:
                future_remediation_implementation_plan_request_from_dict(payload)
            messages.append(str(caught.exception))
            self.assertEqual(payload, snapshot)

        self.assertEqual(messages[0], messages[1])
        self.assertIn(message, messages[0])

    def test_successful_parse_is_repeatable_and_preserves_caller_payload(self):
        payload = self._snapshot(self.canonical)
        snapshot = self._snapshot(payload)

        first = future_remediation_implementation_plan_request_from_dict(payload)
        second = future_remediation_implementation_plan_request_from_dict(payload)

        self.assertEqual(first, self.base.request)
        self.assertEqual(second, self.base.request)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)

        self.assertTrue(first.implementation_planning_requested)
        self.assertFalse(first.implementation_plan_created)
        self.assertFalse(first.code_change_authorized)
        self.assertFalse(first.tool_call_created)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.target_interaction_allowed)
        self.assertFalse(first.future_state_retest_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_schema_and_digest_rejection_are_repeatable_and_input_pure(self):
        schema_invalid = self._snapshot(self.canonical)
        schema_invalid["unexpected"] = "caller-owned"
        self._assert_repeated_rejection_is_input_pure(
            schema_invalid,
            "schema mismatch",
        )

        digest_invalid = self._snapshot(self.canonical)
        digest_invalid["implementation_request_sha256"] = "0" * 64
        self._assert_repeated_rejection_is_input_pure(
            digest_invalid,
            "digest mismatch",
        )


if __name__ == "__main__":
    unittest.main()
