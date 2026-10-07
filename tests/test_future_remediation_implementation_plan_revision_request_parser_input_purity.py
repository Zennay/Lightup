from __future__ import annotations

import copy
import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationImplementationPlanRevisionRequestParserInputPurityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanRevisionRequestHandoffTest(
                "test_programmatic_and_json_forms_round_trip_exactly"
            )
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
        required_revisions = payload["required_revisions"]
        messages: list[str] = []

        for _ in range(2):
            with self.assertRaises(ValueError) as caught:
                future_remediation_implementation_plan_revision_request_from_dict(
                    payload
                )
            messages.append(str(caught.exception))
            self.assertEqual(payload, snapshot)
            self.assertIs(payload["required_revisions"], required_revisions)

        self.assertEqual(messages[0], messages[1])
        self.assertIn(message, messages[0])

    def test_successful_parse_is_repeatable_and_preserves_nested_caller_input(self):
        payload = self._snapshot(self.canonical)
        snapshot = self._snapshot(payload)
        required_revisions = payload["required_revisions"]

        first = future_remediation_implementation_plan_revision_request_from_dict(
            payload
        )
        second = future_remediation_implementation_plan_revision_request_from_dict(
            payload
        )

        self.assertEqual(first, self.base.request)
        self.assertEqual(second, self.base.request)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)
        self.assertIs(payload["required_revisions"], required_revisions)

        self.assertTrue(first.implementation_plan_revision_requested)
        self.assertFalse(first.revised_implementation_plan_created)
        self.assertFalse(first.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(first, field))
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_schema_digest_and_nested_shape_rejection_are_input_pure(self):
        schema_invalid = self._snapshot(self.canonical)
        schema_invalid["unexpected"] = "caller-owned"
        self._assert_repeated_rejection_is_input_pure(
            schema_invalid,
            "schema mismatch",
        )

        digest_invalid = self._snapshot(self.canonical)
        digest_invalid["revision_request_sha256"] = "0" * 64
        self._assert_repeated_rejection_is_input_pure(
            digest_invalid,
            "digest mismatch",
        )

        revisions_invalid = self._snapshot(self.canonical)
        revisions_invalid["required_revisions"] = [
            handoff_tests.REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[1],
            handoff_tests.REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],
        ]
        self._assert_repeated_rejection_is_input_pure(
            revisions_invalid,
            "invalid or out of order",
        )


if __name__ == "__main__":
    unittest.main()
