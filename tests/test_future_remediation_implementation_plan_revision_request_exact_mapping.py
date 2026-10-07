from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


class _SpoofedRevisionRequestMapping(dict):
    def __init__(self, *args, reviewer_model_id: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._reviewer_model_id = reviewer_model_id

    def __getitem__(self, key):
        if key == "reviewer_model_id":
            return self._reviewer_model_id
        return super().__getitem__(key)


class FutureRemediationImplementationPlanRevisionRequestExactMappingTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = handoff_tests._request()

    def test_exact_builtin_dict_control_remains_accepted(self):
        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            self.request.as_dict()
        )

        self.assertEqual(parsed, self.request)
        self.assertTrue(parsed.implementation_plan_revision_requested)
        self.assertFalse(parsed.revised_implementation_plan_created)
        self.assertFalse(parsed.implementation_plan_accepted)
        self.assertFalse(parsed.code_change_authorized)
        self.assertFalse(parsed.tool_call_created)
        self.assertFalse(parsed.execution_allowed)
        self.assertFalse(parsed.target_interaction_allowed)
        self.assertFalse(parsed.future_state_retest_allowed)
        self.assertFalse(parsed.deployment_authorized)
        self.assertFalse(parsed.attack_path_mutation_allowed)

    def test_dict_subclass_cannot_substitute_persisted_reviewer_provenance(self):
        stored = self.request.as_dict()
        canonical_model_id = stored["reviewer_model_id"]
        stored["reviewer_model_id"] = " "

        payload = _SpoofedRevisionRequestMapping(
            stored,
            reviewer_model_id=canonical_model_id,
        )

        self.assertEqual(dict(payload)["reviewer_model_id"], " ")
        self.assertEqual(payload["reviewer_model_id"], canonical_model_id)

        with self.assertRaisesRegex(ValueError, "exact built-in dict"):
            future_remediation_implementation_plan_revision_request_from_dict(
                payload
            )


if __name__ == "__main__":
    unittest.main()
