from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


class _BlankButTruthyAfterStrip(str):
    def strip(self, *args, **kwargs):
        return "canonical-looking-provenance"


def _payload_with_spoofed_provenance(field: str) -> dict:
    request = handoff_tests._request()
    payload = request.as_dict()
    payload[field] = _BlankButTruthyAfterStrip(" ")

    digest_kwargs = {
        "review_sha256": payload["review_sha256"],
        "review_request_sha256": payload["review_request_sha256"],
        "plan_sha256": payload["plan_sha256"],
        "implementation_request_sha256": payload["implementation_request_sha256"],
        "reviewer_provider_id": str(payload["reviewer_provider_id"]),
        "reviewer_model_id": str(payload["reviewer_model_id"]),
        "required_revisions": tuple(payload["required_revisions"]),
    }
    payload["revision_request_sha256"] = handoff_tests._request_digest(
        **digest_kwargs
    )
    return payload


class FutureRemediationImplementationPlanRevisionRequestProvenanceStringTest(
    unittest.TestCase
):
    def test_exact_builtin_string_control_remains_accepted(self):
        request = handoff_tests._request()
        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            request.as_dict()
        )

        self.assertEqual(parsed, request)
        self.assertIs(type(parsed.reviewer_provider_id), str)
        self.assertIs(type(parsed.reviewer_model_id), str)
        self.assertFalse(parsed.code_change_authorized)
        self.assertFalse(parsed.tool_call_created)
        self.assertFalse(parsed.execution_allowed)
        self.assertFalse(parsed.target_interaction_allowed)
        self.assertFalse(parsed.future_state_retest_allowed)
        self.assertFalse(parsed.deployment_authorized)
        self.assertFalse(parsed.attack_path_mutation_allowed)

    def test_reviewer_model_string_subclass_cannot_hide_blank_storage(self):
        payload = _payload_with_spoofed_provenance("reviewer_model_id")

        self.assertEqual(str(payload["reviewer_model_id"]), " ")
        self.assertTrue(payload["reviewer_model_id"].strip())

        with self.assertRaisesRegex(ValueError, "exact built-in string"):
            future_remediation_implementation_plan_revision_request_from_dict(
                payload
            )

    def test_reviewer_provider_string_subclass_cannot_hide_blank_storage(self):
        payload = _payload_with_spoofed_provenance("reviewer_provider_id")

        self.assertEqual(str(payload["reviewer_provider_id"]), " ")
        self.assertTrue(payload["reviewer_provider_id"].strip())

        with self.assertRaisesRegex(ValueError, "exact built-in string"):
            future_remediation_implementation_plan_revision_request_from_dict(
                payload
            )


if __name__ == "__main__":
    unittest.main()
