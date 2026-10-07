from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
)
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


class _EqualitySpoofString(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class FutureRemediationImplementationPlanRevisionRequestPersistedMetadataTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = handoff_tests._request()

    def test_canonical_fixed_metadata_are_exact_builtin_strings(self):
        payload = self.request.as_dict()

        self.assertIs(type(payload["schema_version"]), str)
        self.assertIs(type(payload["source_review_decision"]), str)
        self.assertIs(type(payload["future_semantics"]), str)
        self.assertIs(type(payload["security_verdict"]), str)

        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            payload
        )
        self.assertEqual(parsed, self.request)

    def test_fixed_metadata_string_subclasses_fail_closed_before_equality(self):
        cases = {
            "schema_version": "not-the-schema",
            "source_review_decision": "not-the-decision",
            "future_semantics": "not-the-future-state",
            "security_verdict": "not-the-verdict",
        }

        for field, stored_text in cases.items():
            with self.subTest(field=field):
                payload = self.request.as_dict()
                spoofed = _EqualitySpoofString(stored_text)
                payload[field] = spoofed

                self.assertIs(type(spoofed), _EqualitySpoofString)
                self.assertEqual(str(spoofed), stored_text)

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_revision_request_from_dict(
                        payload
                    )

                self.assertIs(payload[field], spoofed)
                self.assertEqual(str(payload[field]), stored_text)


if __name__ == "__main__":
    unittest.main()
