from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


class _SchemaKeyString(str):
    pass


class FutureRemediationImplementationPlanRevisionRequestSchemaKeyTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = handoff_tests._request()

    def test_canonical_payload_uses_exact_builtin_string_keys(self):
        payload = self.request.as_dict()

        self.assertIs(type(payload), dict)
        self.assertTrue(all(type(key) is str for key in payload))

        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            payload
        )
        self.assertEqual(parsed, self.request)

    def test_string_subclass_schema_key_fails_closed(self):
        payload = self.request.as_dict()
        value = payload.pop("schema_version")
        subclass_key = _SchemaKeyString("schema_version")
        payload[subclass_key] = value

        self.assertIs(type(payload), dict)
        self.assertIs(type(subclass_key), _SchemaKeyString)
        self.assertIn("schema_version", payload)
        self.assertEqual(payload["schema_version"], value)

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_revision_request_from_dict(
                payload
            )

        self.assertIn(subclass_key, payload)
        self.assertIs(
            next(key for key in payload if key == "schema_version"),
            subclass_key,
        )


if __name__ == "__main__":
    unittest.main()
