from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
)


class _ListSubclass(list):
    pass


class _TupleSubclass(tuple):
    pass


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanReviewRequestSchemaRubricTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def _direct(self) -> dict:
        return self.request.as_dict()

    def _decoded(self) -> dict:
        return json.loads(self.request.to_json())

    def _assert_rejected_unchanged(self, payload: dict) -> None:
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_direct_and_json_rubric_forms_remain_valid(self):
        direct = self._direct()
        decoded = self._decoded()

        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_dict(direct),
            self.request,
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_dict(decoded),
            self.request,
        )
        self.assertIs(type(direct["required_checks"]), tuple)
        self.assertIs(type(decoded["required_checks"]), list)
        self.assertTrue(all(type(key) is str for key in direct))
        self.assertTrue(all(type(item) is str for item in direct["required_checks"]))

    def test_each_top_level_schema_key_subclass_is_rejected(self):
        canonical = self._direct()
        for key in tuple(canonical):
            with self.subTest(key=key):
                payload = copy.deepcopy(canonical)
                value = payload.pop(key)
                payload[_StringSubclass(key)] = value
                self._assert_rejected_unchanged(payload)
                stored = next(candidate for candidate in payload if candidate == key)
                self.assertIs(type(stored), _StringSubclass)

    def test_required_checks_container_subclasses_are_rejected(self):
        direct = self._direct()
        direct["required_checks"] = _TupleSubclass(direct["required_checks"])
        self._assert_rejected_unchanged(direct)
        self.assertIs(type(direct["required_checks"]), _TupleSubclass)

        decoded = self._decoded()
        decoded["required_checks"] = _ListSubclass(decoded["required_checks"])
        self._assert_rejected_unchanged(decoded)
        self.assertIs(type(decoded["required_checks"]), _ListSubclass)

    def test_each_required_check_string_subclass_is_rejected(self):
        canonical = self._direct()
        for index, check in enumerate(canonical["required_checks"]):
            with self.subTest(index=index, check=check):
                payload = copy.deepcopy(canonical)
                checks = list(payload["required_checks"])
                checks[index] = _StringSubclass(checks[index])
                payload["required_checks"] = tuple(checks)

                self._assert_rejected_unchanged(payload)
                self.assertIs(
                    type(payload["required_checks"][index]),
                    _StringSubclass,
                )


if __name__ == "__main__":
    unittest.main()
