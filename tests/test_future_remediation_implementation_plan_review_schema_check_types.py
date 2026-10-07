from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_dict,
)


class _ListSubclass(list):
    pass


class _TupleSubclass(tuple):
    pass


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanReviewSchemaCheckTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def _direct(self) -> dict:
        return self.review.as_dict()

    def _decoded(self) -> dict:
        return json.loads(self.review.to_json())

    def _assert_rejected_unchanged(self, payload: dict) -> None:
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_direct_and_json_check_shapes_remain_valid(self):
        direct = self._direct()
        decoded = self._decoded()

        self.assertEqual(
            future_remediation_implementation_plan_review_from_dict(direct),
            self.review,
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_from_dict(decoded),
            self.review,
        )
        self.assertIs(type(direct["checks"]), tuple)
        self.assertIs(type(decoded["checks"]), list)
        self.assertTrue(all(type(key) is str for key in direct))
        self.assertTrue(
            all(type(key) is str for check in direct["checks"] for key in check)
        )

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

    def test_checks_container_subclasses_are_rejected(self):
        direct = self._direct()
        direct["checks"] = _TupleSubclass(direct["checks"])
        self._assert_rejected_unchanged(direct)
        self.assertIs(type(direct["checks"]), _TupleSubclass)

        decoded = self._decoded()
        decoded["checks"] = _ListSubclass(decoded["checks"])
        self._assert_rejected_unchanged(decoded)
        self.assertIs(type(decoded["checks"]), _ListSubclass)

    def test_each_nested_check_schema_key_subclass_is_rejected(self):
        canonical = self._direct()
        for check_index, check in enumerate(canonical["checks"]):
            for key in tuple(check):
                with self.subTest(check_index=check_index, key=key):
                    payload = copy.deepcopy(canonical)
                    rewritten = dict(payload["checks"][check_index])
                    value = rewritten.pop(key)
                    rewritten[_StringSubclass(key)] = value
                    checks = list(payload["checks"])
                    checks[check_index] = rewritten
                    payload["checks"] = tuple(checks)

                    self._assert_rejected_unchanged(payload)
                    stored = next(
                        candidate for candidate in rewritten if candidate == key
                    )
                    self.assertIs(type(stored), _StringSubclass)

    def test_decision_string_subclass_is_rejected(self):
        payload = self._direct()
        payload["decision"] = _StringSubclass(payload["decision"])

        self._assert_rejected_unchanged(payload)
        self.assertIs(type(payload["decision"]), _StringSubclass)

    def test_each_check_name_and_result_subclass_is_rejected(self):
        canonical = self._direct()
        for check_index in range(len(canonical["checks"])):
            for field in ("check", "result"):
                with self.subTest(check_index=check_index, field=field):
                    payload = copy.deepcopy(canonical)
                    rewritten = dict(payload["checks"][check_index])
                    rewritten[field] = _StringSubclass(rewritten[field])
                    checks = list(payload["checks"])
                    checks[check_index] = rewritten
                    payload["checks"] = tuple(checks)

                    self._assert_rejected_unchanged(payload)
                    self.assertIs(type(rewritten[field]), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
