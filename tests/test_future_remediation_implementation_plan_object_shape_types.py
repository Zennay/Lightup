from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_implementation_plan as plan_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_dict,
)


class _DictSubclass(dict):
    pass


class _ListSubclass(list):
    pass


class _TupleSubclass(tuple):
    pass


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanObjectShapeTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.plan = self.base._generate(gateway)

    def _direct(self) -> dict:
        return self.plan.as_dict()

    def _json_object(self) -> dict:
        return json.loads(self.plan.to_json())

    def _assert_rejected_unchanged(self, payload: dict) -> None:
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_direct_and_json_decoded_shapes_remain_valid(self):
        direct = self._direct()
        decoded = self._json_object()

        self.assertEqual(
            future_remediation_implementation_plan_from_dict(direct),
            self.plan,
        )
        self.assertEqual(
            future_remediation_implementation_plan_from_dict(decoded),
            self.plan,
        )
        self.assertIs(type(direct), dict)
        self.assertIs(type(decoded), dict)
        self.assertIs(type(direct["plan_items"]), tuple)
        self.assertIs(type(decoded["plan_items"]), list)
        self.assertIs(type(direct["plan_items"][0]), dict)
        self.assertIs(type(decoded["plan_items"][0]), dict)

    def test_top_level_mapping_subclass_is_rejected(self):
        payload = _DictSubclass(self._direct())
        self._assert_rejected_unchanged(payload)
        self.assertIs(type(payload), _DictSubclass)

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

    def test_plan_items_sequence_subclasses_are_rejected(self):
        direct = self._direct()
        direct["plan_items"] = _TupleSubclass(direct["plan_items"])
        self._assert_rejected_unchanged(direct)
        self.assertIs(type(direct["plan_items"]), _TupleSubclass)

        decoded = self._json_object()
        decoded["plan_items"] = _ListSubclass(decoded["plan_items"])
        self._assert_rejected_unchanged(decoded)
        self.assertIs(type(decoded["plan_items"]), _ListSubclass)

    def test_nested_item_mapping_and_schema_key_subclasses_are_rejected(self):
        payload = self._direct()
        payload["plan_items"] = (
            _DictSubclass(payload["plan_items"][0]),
        )
        self._assert_rejected_unchanged(payload)
        self.assertIs(type(payload["plan_items"][0]), _DictSubclass)

        canonical = self._direct()
        item = canonical["plan_items"][0]
        for key in tuple(item):
            with self.subTest(key=key):
                payload = copy.deepcopy(canonical)
                rewritten = dict(payload["plan_items"][0])
                value = rewritten.pop(key)
                rewritten[_StringSubclass(key)] = value
                payload["plan_items"] = (rewritten,)
                self._assert_rejected_unchanged(payload)
                stored = next(candidate for candidate in rewritten if candidate == key)
                self.assertIs(type(stored), _StringSubclass)

    def test_auxiliary_sequence_subclasses_are_rejected(self):
        for field in ("assumptions", "unresolved_questions"):
            with self.subTest(field=field, container="tuple"):
                payload = self._direct()
                payload[field] = _TupleSubclass(payload[field])
                self._assert_rejected_unchanged(payload)
                self.assertIs(type(payload[field]), _TupleSubclass)

            with self.subTest(field=field, container="list"):
                payload = self._json_object()
                payload[field] = _ListSubclass(payload[field])
                self._assert_rejected_unchanged(payload)
                self.assertIs(type(payload[field]), _ListSubclass)

    def test_top_level_string_subclasses_are_rejected(self):
        fields = (
            "schema_version",
            "implementation_request_sha256",
            "review_sha256",
            "proposal_sha256",
            "content_sha256",
            "provider_id",
            "model_id",
            "summary",
            "plan_sha256",
            "future_semantics",
            "security_verdict",
        )
        for field in fields:
            with self.subTest(field=field):
                payload = self._direct()
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)
                self.assertIs(type(payload[field]), _StringSubclass)

    def test_nested_item_string_subclasses_are_rejected(self):
        for field in (
            "plan_item_id",
            "change_area",
            "intent",
            "verification_intent",
            "rollback_intent",
        ):
            with self.subTest(field=field):
                payload = self._direct()
                item = dict(payload["plan_items"][0])
                item[field] = _StringSubclass(item[field])
                payload["plan_items"] = (item,)
                self._assert_rejected_unchanged(payload)
                self.assertIs(type(item[field]), _StringSubclass)

    def test_assumption_string_subclass_is_rejected(self):
        payload = self._direct()
        assumptions = list(payload["assumptions"])
        self.assertTrue(assumptions)
        assumptions[0] = _StringSubclass(assumptions[0])
        payload["assumptions"] = tuple(assumptions)

        self._assert_rejected_unchanged(payload)
        self.assertIs(type(payload["assumptions"][0]), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
