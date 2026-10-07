from __future__ import annotations

import copy
import json
import unittest

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request_handoff import (
    future_security_retest_request_from_dict,
)


class _DictSubclass(dict):
    pass


class _ListSubclass(list):
    pass


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class FutureSecurityRetestRequestObjectShapeTypesTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        *_, self.request = self.r._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="object-shape-types",
        )

    def _payload(self) -> dict:
        return json.loads(self.request.to_json())

    def _assert_rejected_unchanged(self, payload: dict) -> None:
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_retest_request_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_json_decoded_object_shape_remains_valid(self):
        payload = self._payload()

        parsed = future_security_retest_request_from_dict(payload)

        self.assertEqual(parsed, self.request)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["items"]), list)
        self.assertTrue(all(type(key) is str for key in payload))
        self.assertTrue(all(type(item) is dict for item in payload["items"]))
        self.assertTrue(
            all(type(key) is str for item in payload["items"] for key in item)
        )
        self.assertIs(type(payload["current_twin_version"]), int)
        self.assertIs(type(payload["twin_version"]), int)

    def test_top_level_mapping_subclass_is_rejected(self):
        payload = _DictSubclass(self._payload())

        self._assert_rejected_unchanged(payload)

        self.assertIs(type(payload), _DictSubclass)

    def test_each_top_level_schema_key_subclass_is_rejected(self):
        canonical = self._payload()
        for key in tuple(canonical):
            with self.subTest(key=key):
                payload = copy.deepcopy(canonical)
                value = payload.pop(key)
                payload[_StringSubclass(key)] = value

                self._assert_rejected_unchanged(payload)

                stored = next(candidate for candidate in payload if candidate == key)
                self.assertIs(type(stored), _StringSubclass)

    def test_items_list_subclass_is_rejected(self):
        payload = self._payload()
        payload["items"] = _ListSubclass(payload["items"])

        self._assert_rejected_unchanged(payload)

        self.assertIs(type(payload["items"]), _ListSubclass)

    def test_each_nested_item_mapping_subclass_is_rejected(self):
        canonical = self._payload()
        for index in range(len(canonical["items"])):
            with self.subTest(index=index):
                payload = copy.deepcopy(canonical)
                payload["items"][index] = _DictSubclass(payload["items"][index])

                self._assert_rejected_unchanged(payload)

                self.assertIs(type(payload["items"][index]), _DictSubclass)

    def test_each_nested_item_schema_key_subclass_is_rejected(self):
        canonical = self._payload()
        for item_index, item in enumerate(canonical["items"]):
            for key in tuple(item):
                with self.subTest(item_index=item_index, key=key):
                    payload = copy.deepcopy(canonical)
                    rewritten = dict(payload["items"][item_index])
                    value = rewritten.pop(key)
                    rewritten[_StringSubclass(key)] = value
                    payload["items"][item_index] = rewritten

                    self._assert_rejected_unchanged(payload)

                    stored = next(
                        candidate for candidate in rewritten if candidate == key
                    )
                    self.assertIs(type(stored), _StringSubclass)

    def test_top_level_string_list_subclasses_are_rejected(self):
        for field in ("requested_capability_ids", "evidence_ids"):
            with self.subTest(field=field):
                payload = self._payload()
                payload[field] = _ListSubclass(payload[field])

                self._assert_rejected_unchanged(payload)

                self.assertIs(type(payload[field]), _ListSubclass)

    def test_each_item_string_list_subclass_is_rejected(self):
        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                payload = self._payload()
                payload["items"][0][field] = _ListSubclass(
                    payload["items"][0][field]
                )

                self._assert_rejected_unchanged(payload)

                self.assertIs(type(payload["items"][0][field]), _ListSubclass)

    def test_version_integer_subclasses_are_rejected(self):
        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                payload = self._payload()
                payload[field] = _IntSubclass(payload[field])

                self._assert_rejected_unchanged(payload)

                self.assertIs(type(payload[field]), _IntSubclass)

    def test_schema_version_string_subclass_is_rejected(self):
        payload = self._payload()
        payload["schema_version"] = _StringSubclass(payload["schema_version"])

        self._assert_rejected_unchanged(payload)

        self.assertIs(type(payload["schema_version"]), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
