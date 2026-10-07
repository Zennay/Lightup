from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_authoring_request_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
)


class _StringSubclass(str):
    pass


class _ListSubclass(list):
    pass


class _DictSubclass(dict):
    pass


class FutureRemediationAuthoringRequestPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationAuthoringRequestHandoffTest(
            "test_real_request_round_trips_and_is_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        produced = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-persisted-object-types",
        )
        self.request = produced[-1]
        self.payload = json.loads(self.request.to_json())

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_authoring_request_from_dict(payload)
        self.assertEqual(payload, before)

    def test_builtin_json_object_form_remains_green(self):
        payload = copy.deepcopy(self.payload)
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            self.request,
        )
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["items"]), list)
        self.assertIs(type(payload["items"][0]), dict)
        self.assertIs(type(payload["items"][0]["evidence"]), list)
        self.assertIs(type(payload["items"][0]["evidence"][0]), dict)

    def test_top_level_mapping_subclass_fails_closed(self):
        self._assert_rejected_unchanged(
            _DictSubclass(copy.deepcopy(self.payload))
        )

    def test_top_level_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        value = payload.pop("client_id")
        payload[_StringSubclass("client_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_items_and_item_mapping_subclasses_fail_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["items"] = _ListSubclass(payload["items"])
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        payload["items"][0] = _DictSubclass(payload["items"][0])
        self._assert_rejected_unchanged(payload)

    def test_item_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        item = payload["items"][0]
        value = item.pop("change_node_id")
        item[_StringSubclass("change_node_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_item_string_list_subclasses_fail_closed(self):
        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload["items"][0][field] = _ListSubclass(
                    payload["items"][0][field]
                )
                self._assert_rejected_unchanged(payload)

    def test_evidence_container_and_mapping_subclasses_fail_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["items"][0]["evidence"] = _ListSubclass(
            payload["items"][0]["evidence"]
        )
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        payload["items"][0]["evidence"][0] = _DictSubclass(
            payload["items"][0]["evidence"][0]
        )
        self._assert_rejected_unchanged(payload)

    def test_evidence_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        evidence = payload["items"][0]["evidence"][0]
        value = evidence.pop("evidence_id")
        evidence[_StringSubclass("evidence_id")] = value
        self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
