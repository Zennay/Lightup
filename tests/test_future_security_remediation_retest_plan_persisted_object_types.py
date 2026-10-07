from __future__ import annotations

import copy
import json
import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
)


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _ListSubclass(list):
    pass


class _DictSubclass(dict):
    pass


class FutureSecurityRemediationRetestPlanPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.plan = self.base._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="handoff-object-types",
        )
        self.payload = json.loads(self.plan.to_json())

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_remediation_retest_plan_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_json_decoded_object_remains_green(self):
        parsed = future_security_remediation_retest_plan_from_dict(
            copy.deepcopy(self.payload)
        )
        self.assertEqual(parsed, self.plan)

    def test_top_level_mapping_subclass_fails_closed(self):
        self._assert_rejected_unchanged(_DictSubclass(copy.deepcopy(self.payload)))

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

    def test_nested_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        item = payload["items"][0]
        value = item.pop("change_node_id")
        item[_StringSubclass("change_node_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_string_list_container_and_entry_subclasses_fail_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["items"][0]["current_attack_path_ids"] = _ListSubclass(
            payload["items"][0]["current_attack_path_ids"]
        )
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        item = payload["items"][0]
        list_field = next(
            field
            for field in (
                "current_attack_path_ids",
                "effect_ids",
                "evidence_ids",
                "capability_ids",
            )
            if item[field]
        )
        item[list_field][0] = _StringSubclass(item[list_field][0])
        self._assert_rejected_unchanged(payload)

    def test_identifier_and_sha_string_subclasses_fail_closed(self):
        for field in ("client_id", "current_twin_id", "twin_id", "changeset_id"):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

        for field in (
            "proposal_sha256",
            "impact_analysis_sha256",
            "preview_sha256",
            "report_sha256",
            "plan_sha256",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
            "resolution_sha256",
        ):
            with self.subTest(field=f"item.{field}"):
                payload = copy.deepcopy(self.payload)
                payload["items"][0][field] = _StringSubclass(
                    payload["items"][0][field]
                )
                self._assert_rejected_unchanged(payload)

    def test_fixed_metadata_and_enum_string_subclasses_fail_closed(self):
        for field in ("schema_version", "future_semantics", "security_verdict"):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

        for field in ("classification", "graph_diff_action", "next_action"):
            with self.subTest(field=f"item.{field}"):
                payload = copy.deepcopy(self.payload)
                payload["items"][0][field] = _StringSubclass(
                    payload["items"][0][field]
                )
                self._assert_rejected_unchanged(payload)

    def test_version_and_count_integer_subclasses_fail_closed(self):
        for field in (
            "current_twin_version",
            "twin_version",
            "remediation_item_count",
            "retest_item_count",
            "evidence_gap_count",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _IntSubclass(payload[field])
                self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
