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


class _IntSubclass(int):
    pass


class FutureRemediationAuthoringRequestPersistedScalarTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationAuthoringRequestHandoffTest(
            "test_real_request_round_trips_and_is_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        produced = self.base._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-persisted-scalar-types",
        )
        self.request = produced[-1]
        self.payload = json.loads(self.request.to_json())

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_authoring_request_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_json_scalars_remain_exact_builtins(self):
        payload = copy.deepcopy(self.payload)
        parsed = future_remediation_authoring_request_from_dict(payload)
        self.assertEqual(parsed, self.request)

        for field in (
            "schema_version",
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
            "report_sha256",
            "plan_sha256",
            "bundle_sha256",
            "request_sha256",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(scope="top-level-string", field=field):
                self.assertIs(type(payload[field]), str)

        for field in ("current_twin_version", "twin_version", "item_count"):
            with self.subTest(scope="top-level-int", field=field):
                self.assertIs(type(payload[field]), int)

        item = payload["items"][0]
        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
            "resolution_sha256",
            "classification",
            "evidence_manifest_sha256",
            "requested_output",
        ):
            with self.subTest(scope="item-string", field=field):
                self.assertIs(type(item[field]), str)

        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "capability_ids",
        ):
            with self.subTest(scope="item-list-strings", field=field):
                self.assertTrue(item[field])
                self.assertTrue(all(type(value) is str for value in item[field]))

        evidence = item["evidence"][0]
        for field in (
            "evidence_id",
            "run_id",
            "capability_id",
            "kind",
            "sha256",
        ):
            with self.subTest(scope="evidence-string", field=field):
                self.assertIs(type(evidence[field]), str)

    def test_all_top_level_string_subclasses_fail_closed(self):
        for field in (
            "schema_version",
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
            "report_sha256",
            "plan_sha256",
            "bundle_sha256",
            "request_sha256",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_all_top_level_integer_subclasses_fail_closed(self):
        for field in ("current_twin_version", "twin_version", "item_count"):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _IntSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_all_item_scalar_string_subclasses_fail_closed(self):
        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
            "resolution_sha256",
            "classification",
            "evidence_manifest_sha256",
            "requested_output",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload["items"][0][field] = _StringSubclass(
                    payload["items"][0][field]
                )
                self._assert_rejected_unchanged(payload)

    def test_all_string_list_entry_subclasses_fail_closed(self):
        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                value = payload["items"][0][field][0]
                payload["items"][0][field][0] = _StringSubclass(value)
                self._assert_rejected_unchanged(payload)

    def test_all_evidence_scalar_string_subclasses_fail_closed(self):
        for field in (
            "evidence_id",
            "run_id",
            "capability_id",
            "kind",
            "sha256",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                evidence = payload["items"][0]["evidence"][0]
                evidence[field] = _StringSubclass(evidence[field])
                self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
