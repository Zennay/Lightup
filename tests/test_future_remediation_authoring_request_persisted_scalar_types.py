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

        self.assertIs(type(payload["schema_version"]), str)
        self.assertIs(type(payload["client_id"]), str)
        self.assertIs(type(payload["request_sha256"]), str)
        self.assertIs(type(payload["twin_version"]), int)

        item = payload["items"][0]
        self.assertIs(type(item["change_node_id"]), str)
        self.assertIs(type(item["classification"]), str)
        self.assertIs(type(item["requested_output"]), str)
        self.assertIs(type(item["resolution_sha256"]), str)
        self.assertIs(type(item["capability_ids"][0]), str)

        evidence = item["evidence"][0]
        self.assertIs(type(evidence["evidence_id"]), str)
        self.assertIs(type(evidence["kind"]), str)
        self.assertIs(type(evidence["sha256"]), str)

    def test_fixed_top_level_string_subclasses_fail_closed(self):
        for field in (
            "schema_version",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_top_level_identifier_and_sha_subclasses_fail_closed(self):
        for field in (
            "client_id",
            "request_sha256",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_top_level_integer_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["twin_version"] = _IntSubclass(payload["twin_version"])
        self._assert_rejected_unchanged(payload)

    def test_item_scalar_string_subclasses_fail_closed(self):
        for field in (
            "change_node_id",
            "classification",
            "requested_output",
            "resolution_sha256",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload["items"][0][field] = _StringSubclass(
                    payload["items"][0][field]
                )
                self._assert_rejected_unchanged(payload)

    def test_string_list_entry_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        capability = payload["items"][0]["capability_ids"][0]
        payload["items"][0]["capability_ids"][0] = _StringSubclass(capability)
        self._assert_rejected_unchanged(payload)

    def test_evidence_scalar_string_subclasses_fail_closed(self):
        for field in (
            "evidence_id",
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
