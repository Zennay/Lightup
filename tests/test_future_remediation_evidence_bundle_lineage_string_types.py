from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_evidence_bundle_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_dict,
)


class _StringSubclass(str):
    pass


class FutureRemediationEvidenceBundleLineageStringTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationEvidenceBundleHandoffTest(
            "test_real_producer_round_trips_and_is_immediately_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        produced = self.base._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-lineage-string-types",
        )
        self.bundle = produced[-1]
        self.payload = json.loads(self.bundle.to_json())

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_json_lineage_strings_remain_exact_builtins(self):
        payload = copy.deepcopy(self.payload)
        self.assertEqual(
            future_remediation_evidence_bundle_from_dict(payload),
            self.bundle,
        )

        for field in (
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
        ):
            with self.subTest(scope="top-level", field=field):
                self.assertIs(type(payload[field]), str)

        item = payload["items"][0]
        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
        ):
            with self.subTest(scope="item", field=field):
                self.assertIs(type(item[field]), str)

        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "capability_ids",
        ):
            with self.subTest(scope="item-list", field=field):
                self.assertTrue(item[field])
                self.assertTrue(all(type(value) is str for value in item[field]))

        evidence = item["evidence"][0]
        for field in (
            "evidence_id",
            "run_id",
            "capability_id",
            "kind",
        ):
            with self.subTest(scope="evidence", field=field):
                self.assertIs(type(evidence[field]), str)

    def test_top_level_lineage_string_subclasses_fail_closed(self):
        for field in (
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_item_lineage_string_subclasses_fail_closed(self):
        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload["items"][0][field] = _StringSubclass(
                    payload["items"][0][field]
                )
                self._assert_rejected_unchanged(payload)

    def test_item_string_list_entry_subclasses_fail_closed(self):
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

    def test_evidence_lineage_and_kind_string_subclasses_fail_closed(self):
        for field in (
            "evidence_id",
            "run_id",
            "capability_id",
            "kind",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                evidence = payload["items"][0]["evidence"][0]
                evidence[field] = _StringSubclass(evidence[field])
                self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
