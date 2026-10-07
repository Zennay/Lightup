from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness as freshness_tests
from lightup.future_security_evidence_freshness import (
    future_security_evidence_freshness_constraints_from_dict,
)


class _DictSubclass(dict):
    pass


class _ListSubclass(list):
    pass


class _StrSubclass(str):
    pass


class _IntSubclass(int):
    pass


def _replace_key(mapping: dict, key: str) -> dict:
    return {
        (_StrSubclass(existing) if existing == key else existing): value
        for existing, value in mapping.items()
    }


class FutureSecurityEvidenceFreshnessPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        *_, constraints = self.base._constraints(suffix="freshness-object-types")
        return constraints, json.loads(constraints.to_json())

    def _assert_rejected(self, payload):
        snapshot = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_constraints_from_dict(payload)
        self.assertEqual(payload, snapshot)

    def test_canonical_json_decoded_object_remains_valid(self):
        constraints, payload = self._payload()
        restored = future_security_evidence_freshness_constraints_from_dict(payload)
        self.assertEqual(restored, constraints)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["items"]), list)
        self.assertIs(type(payload["items"][0]), dict)
        self.assertIs(type(payload["items"][0]["prior_evidence"]), list)
        self.assertIs(type(payload["items"][0]["prior_evidence"][0]), dict)

    def test_top_level_mapping_subclass_fails_closed(self):
        _, payload = self._payload()
        self._assert_rejected(_DictSubclass(payload))

    def test_top_level_schema_key_subclass_fails_closed(self):
        _, payload = self._payload()
        mutated = _replace_key(payload, "client_id")
        self.assertTrue(
            any(type(key) is _StrSubclass for key in mutated if key == "client_id")
        )
        self._assert_rejected(mutated)

    def test_item_and_prior_evidence_mapping_subclasses_fail_closed(self):
        _, payload = self._payload()

        item = copy.deepcopy(payload)
        item["items"][0] = _DictSubclass(item["items"][0])
        self._assert_rejected(item)

        evidence = copy.deepcopy(payload)
        evidence["items"][0]["prior_evidence"][0] = _DictSubclass(
            evidence["items"][0]["prior_evidence"][0]
        )
        self._assert_rejected(evidence)

    def test_nested_schema_key_subclasses_fail_closed(self):
        _, payload = self._payload()

        item_key = copy.deepcopy(payload)
        item_key["items"][0] = _replace_key(
            item_key["items"][0],
            "source_resolution_id",
        )
        self._assert_rejected(item_key)

        evidence_key = copy.deepcopy(payload)
        evidence_key["items"][0]["prior_evidence"][0] = _replace_key(
            evidence_key["items"][0]["prior_evidence"][0],
            "evidence_id",
        )
        self._assert_rejected(evidence_key)

    def test_list_container_subclasses_fail_closed(self):
        _, payload = self._payload()

        items = copy.deepcopy(payload)
        items["items"] = _ListSubclass(items["items"])
        self._assert_rejected(items)

        lineage = copy.deepcopy(payload)
        lineage["items"][0]["effect_ids"] = _ListSubclass(
            lineage["items"][0]["effect_ids"]
        )
        self._assert_rejected(lineage)

        prior = copy.deepcopy(payload)
        prior["items"][0]["prior_evidence"] = _ListSubclass(
            prior["items"][0]["prior_evidence"]
        )
        self._assert_rejected(prior)

    def test_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()

        for field in ("schema_version", "client_id", "request_sha256"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _StrSubclass(mutated[field])
                self._assert_rejected(mutated)

        nested = copy.deepcopy(payload)
        nested["items"][0]["source_resolution_sha256"] = _StrSubclass(
            nested["items"][0]["source_resolution_sha256"]
        )
        self._assert_rejected(nested)

        nested_identifier = copy.deepcopy(payload)
        nested_identifier["items"][0]["effect_ids"][0] = _StrSubclass(
            nested_identifier["items"][0]["effect_ids"][0]
        )
        self._assert_rejected(nested_identifier)

        evidence = copy.deepcopy(payload)
        evidence["items"][0]["prior_evidence"][0]["kind"] = _StrSubclass(
            evidence["items"][0]["prior_evidence"][0]["kind"]
        )
        self._assert_rejected(evidence)

    def test_integer_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in ("current_twin_version", "twin_version", "freshness_item_count"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _IntSubclass(mutated[field])
                self._assert_rejected(mutated)


if __name__ == "__main__":
    unittest.main()
