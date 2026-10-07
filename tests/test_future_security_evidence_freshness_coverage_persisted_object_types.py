from __future__ import annotations

import copy
import unittest

import test_future_security_evidence_freshness_coverage_handoff as handoff_tests
from lightup.future_security_evidence_freshness_coverage import (
    future_security_evidence_freshness_coverage_from_dict,
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


class FutureSecurityEvidenceFreshnessCoveragePersistedObjectTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityEvidenceFreshnessCoverageHandoffTest(
            "test_exact_round_trip_restores_covered_and_uncovered_reports"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        return self.base._covered_payload()

    def _assert_rejected(self, payload):
        snapshot = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_coverage_from_dict(payload)
        self.assertEqual(payload, snapshot)

    def test_canonical_json_decoded_covered_and_uncovered_objects_remain_valid(self):
        for factory in (self.base._covered_payload, self.base._uncovered_payload):
            with self.subTest(factory=factory.__name__):
                coverage, payload = factory()
                restored = future_security_evidence_freshness_coverage_from_dict(
                    payload
                )
                self.assertEqual(restored, coverage)
                self.assertIs(type(payload), dict)
                self.assertIs(type(payload["items"]), list)
                self.assertIs(type(payload["items"][0]), dict)
                self.assertIs(
                    type(payload["items"][0]["candidate_evidence_ids"]),
                    list,
                )

    def test_mapping_and_schema_key_subclasses_fail_closed(self):
        _, payload = self._payload()
        self._assert_rejected(_DictSubclass(payload))

        keyed = _replace_key(payload, "client_id")
        self.assertTrue(
            any(type(key) is _StrSubclass for key in keyed if key == "client_id")
        )
        self._assert_rejected(keyed)

        item_mapping = copy.deepcopy(payload)
        item_mapping["items"][0] = _DictSubclass(item_mapping["items"][0])
        self._assert_rejected(item_mapping)

        item_key = copy.deepcopy(payload)
        item_key["items"][0] = _replace_key(
            item_key["items"][0],
            "source_resolution_id",
        )
        self._assert_rejected(item_key)

    def test_list_container_and_entry_subclasses_fail_closed(self):
        _, payload = self._payload()

        items = copy.deepcopy(payload)
        items["items"] = _ListSubclass(items["items"])
        self._assert_rejected(items)

        evidence = copy.deepcopy(payload)
        evidence["items"][0]["candidate_evidence_ids"] = _ListSubclass(
            evidence["items"][0]["candidate_evidence_ids"]
        )
        self._assert_rejected(evidence)

        entry = copy.deepcopy(payload)
        entry["items"][0]["candidate_evidence_ids"][0] = _StrSubclass(
            entry["items"][0]["candidate_evidence_ids"][0]
        )
        self._assert_rejected(entry)

    def test_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in (
            "schema_version",
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
            "request_sha256",
            "constraints_sha256",
            "coverage_sha256",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _StrSubclass(mutated[field])
                self._assert_rejected(mutated)

        for field in (
            "change_node_id",
            "subject_node_id",
            "source_resolution_id",
            "admission_sha256",
            "candidate_run_id",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated["items"][0][field] = _StrSubclass(
                    mutated["items"][0][field]
                )
                self._assert_rejected(mutated)

    def test_integer_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in (
            "current_twin_version",
            "twin_version",
            "total_gap_count",
            "covered_gap_count",
            "missing_gap_count",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _IntSubclass(mutated[field])
                self._assert_rejected(mutated)


if __name__ == "__main__":
    unittest.main()
