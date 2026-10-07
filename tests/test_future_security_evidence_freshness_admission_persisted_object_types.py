from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness_admission as admission_tests
from lightup.future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
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


class FutureSecurityEvidenceFreshnessAdmissionPersistedObjectTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = admission_tests.FutureSecurityEvidenceFreshnessAdmissionTest(
            "test_fresh_new_run_evidence_passes_without_security_classification"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        *_, admission = self.base._admission(suffix="admission-object-types")
        return admission, json.loads(admission.to_json())

    def _assert_rejected(self, payload):
        snapshot = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_admission_from_dict(payload)
        self.assertEqual(payload, snapshot)

    def test_canonical_json_decoded_object_remains_valid(self):
        admission, payload = self._payload()
        restored = future_security_evidence_freshness_admission_from_dict(payload)
        self.assertEqual(restored, admission)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["candidate_evidence"]), list)
        self.assertIs(type(payload["candidate_evidence"][0]), dict)
        self.assertIs(type(payload["candidate_evidence_ids"]), list)
        self.assertIs(type(payload["candidate_capability_ids"]), list)

    def test_top_level_mapping_subclass_fails_closed(self):
        _, payload = self._payload()
        self._assert_rejected(_DictSubclass(payload))

    def test_schema_key_subclasses_fail_closed(self):
        _, payload = self._payload()

        top = _replace_key(payload, "client_id")
        self.assertTrue(any(type(key) is _StrSubclass for key in top if key == "client_id"))
        self._assert_rejected(top)

        nested = copy.deepcopy(payload)
        nested["candidate_evidence"][0] = _replace_key(
            nested["candidate_evidence"][0],
            "evidence_id",
        )
        self._assert_rejected(nested)

    def test_candidate_evidence_mapping_subclass_fails_closed(self):
        _, payload = self._payload()
        mutated = copy.deepcopy(payload)
        mutated["candidate_evidence"][0] = _DictSubclass(
            mutated["candidate_evidence"][0]
        )
        self._assert_rejected(mutated)

    def test_list_container_subclasses_fail_closed(self):
        _, payload = self._payload()

        evidence = copy.deepcopy(payload)
        evidence["candidate_evidence"] = _ListSubclass(evidence["candidate_evidence"])
        self._assert_rejected(evidence)

        evidence_ids = copy.deepcopy(payload)
        evidence_ids["candidate_evidence_ids"] = _ListSubclass(
            evidence_ids["candidate_evidence_ids"]
        )
        self._assert_rejected(evidence_ids)

        capability_ids = copy.deepcopy(payload)
        capability_ids["candidate_capability_ids"] = _ListSubclass(
            capability_ids["candidate_capability_ids"]
        )
        self._assert_rejected(capability_ids)

    def test_top_level_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()

        for field in (
            "schema_version",
            "client_id",
            "candidate_run_id",
            "request_sha256",
            "constraints_sha256",
            "admission_sha256",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _StrSubclass(mutated[field])
                self._assert_rejected(mutated)

    def test_nested_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()

        for field in ("evidence_id", "run_id", "capability_id", "kind", "sha256"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated["candidate_evidence"][0][field] = _StrSubclass(
                    mutated["candidate_evidence"][0][field]
                )
                self._assert_rejected(mutated)

        lineage = copy.deepcopy(payload)
        lineage["candidate_evidence_ids"][0] = _StrSubclass(
            lineage["candidate_evidence_ids"][0]
        )
        self._assert_rejected(lineage)

    def test_integer_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _IntSubclass(mutated[field])
                self._assert_rejected(mutated)


if __name__ == "__main__":
    unittest.main()
