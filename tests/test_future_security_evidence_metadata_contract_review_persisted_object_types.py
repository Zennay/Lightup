from __future__ import annotations

import copy
import unittest

import test_future_security_evidence_metadata_contract_review_handoff as handoff_tests
from lightup.future_security_evidence_metadata_contract_review_handoff import (
    future_security_evidence_metadata_contract_review_from_dict,
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


class FutureSecurityEvidenceMetadataContractReviewPersistedObjectTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityEvidenceMetadataContractReviewHandoffTest(
            "test_round_trip_restores_exact_typed_review"
        )

    def _payload(self):
        return self.base._payload()

    def _assert_rejected(self, payload):
        snapshot = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_evidence_metadata_contract_review_from_dict(payload)
        self.assertEqual(payload, snapshot)

    def test_canonical_json_decoded_object_remains_valid(self):
        review, payload = self._payload()
        restored = future_security_evidence_metadata_contract_review_from_dict(payload)
        self.assertEqual(restored, review)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["candidate_evidence_ids"]), list)
        self.assertIs(type(payload["candidate_capability_ids"]), list)

    def test_top_level_mapping_subclass_fails_closed(self):
        _, payload = self._payload()
        self._assert_rejected(_DictSubclass(payload))

    def test_schema_key_subclass_fails_closed(self):
        _, payload = self._payload()
        mutated = _replace_key(payload, "client_id")
        self.assertTrue(
            any(type(key) is _StrSubclass for key in mutated if key == "client_id")
        )
        self._assert_rejected(mutated)

    def test_list_container_subclasses_fail_closed(self):
        _, payload = self._payload()

        evidence = copy.deepcopy(payload)
        evidence["candidate_evidence_ids"] = _ListSubclass(
            evidence["candidate_evidence_ids"]
        )
        self._assert_rejected(evidence)

        capabilities = copy.deepcopy(payload)
        capabilities["candidate_capability_ids"] = _ListSubclass(
            capabilities["candidate_capability_ids"]
        )
        self._assert_rejected(capabilities)

    def test_list_entry_string_subclasses_fail_closed(self):
        _, payload = self._payload()

        evidence = copy.deepcopy(payload)
        evidence["candidate_evidence_ids"][0] = _StrSubclass(
            evidence["candidate_evidence_ids"][0]
        )
        self._assert_rejected(evidence)

        capabilities = copy.deepcopy(payload)
        capabilities["candidate_capability_ids"][0] = _StrSubclass(
            capabilities["candidate_capability_ids"][0]
        )
        self._assert_rejected(capabilities)

    def test_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()

        for field in (
            "schema_version",
            "client_id",
            "candidate_run_id",
            "request_sha256",
            "constraints_sha256",
            "admission_sha256",
            "review_sha256",
            "candidate_classification_claim",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _StrSubclass(mutated[field])
                self._assert_rejected(mutated)

    def test_integer_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _IntSubclass(mutated[field])
                self._assert_rejected(mutated)


if __name__ == "__main__":
    unittest.main()
