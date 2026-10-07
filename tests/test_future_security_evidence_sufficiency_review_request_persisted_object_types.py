from __future__ import annotations

import copy
import unittest

import test_future_security_evidence_sufficiency_review_request_handoff as handoff_tests
from lightup.future_security_evidence_sufficiency_review_request_handoff import (
    future_security_evidence_sufficiency_review_request_from_dict,
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


class FutureSecurityEvidenceSufficiencyReviewRequestPersistedObjectTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityEvidenceSufficiencyReviewRequestHandoffTest(
            "test_round_trip_restores_exact_typed_request"
        )

    def _payload(self):
        return self.base._payload()

    def _assert_rejected(self, payload):
        snapshot = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_evidence_sufficiency_review_request_from_dict(payload)
        self.assertEqual(payload, snapshot)

    def test_canonical_json_decoded_object_remains_valid(self):
        request, payload = self._payload()
        restored = future_security_evidence_sufficiency_review_request_from_dict(
            payload
        )
        self.assertEqual(restored, request)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["candidate_evidence_ids"]), list)
        self.assertIs(type(payload["candidate_capability_ids"]), list)
        self.assertIs(type(payload["required_checks"]), list)

    def test_top_level_mapping_and_schema_key_subclasses_fail_closed(self):
        _, payload = self._payload()
        self._assert_rejected(_DictSubclass(payload))

        keyed = _replace_key(payload, "client_id")
        self.assertTrue(
            any(type(key) is _StrSubclass for key in keyed if key == "client_id")
        )
        self._assert_rejected(keyed)

    def test_list_container_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in (
            "candidate_evidence_ids",
            "candidate_capability_ids",
            "required_checks",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _ListSubclass(mutated[field])
                self._assert_rejected(mutated)

    def test_list_entry_string_subclasses_fail_closed(self):
        _, payload = self._payload()

        for field in ("candidate_evidence_ids", "candidate_capability_ids"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field][0] = _StrSubclass(mutated[field][0])
                self._assert_rejected(mutated)

        checks = copy.deepcopy(payload)
        checks["required_checks"][0] = _StrSubclass(checks["required_checks"][0])
        self._assert_rejected(checks)

    def test_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in (
            "schema_version",
            "client_id",
            "candidate_run_id",
            "request_sha256",
            "constraints_sha256",
            "admission_sha256",
            "metadata_review_sha256",
            "sufficiency_request_sha256",
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
