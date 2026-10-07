from __future__ import annotations

import copy
import unittest

import test_future_security_evidence_sufficiency_attestation_handoff as handoff_tests
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)
from lightup.future_security_evidence_sufficiency_attestation_handoff import (
    future_security_evidence_sufficiency_attestation_from_dict,
)


class _DictSubclass(dict):
    pass


class _ListSubclass(list):
    pass


class _StrSubclass(str):
    pass


def _replace_key(mapping: dict, key: str) -> dict:
    return {
        (_StrSubclass(existing) if existing == key else existing): value
        for existing, value in mapping.items()
    }


class FutureSecurityEvidenceSufficiencyAttestationPersistedObjectTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureSecurityEvidenceSufficiencyAttestationHandoffTest(
                "test_all_dispositions_round_trip_with_exact_derived_flags"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        values, payload = self.base._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="attestation-object-types",
        )
        return values[-1], payload

    def _assert_rejected(self, payload):
        snapshot = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_security_evidence_sufficiency_attestation_from_dict(payload)
        self.assertEqual(payload, snapshot)

    def test_canonical_json_decoded_object_remains_valid(self):
        attestation, payload = self._payload()
        restored = future_security_evidence_sufficiency_attestation_from_dict(payload)
        self.assertEqual(restored, attestation)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["candidate_evidence_ids"]), list)
        self.assertIs(type(payload["candidate_capability_ids"]), list)

    def test_top_level_mapping_and_schema_key_subclasses_fail_closed(self):
        _, payload = self._payload()
        self._assert_rejected(_DictSubclass(payload))

        keyed = _replace_key(payload, "client_id")
        self.assertTrue(
            any(type(key) is _StrSubclass for key in keyed if key == "client_id")
        )
        self._assert_rejected(keyed)

    def test_list_container_and_entry_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in ("candidate_evidence_ids", "candidate_capability_ids"):
            with self.subTest(field=field, kind="container"):
                container = copy.deepcopy(payload)
                container[field] = _ListSubclass(container[field])
                self._assert_rejected(container)

            with self.subTest(field=field, kind="entry"):
                entry = copy.deepcopy(payload)
                entry[field][0] = _StrSubclass(entry[field][0])
                self._assert_rejected(entry)

    def test_string_scalar_subclasses_fail_closed(self):
        _, payload = self._payload()
        for field in (
            "schema_version",
            "client_id",
            "sufficiency_request_sha256",
            "verifier_preflight_sha256",
            "metadata_review_sha256",
            "admission_sha256",
            "source_resolution_id",
            "change_node_id",
            "subject_node_id",
            "candidate_run_id",
            "candidate_classification_claim",
            "verifier_user_id",
            "disposition",
            "attestation_sha256",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(payload)
                mutated[field] = _StrSubclass(mutated[field])
                self._assert_rejected(mutated)


if __name__ == "__main__":
    unittest.main()
