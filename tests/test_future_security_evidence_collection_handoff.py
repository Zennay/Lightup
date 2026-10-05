from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_collection_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_collection_request import (
    future_security_evidence_collection_request_from_dict,
)


class FutureSecurityEvidenceCollectionHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityEvidenceCollectionRequestTest(
            "test_insufficient_evidence_produces_fresh_evidence_request_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        *_, request = self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="evidence-collection-handoff",
        )
        return request, json.loads(request.to_json())

    def test_round_trip_restores_exact_typed_request(self):
        request, payload = self._payload()
        restored = future_security_evidence_collection_request_from_dict(payload)
        self.assertEqual(restored, request)

    def test_extra_and_missing_fields_fail_closed(self):
        _, payload = self._payload()

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_collection_request_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["plan_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_collection_request_from_dict(missing)

        item_extra = copy.deepcopy(payload)
        item_extra["items"][0]["target"] = "127.0.0.1"
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_security_evidence_collection_request_from_dict(item_extra)

    def test_mutated_safety_flags_and_digest_fail_closed(self):
        _, payload = self._payload()

        execution = copy.deepcopy(payload)
        execution["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "execution_allowed must remain false"):
            future_security_evidence_collection_request_from_dict(execution)

        remediation = copy.deepcopy(payload)
        remediation["items"][0]["remediation_authoring_allowed"] = True
        with self.assertRaisesRegex(ValueError, "cannot authorize remediation"):
            future_security_evidence_collection_request_from_dict(remediation)

        digest = copy.deepcopy(payload)
        digest["request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_collection_request_from_dict(digest)

    def test_noncanonical_or_duplicate_lineage_arrays_fail_closed(self):
        _, payload = self._payload()

        duplicate = copy.deepcopy(payload)
        duplicate["items"][0]["prior_evidence_ids"].append(
            duplicate["items"][0]["prior_evidence_ids"][0]
        )
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_collection_request_from_dict(duplicate)

        unsorted = copy.deepcopy(payload)
        values = unsorted["items"][0]["effect_ids"]
        values.append("000-artificial")
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_collection_request_from_dict(unsorted)

    def test_invalid_enum_and_primitive_types_fail_closed(self):
        _, payload = self._payload()

        enum_payload = copy.deepcopy(payload)
        enum_payload["items"][0]["classification"] = "introduced"
        with self.assertRaisesRegex(ValueError, "must remain insufficient_evidence"):
            future_security_evidence_collection_request_from_dict(enum_payload)

        version_payload = copy.deepcopy(payload)
        version_payload["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_evidence_collection_request_from_dict(version_payload)

        fresh_payload = copy.deepcopy(payload)
        fresh_payload["items"][0]["fresh_evidence_required"] = 1
        with self.assertRaisesRegex(ValueError, "must require fresh evidence"):
            future_security_evidence_collection_request_from_dict(fresh_payload)

    def test_noncanonical_sha256_is_rejected_before_handoff(self):
        _, payload = self._payload()
        payload["plan_sha256"] = "A" * 64
        with self.assertRaisesRegex(ValueError, "canonical SHA-256"):
            future_security_evidence_collection_request_from_dict(payload)


    def test_empty_path_lineage_still_requires_a_real_list(self):
        _, payload = self._payload()

        none_paths = copy.deepcopy(payload)
        none_paths["items"][0]["current_attack_path_ids"] = None
        with self.assertRaisesRegex(ValueError, "must be a string list"):
            future_security_evidence_collection_request_from_dict(none_paths)

        string_paths = copy.deepcopy(payload)
        string_paths["items"][0]["current_attack_path_ids"] = ""
        with self.assertRaisesRegex(ValueError, "must be a string list"):
            future_security_evidence_collection_request_from_dict(string_paths)



if __name__ == "__main__":
    unittest.main()
