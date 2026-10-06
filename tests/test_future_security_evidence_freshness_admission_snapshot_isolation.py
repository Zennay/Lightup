from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness_admission_handoff as handoff_tests
from lightup.future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
)


_FALSE_SAFETY_FLAGS = (
    "evidence_suitability_evaluated",
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityEvidenceFreshnessAdmissionSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityEvidenceFreshnessAdmissionHandoffTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.admission, self.payload = self.base._payload()

    def test_to_json_is_byte_deterministic_and_json_snapshot_round_trips(self):
        first = self.admission.to_json()
        second = self.admission.to_json()
        third = self.admission.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_security_evidence_freshness_admission_from_dict(
                json.loads(first)
            ),
            self.admission,
        )

    def test_nested_as_dict_mutation_cannot_change_source_admission(self):
        original_json = self.admission.to_json()
        snapshot = self.admission.as_dict()

        snapshot["candidate_run_id"] = "forged-run"
        snapshot["candidate_evidence"][0]["evidence_id"] = "forged-evidence"
        snapshot["candidate_evidence"][0]["capability_id"] = "forged-capability"
        snapshot["candidate_evidence_ids"] = ("forged-evidence",)
        snapshot["candidate_capability_ids"] = ("forged-capability",)
        snapshot["freshness_check_passed"] = False
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.admission.to_json(), original_json)
        self.assertTrue(self.admission.freshness_check_passed)
        self.assertFalse(self.admission.execution_allowed)
        self.assertEqual(self.admission.future_semantics, "unresolved")
        self.assertEqual(self.admission.security_verdict, "not_evaluated")
        self.assertNotEqual(
            self.admission.candidate_evidence[0].evidence_id,
            "forged-evidence",
        )

    def test_separate_as_dict_snapshots_do_not_alias_nested_evidence(self):
        first = self.admission.as_dict()
        second = self.admission.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["candidate_evidence"], second["candidate_evidence"])
        self.assertIsNot(
            first["candidate_evidence"][0],
            second["candidate_evidence"][0],
        )
        self.assertIsNot(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )
        self.assertIsNot(
            first["candidate_capability_ids"],
            second["candidate_capability_ids"],
        )

        first["candidate_evidence"][0]["evidence_id"] = "changed-only-in-first"
        first["candidate_evidence_ids"] = ("changed-only-in-first",)

        self.assertEqual(
            second["candidate_evidence"][0]["evidence_id"],
            self.admission.candidate_evidence[0].evidence_id,
        )
        self.assertEqual(
            second["candidate_evidence_ids"],
            self.admission.candidate_evidence_ids,
        )

    def test_parser_detaches_from_caller_owned_nested_json_containers(self):
        persisted = json.loads(self.admission.to_json())
        fingerprints = persisted["candidate_evidence"]
        fingerprint = fingerprints[0]
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]

        parsed = future_security_evidence_freshness_admission_from_dict(persisted)
        parsed_json = parsed.to_json()

        fingerprint["evidence_id"] = "forged-evidence-after-parse"
        fingerprint["run_id"] = "forged-run-after-parse"
        fingerprint["capability_id"] = "forged-capability-after-parse"
        fingerprint["sha256"] = "0" * 64
        fingerprints.clear()
        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability")

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.admission)
        self.assertEqual(
            parsed.candidate_evidence[0].evidence_id,
            self.admission.candidate_evidence[0].evidence_id,
        )
        self.assertEqual(parsed.candidate_evidence_ids, self.admission.candidate_evidence_ids)
        self.assertEqual(
            parsed.candidate_capability_ids,
            self.admission.candidate_capability_ids,
        )

    def test_freshness_and_fail_closed_authority_state_cannot_be_forged(self):
        freshness = json.loads(self.admission.to_json())
        freshness["freshness_check_passed"] = False
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_admission_from_dict(freshness)

        for field in _FALSE_SAFETY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.admission.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_admission_from_dict(payload)

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self.admission.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_admission_from_dict(payload)

    def test_candidate_fingerprint_binding_forgery_fails_closed_without_source_mutation(self):
        original_json = self.admission.to_json()
        snapshot = self.admission.as_dict()
        snapshot["candidate_evidence"][0]["run_id"] = "forged-run"
        snapshot["candidate_capability_ids"] = ("forged-capability",)

        self.assertEqual(self.admission.to_json(), original_json)

        forged = json.loads(original_json)
        forged["candidate_evidence"][0]["run_id"] = "forged-run"
        with self.assertRaisesRegex(ValueError, "must match candidate_run_id"):
            future_security_evidence_freshness_admission_from_dict(forged)


if __name__ == "__main__":
    unittest.main()
