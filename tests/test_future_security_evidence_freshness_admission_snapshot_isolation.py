from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness_admission_handoff as handoff_tests
from lightup.future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
)


_SAFETY_FALSE_FIELDS = (
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
        self.handoff = handoff_tests.FutureSecurityEvidenceFreshnessAdmissionHandoffTest(
            "test_round_trip_restores_exact_typed_admission"
        )
        self.handoff.setUp()
        self.addCleanup(self.handoff.tearDown)
        self.admission, _ = self.handoff._payload()

    def _persisted_dict(self):
        return json.loads(self.admission.to_json())

    def test_json_is_byte_deterministic_and_json_derived_dict_round_trips(self):
        first = self.admission.to_json()
        second = self.admission.to_json()
        third = self.admission.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        restored = future_security_evidence_freshness_admission_from_dict(
            json.loads(first)
        )
        self.assertEqual(restored, self.admission)

    def test_producer_snapshot_nested_mutation_cannot_change_source_admission(self):
        original_json = self.admission.to_json()
        snapshot = self.admission.as_dict()

        snapshot["candidate_run_id"] = "forged-run"
        snapshot["candidate_evidence"][0]["evidence_id"] = "forged-evidence"
        snapshot["candidate_evidence"][0]["sha256"] = "0" * 64
        snapshot["candidate_evidence_ids"] = ("forged-evidence",)
        snapshot["candidate_capability_ids"] = ("forged-capability",)
        snapshot["freshness_check_passed"] = False
        snapshot["classification_selected"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.admission.to_json(), original_json)
        self.assertTrue(self.admission.freshness_check_passed)
        self.assertFalse(self.admission.evidence_suitability_evaluated)
        self.assertFalse(self.admission.classification_selected)
        self.assertFalse(self.admission.execution_allowed)
        self.assertEqual(self.admission.future_semantics, "unresolved")
        self.assertEqual(self.admission.security_verdict, "not_evaluated")

    def test_independent_producer_snapshots_do_not_alias_nested_state(self):
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

        self.assertNotEqual(
            first["candidate_evidence"][0]["evidence_id"],
            second["candidate_evidence"][0]["evidence_id"],
        )
        self.assertNotEqual(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )

    def test_parser_detaches_from_mutable_nested_persisted_state(self):
        persisted = self._persisted_dict()
        evidence = persisted["candidate_evidence"]
        first_fingerprint = evidence[0]
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]

        parsed = future_security_evidence_freshness_admission_from_dict(persisted)
        parsed_json = parsed.to_json()

        first_fingerprint["evidence_id"] = "forged-after-parse"
        first_fingerprint["sha256"] = "0" * 64
        evidence.append(dict(first_fingerprint))
        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence-after-parse")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability-after-parse")
        persisted["execution_allowed"] = True

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.admission)
        self.assertNotIn(
            "forged-evidence-after-parse",
            parsed.candidate_evidence_ids,
        )
        self.assertNotIn(
            "forged-capability-after-parse",
            parsed.candidate_capability_ids,
        )
        self.assertFalse(parsed.execution_allowed)

    def test_forged_freshness_and_safety_snapshot_state_fails_closed(self):
        mutations = {
            "freshness_check_passed": False,
            "future_semantics": "resolved",
            "security_verdict": "secure",
        }
        for field in _SAFETY_FALSE_FIELDS:
            mutations[field] = True

        for field, value in mutations.items():
            with self.subTest(field=field):
                persisted = self._persisted_dict()
                persisted[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_admission_from_dict(
                        persisted
                    )

    def test_forged_nested_candidate_fingerprint_fails_closed(self):
        run_drift = self._persisted_dict()
        run_drift["candidate_evidence"][0]["run_id"] = "different-run"
        with self.assertRaisesRegex(ValueError, "must match candidate_run_id"):
            future_security_evidence_freshness_admission_from_dict(run_drift)

        digest_drift = self._persisted_dict()
        digest_drift["candidate_evidence"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_freshness_admission_from_dict(digest_drift)

        duplicate = self._persisted_dict()
        fingerprint = dict(duplicate["candidate_evidence"][0])
        duplicate["candidate_evidence"].append(fingerprint)
        duplicate["candidate_evidence_ids"].append(fingerprint["evidence_id"])
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_admission_from_dict(duplicate)

    def test_post_parse_top_level_mutation_cannot_change_typed_admission(self):
        persisted = self._persisted_dict()
        parsed = future_security_evidence_freshness_admission_from_dict(persisted)
        parsed_json = parsed.to_json()

        persisted["client_id"] = "changed-after-parse"
        persisted["admission_sha256"] = "0" * 64
        persisted["classification_selected"] = True
        persisted["security_verdict"] = "secure"

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.admission)
        self.assertFalse(parsed.classification_selected)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
