from __future__ import annotations

import json
import unittest

import test_future_security_evidence_sufficiency_attestation as attestation_tests
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)
from lightup.future_security_evidence_sufficiency_attestation_handoff import (
    future_security_evidence_sufficiency_attestation_from_dict,
)


_SAFETY_FALSE_FIELDS = (
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


class FutureSecurityEvidenceSufficiencyAttestationSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = attestation_tests.FutureSecurityEvidenceSufficiencyAttestationTest(
            "test_all_dispositions_derive_exact_fail_closed_semantics"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        values = self.base._attest(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="snapshot-isolation",
        )
        self.attestation = values[-1]

    def _persisted_dict(self):
        return json.loads(self.attestation.to_json())

    def test_json_is_byte_deterministic_and_json_derived_dict_round_trips(self):
        first = self.attestation.to_json()
        second = self.attestation.to_json()
        third = self.attestation.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        restored = future_security_evidence_sufficiency_attestation_from_dict(
            json.loads(first)
        )
        self.assertEqual(restored, self.attestation)

    def test_producer_snapshot_mutation_cannot_change_source_attestation(self):
        original_json = self.attestation.to_json()
        snapshot = self.attestation.as_dict()

        snapshot["client_id"] = "forged-client"
        snapshot["candidate_evidence_ids"] = ("forged-evidence",)
        snapshot["candidate_capability_ids"] = ("forged-capability",)
        snapshot["evidence_sufficient"] = False
        snapshot["eligible_for_classification_review"] = False
        snapshot["classification_selected"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.attestation.to_json(), original_json)
        self.assertTrue(self.attestation.evidence_sufficient)
        self.assertTrue(self.attestation.classification_claim_justified)
        self.assertTrue(self.attestation.eligible_for_classification_review)
        self.assertFalse(self.attestation.classification_selected)
        self.assertEqual(self.attestation.future_semantics, "unresolved")
        self.assertEqual(self.attestation.security_verdict, "not_evaluated")

    def test_independent_producer_snapshots_do_not_alias(self):
        first = self.attestation.as_dict()
        second = self.attestation.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )
        self.assertIsNot(
            first["candidate_capability_ids"],
            second["candidate_capability_ids"],
        )

        first["candidate_evidence_ids"] = ("changed-only-in-first",)
        first["candidate_capability_ids"] = ("changed-only-in-first",)
        first["disposition"] = "insufficient_for_classification"

        self.assertNotEqual(
            first["candidate_evidence_ids"],
            second["candidate_evidence_ids"],
        )
        self.assertNotEqual(
            first["candidate_capability_ids"],
            second["candidate_capability_ids"],
        )
        self.assertNotEqual(first["disposition"], second["disposition"])

    def test_parser_detaches_from_mutable_persisted_candidate_lists(self):
        persisted = self._persisted_dict()
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]
        parsed = future_security_evidence_sufficiency_attestation_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        evidence_ids[0] = "forged-after-parse"
        evidence_ids.append("extra-after-parse")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability-after-parse")

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.attestation)
        self.assertNotIn("forged-after-parse", parsed.candidate_evidence_ids)
        self.assertNotIn(
            "forged-capability-after-parse",
            parsed.candidate_capability_ids,
        )

    def test_forged_derived_and_safety_snapshot_state_fails_closed(self):
        mutations = {
            "evidence_sufficient": False,
            "classification_claim_justified": False,
            "needs_more_evidence": True,
            "eligible_for_classification_review": False,
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
                    future_security_evidence_sufficiency_attestation_from_dict(
                        persisted
                    )

    def test_forged_classification_claim_and_disposition_fail_closed(self):
        forged_claim = self._persisted_dict()
        forged_claim["candidate_classification_claim"] = "secure_by_operator"
        with self.assertRaisesRegex(ValueError, "classification claim is unsupported"):
            future_security_evidence_sufficiency_attestation_from_dict(
                forged_claim
            )

        forged_disposition = self._persisted_dict()
        forged_disposition["disposition"] = "classification_selected"
        with self.assertRaisesRegex(ValueError, "disposition is unsupported"):
            future_security_evidence_sufficiency_attestation_from_dict(
                forged_disposition
            )

    def test_post_parse_top_level_mutation_cannot_change_typed_attestation(self):
        persisted = self._persisted_dict()
        parsed = future_security_evidence_sufficiency_attestation_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        persisted["client_id"] = "changed-after-parse"
        persisted["verifier_user_id"] = "changed-after-parse"
        persisted["attestation_sha256"] = "0" * 64
        persisted["execution_allowed"] = True

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.attestation)
        self.assertFalse(parsed.execution_allowed)


if __name__ == "__main__":
    unittest.main()
