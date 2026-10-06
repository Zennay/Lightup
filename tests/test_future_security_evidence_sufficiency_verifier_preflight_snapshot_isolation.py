from __future__ import annotations

import json
import unittest

import test_future_security_evidence_sufficiency_verifier_preflight_handoff as handoff_tests
from lightup.future_security_evidence_sufficiency_verifier_preflight_handoff import (
    future_security_evidence_sufficiency_verifier_preflight_from_dict,
)


_FALSE_SAFETY_FLAGS = (
    "sufficiency_decision_created",
    "evidence_sufficiency_evaluated",
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


class FutureSecurityEvidenceSufficiencyVerifierPreflightSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureSecurityEvidenceSufficiencyVerifierPreflightHandoffTest()
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.values, self.payload = self.base._payload(
            suffix="verifier-preflight-snapshot"
        )
        self.preflight = self.values[-1]

    def test_to_json_is_byte_deterministic_and_json_snapshot_round_trips(self):
        first = self.preflight.to_json()
        second = self.preflight.to_json()
        third = self.preflight.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                json.loads(first)
            ),
            self.preflight,
        )

    def test_as_dict_mutation_cannot_change_source_preflight(self):
        original_json = self.preflight.to_json()
        snapshot = self.preflight.as_dict()

        snapshot["verifier_user_id"] = "forged-operator"
        snapshot["verifier_role"] = "client_admin"
        snapshot["eligible_for_sufficiency_review"] = False
        snapshot["candidate_evidence_ids"] = ("evidence-z",)
        snapshot["candidate_capability_ids"] = ("capability-z",)
        snapshot["candidate_classification_claim"] = "secure"
        snapshot["sufficiency_decision_created"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"

        self.assertEqual(self.preflight.to_json(), original_json)
        self.assertEqual(self.preflight.verifier_role, "operator")
        self.assertTrue(self.preflight.eligible_for_sufficiency_review)
        self.assertFalse(self.preflight.sufficiency_decision_created)
        self.assertFalse(self.preflight.execution_allowed)
        self.assertEqual(self.preflight.future_semantics, "unresolved")
        self.assertEqual(self.preflight.security_verdict, "not_evaluated")

    def test_separate_as_dict_snapshots_do_not_alias(self):
        first = self.preflight.as_dict()
        second = self.preflight.as_dict()

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

        self.assertEqual(
            second["candidate_evidence_ids"],
            self.preflight.candidate_evidence_ids,
        )
        self.assertEqual(
            second["candidate_capability_ids"],
            self.preflight.candidate_capability_ids,
        )

    def test_parser_detaches_from_caller_owned_mutable_lists(self):
        persisted = json.loads(self.preflight.to_json())
        evidence_ids = persisted["candidate_evidence_ids"]
        capability_ids = persisted["candidate_capability_ids"]

        parsed = future_security_evidence_sufficiency_verifier_preflight_from_dict(
            persisted
        )
        parsed_json = parsed.to_json()

        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence")
        capability_ids[0] = "forged-capability-after-parse"
        capability_ids.append("extra-capability")

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.preflight)
        self.assertEqual(parsed.candidate_evidence_ids, self.preflight.candidate_evidence_ids)
        self.assertEqual(
            parsed.candidate_capability_ids,
            self.preflight.candidate_capability_ids,
        )

    def test_forged_verifier_and_authority_state_fail_closed(self):
        for field, value in (
            ("verifier_role", "client_admin"),
            ("eligible_for_sufficiency_review", False),
        ):
            with self.subTest(field=field):
                payload = json.loads(self.preflight.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_sufficiency_verifier_preflight_from_dict(
                        payload
                    )

        for field in _FALSE_SAFETY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.preflight.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_security_evidence_sufficiency_verifier_preflight_from_dict(
                        payload
                    )

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self.preflight.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_sufficiency_verifier_preflight_from_dict(
                        payload
                    )

    def test_classification_claim_remains_claim_only_and_snapshot_mutation_is_local(self):
        original_json = self.preflight.to_json()
        snapshot = self.preflight.as_dict()
        snapshot["candidate_classification_claim"] = "secure"

        self.assertEqual(self.preflight.to_json(), original_json)
        self.assertFalse(self.preflight.classification_selected)

        persisted = json.loads(original_json)
        persisted["candidate_classification_claim"] = "secure"
        with self.assertRaisesRegex(ValueError, "classification claim is unsupported"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                persisted
            )


if __name__ == "__main__":
    unittest.main()
