from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_sufficiency_verifier_preflight as preflight_tests
from lightup.domain import AccessContext, Role
from lightup.future_security_evidence_sufficiency_verifier_preflight import (
    validate_future_security_evidence_sufficiency_verifier_preflight,
)
from lightup.future_security_evidence_sufficiency_verifier_preflight_handoff import (
    future_security_evidence_sufficiency_verifier_preflight_from_dict,
)


class FutureSecurityEvidenceSufficiencyVerifierPreflightHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = (
            preflight_tests.FutureSecurityEvidenceSufficiencyVerifierPreflightTest(
                "test_operator_context_creates_bounded_eligibility_only"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self, *, suffix: str = "verifier-preflight-handoff"):
        values = self.base._preflight(suffix=suffix)
        preflight = values[-1]
        return values, json.loads(preflight.to_json())

    def test_round_trip_restores_exact_typed_preflight(self):
        values, payload = self._payload()
        restored = future_security_evidence_sufficiency_verifier_preflight_from_dict(
            payload
        )
        self.assertEqual(restored, values[-1])

    def test_extra_missing_and_malformed_fields_fail_closed(self):
        _, payload = self._payload(suffix="handoff-schema")

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["metadata_review_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(missing)

        malformed_id = copy.deepcopy(payload)
        malformed_id["verifier_user_id"] = True
        with self.assertRaisesRegex(ValueError, "canonical non-empty string"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                malformed_id
            )

        malformed_claim = copy.deepcopy(payload)
        malformed_claim["candidate_classification_claim"] = 1
        with self.assertRaisesRegex(ValueError, "claim must be a string"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                malformed_claim
            )

    def test_candidate_identity_and_classification_claim_fail_closed(self):
        _, payload = self._payload(suffix="handoff-identities")

        duplicate_evidence = copy.deepcopy(payload)
        duplicate_evidence["candidate_evidence_ids"].append(
            duplicate_evidence["candidate_evidence_ids"][0]
        )
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                duplicate_evidence
            )

        noncanonical_capability = copy.deepcopy(payload)
        noncanonical_capability["candidate_capability_ids"][0] += " "
        with self.assertRaisesRegex(ValueError, "canonical non-empty string"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                noncanonical_capability
            )

        unsupported_claim = copy.deepcopy(payload)
        unsupported_claim["candidate_classification_claim"] = "forged-classification"
        with self.assertRaisesRegex(ValueError, "classification claim is unsupported"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                unsupported_claim
            )

    def test_verifier_and_fail_closed_semantics_cannot_be_forged(self):
        _, payload = self._payload(suffix="handoff-semantics")

        role = copy.deepcopy(payload)
        role["verifier_role"] = "client_admin"
        with self.assertRaisesRegex(ValueError, "role must remain operator"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(role)

        ineligible = copy.deepcopy(payload)
        ineligible["eligible_for_sufficiency_review"] = False
        with self.assertRaisesRegex(ValueError, "retain review eligibility"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                ineligible
            )

        for field in (
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
        ):
            forged = copy.deepcopy(payload)
            forged[field] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must remain false"):
                    future_security_evidence_sufficiency_verifier_preflight_from_dict(
                        forged
                    )

        semantics = copy.deepcopy(payload)
        semantics["future_semantics"] = "verified"
        with self.assertRaisesRegex(ValueError, "must remain unresolved"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(
                semantics
            )

        verdict = copy.deepcopy(payload)
        verdict["security_verdict"] = "secure"
        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(verdict)

    def test_digest_tampering_fails_closed(self):
        _, payload = self._payload(suffix="handoff-digest")
        payload["preflight_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_sufficiency_verifier_preflight_from_dict(payload)

    def test_real_producer_round_trip_still_requires_live_validation(self):
        values, payload = self._payload(suffix="handoff-live-validation")
        (
            _current,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            admission,
            review,
            sufficiency_request,
            verifier,
            preflight,
        ) = values
        restored = future_security_evidence_sufficiency_verifier_preflight_from_dict(
            payload
        )
        self.assertEqual(restored, preflight)

        validated = validate_future_security_evidence_sufficiency_verifier_preflight(
            restored,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.base.state,
        )
        self.assertEqual(validated, restored)

        different_verifier = AccessContext(
            user_id="operator-different",
            role=Role.OPERATOR,
        )
        with self.assertRaisesRegex(ValueError, "does not match live validated lineage"):
            validate_future_security_evidence_sufficiency_verifier_preflight(
                restored,
                sufficiency_request,
                review,
                admission,
                constraints,
                verifier=different_verifier,
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.base.state,
            )


if __name__ == "__main__":
    unittest.main()
