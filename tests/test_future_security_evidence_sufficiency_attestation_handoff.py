from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_sufficiency_attestation as attestation_tests
from lightup.domain import AccessContext, Role
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
    validate_future_security_evidence_sufficiency_attestation,
)
from lightup.future_security_evidence_sufficiency_attestation_handoff import (
    future_security_evidence_sufficiency_attestation_from_dict,
)


class FutureSecurityEvidenceSufficiencyAttestationHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = attestation_tests.FutureSecurityEvidenceSufficiencyAttestationTest(
            "test_all_dispositions_derive_exact_fail_closed_semantics"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(
        self,
        disposition: EvidenceSufficiencyAttestationDisposition,
        *,
        suffix: str,
    ):
        values = self.base._attest(disposition, suffix=suffix)
        attestation = values[-1]
        return values, json.loads(attestation.to_json())

    def test_all_dispositions_round_trip_with_exact_derived_flags(self):
        cases = (
            (
                EvidenceSufficiencyAttestationDisposition.INSUFFICIENT_FOR_CLASSIFICATION,
                False,
                False,
                True,
                False,
            ),
            (
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_UNJUSTIFIED,
                True,
                False,
                False,
                False,
            ),
            (
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
                True,
                True,
                False,
                True,
            ),
        )
        for disposition, sufficient, justified, needs_more, eligible in cases:
            with self.subTest(disposition=disposition.value):
                values, payload = self._payload(
                    disposition,
                    suffix=f"handoff-{disposition.value}",
                )
                restored = future_security_evidence_sufficiency_attestation_from_dict(
                    payload
                )
                self.assertEqual(restored, values[-1])
                self.assertEqual(restored.evidence_sufficient, sufficient)
                self.assertEqual(
                    restored.classification_claim_justified,
                    justified,
                )
                self.assertEqual(restored.needs_more_evidence, needs_more)
                self.assertEqual(
                    restored.eligible_for_classification_review,
                    eligible,
                )

    def test_extra_missing_and_malformed_fields_fail_closed(self):
        _, payload = self._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="handoff-schema",
        )

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_sufficiency_attestation_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["verifier_preflight_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_sufficiency_attestation_from_dict(missing)

        bad_identifier = copy.deepcopy(payload)
        bad_identifier["verifier_user_id"] = True
        with self.assertRaisesRegex(ValueError, "canonical non-empty string"):
            future_security_evidence_sufficiency_attestation_from_dict(
                bad_identifier
            )

        bad_disposition_type = copy.deepcopy(payload)
        bad_disposition_type["disposition"] = 1
        with self.assertRaisesRegex(ValueError, "disposition must be a string"):
            future_security_evidence_sufficiency_attestation_from_dict(
                bad_disposition_type
            )

    def test_candidate_ids_claim_and_disposition_are_canonical(self):
        _, payload = self._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="handoff-canonical",
        )

        duplicate = copy.deepcopy(payload)
        duplicate["candidate_evidence_ids"].append(
            duplicate["candidate_evidence_ids"][0]
        )
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_sufficiency_attestation_from_dict(duplicate)

        noncanonical = copy.deepcopy(payload)
        noncanonical["candidate_capability_ids"][0] += " "
        with self.assertRaisesRegex(ValueError, "canonical non-empty string"):
            future_security_evidence_sufficiency_attestation_from_dict(noncanonical)

        bad_claim = copy.deepcopy(payload)
        bad_claim["candidate_classification_claim"] = "forged-classification"
        with self.assertRaisesRegex(ValueError, "classification claim is unsupported"):
            future_security_evidence_sufficiency_attestation_from_dict(bad_claim)

        bad_disposition = copy.deepcopy(payload)
        bad_disposition["disposition"] = "operator_says_secure"
        with self.assertRaisesRegex(ValueError, "disposition is unsupported"):
            future_security_evidence_sufficiency_attestation_from_dict(
                bad_disposition
            )

    def test_derived_and_safety_semantics_cannot_be_forged(self):
        _, payload = self._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="handoff-derived",
        )

        for field in (
            "evidence_sufficient",
            "classification_claim_justified",
            "needs_more_evidence",
            "eligible_for_classification_review",
        ):
            forged = copy.deepcopy(payload)
            forged[field] = not forged[field]
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} does not match disposition"):
                    future_security_evidence_sufficiency_attestation_from_dict(
                        forged
                    )

        for field in (
            "sufficiency_decision_created",
            "evidence_sufficiency_evaluated",
            "classification_justification_evaluated",
        ):
            forged = copy.deepcopy(payload)
            forged[field] = False
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must remain true"):
                    future_security_evidence_sufficiency_attestation_from_dict(
                        forged
                    )

        for field in (
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
                    future_security_evidence_sufficiency_attestation_from_dict(
                        forged
                    )

        semantics = copy.deepcopy(payload)
        semantics["future_semantics"] = "verified"
        with self.assertRaisesRegex(ValueError, "must remain unresolved"):
            future_security_evidence_sufficiency_attestation_from_dict(semantics)

        verdict = copy.deepcopy(payload)
        verdict["security_verdict"] = "secure"
        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            future_security_evidence_sufficiency_attestation_from_dict(verdict)

    def test_noncanonical_sha_and_digest_drift_fail_closed(self):
        _, payload = self._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="handoff-digest",
        )

        uppercase = copy.deepcopy(payload)
        uppercase["verifier_preflight_sha256"] = "A" * 64
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            future_security_evidence_sufficiency_attestation_from_dict(uppercase)

        changed = copy.deepcopy(payload)
        changed["subject_node_id"] = "different-subject"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_sufficiency_attestation_from_dict(changed)

        digest = copy.deepcopy(payload)
        digest["attestation_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_sufficiency_attestation_from_dict(digest)

    def test_real_producer_round_trip_still_requires_live_validation(self):
        values, payload = self._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="handoff-live",
        )
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
            attestation,
        ) = values
        restored = future_security_evidence_sufficiency_attestation_from_dict(payload)
        self.assertEqual(restored, attestation)

        validated = validate_future_security_evidence_sufficiency_attestation(
            restored,
            preflight,
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
        with self.assertRaises(ValueError):
            validate_future_security_evidence_sufficiency_attestation(
                restored,
                preflight,
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
