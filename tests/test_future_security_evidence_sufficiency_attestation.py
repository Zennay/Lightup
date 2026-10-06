from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_sufficiency_verifier_preflight as preflight_tests
from lightup.domain import AccessContext, Role, RoleError
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
    SUFFICIENCY_ATTESTATION_SCHEMA_VERSION,
    attest_future_security_evidence_sufficiency,
    validate_future_security_evidence_sufficiency_attestation,
)


class FutureSecurityEvidenceSufficiencyAttestationTest(unittest.TestCase):
    def setUp(self):
        self.base = preflight_tests.FutureSecurityEvidenceSufficiencyVerifierPreflightTest(
            "test_operator_context_creates_bounded_eligibility_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _inputs(self, *, suffix: str):
        return self.base._preflight(suffix=suffix)

    def _attest(
        self,
        disposition: EvidenceSufficiencyAttestationDisposition,
        *,
        suffix: str,
    ):
        (
            current,
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
        ) = self._inputs(suffix=suffix)
        before = dataclasses.asdict(current)
        attestation = attest_future_security_evidence_sufficiency(
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
            disposition=disposition,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(dataclasses.asdict(current), before)
        return (
            current,
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
        )

    def test_all_dispositions_derive_exact_fail_closed_semantics(self):
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
                *_, attestation = self._attest(
                    disposition,
                    suffix=f"attestation-{disposition.value}",
                )
                self.assertEqual(
                    attestation.schema_version,
                    SUFFICIENCY_ATTESTATION_SCHEMA_VERSION,
                )
                self.assertEqual(attestation.disposition, disposition)
                self.assertEqual(attestation.evidence_sufficient, sufficient)
                self.assertEqual(
                    attestation.classification_claim_justified,
                    justified,
                )
                self.assertEqual(attestation.needs_more_evidence, needs_more)
                self.assertEqual(
                    attestation.eligible_for_classification_review,
                    eligible,
                )
                self.assertTrue(attestation.sufficiency_decision_created)
                self.assertTrue(attestation.evidence_sufficiency_evaluated)
                self.assertTrue(
                    attestation.classification_justification_evaluated
                )
                self.assertFalse(attestation.classification_selected)
                self.assertFalse(attestation.transition_resolution_created)
                self.assertFalse(attestation.collection_authorized)
                self.assertFalse(attestation.tool_call_created)
                self.assertFalse(attestation.execution_allowed)
                self.assertFalse(attestation.target_interaction_allowed)
                self.assertFalse(attestation.remediation_authoring_allowed)
                self.assertFalse(attestation.future_state_retest_allowed)
                self.assertFalse(attestation.deployment_authorized)
                self.assertFalse(attestation.attack_path_mutation_allowed)
                self.assertEqual(attestation.future_semantics, "unresolved")
                self.assertEqual(attestation.security_verdict, "not_evaluated")

    def test_bounded_export_and_deterministic_attestation(self):
        (
            _,
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
            first,
        ) = self._attest(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="attestation-deterministic",
        )
        second = attest_future_security_evidence_sufficiency(
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=verifier,
            disposition=first.disposition,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.attestation_sha256), 64)
        int(first.attestation_sha256, 16)

        exported = json.loads(first.to_json())
        self.assertEqual(
            exported["disposition"],
            "sufficient_claim_justified",
        )
        self.assertFalse(exported["classification_selected"])
        for forbidden in (
            "metadata",
            "payload",
            "source",
            "target",
            "arguments",
            "credentials",
            "password",
            "session",
        ):
            self.assertNotIn(forbidden, exported)

    def test_client_role_and_different_operator_fail_closed(self):
        (
            _,
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
        ) = self._inputs(suffix="attestation-verifier-binding")

        client_verifier = AccessContext(
            "client-verifier",
            Role.CLIENT_ADMIN,
            client_id=sufficiency_request.client_id,
        )
        with self.assertRaises(RoleError):
            attest_future_security_evidence_sufficiency(
                preflight,
                sufficiency_request,
                review,
                admission,
                constraints,
                verifier=client_verifier,
                disposition=(
                    EvidenceSufficiencyAttestationDisposition
                    .INSUFFICIENT_FOR_CLASSIFICATION
                ),
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        other_operator = AccessContext("other-operator", Role.OPERATOR)
        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            attest_future_security_evidence_sufficiency(
                preflight,
                sufficiency_request,
                review,
                admission,
                constraints,
                verifier=other_operator,
                disposition=(
                    EvidenceSufficiencyAttestationDisposition
                    .INSUFFICIENT_FOR_CLASSIFICATION
                ),
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )
        self.assertNotEqual(verifier.user_id, other_operator.user_id)

    def test_tampered_preflight_and_invalid_disposition_fail_closed(self):
        (
            _,
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
        ) = self._inputs(suffix="attestation-tampered-preflight")
        tampered = dataclasses.replace(preflight, preflight_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            attest_future_security_evidence_sufficiency(
                tampered,
                sufficiency_request,
                review,
                admission,
                constraints,
                verifier=verifier,
                disposition=(
                    EvidenceSufficiencyAttestationDisposition
                    .INSUFFICIENT_FOR_CLASSIFICATION
                ),
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        with self.assertRaisesRegex(ValueError, "disposition must be"):
            attest_future_security_evidence_sufficiency(
                preflight,
                sufficiency_request,
                review,
                admission,
                constraints,
                verifier=verifier,
                disposition="sufficient_claim_justified",  # type: ignore[arg-type]
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_persisted_attestation_rejects_forged_semantics(self):
        (
            _,
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
            first,
        ) = self._attest(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="attestation-persisted",
        )

        validated = validate_future_security_evidence_sufficiency_attestation(
            first,
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
            state=self.state,
        )
        self.assertEqual(validated, first)

        forged = (
            dataclasses.replace(first, classification_selected=True),
            dataclasses.replace(first, execution_allowed=True),
            dataclasses.replace(first, transition_resolution_created=True),
            dataclasses.replace(first, eligible_for_classification_review=False),
            dataclasses.replace(first, classification_claim_justified=False),
            dataclasses.replace(first, attestation_sha256="0" * 64),
        )
        for tampered in forged:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(ValueError, "live validated lineage"):
                    validate_future_security_evidence_sufficiency_attestation(
                        tampered,
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
                        state=self.state,
                    )


if __name__ == "__main__":
    unittest.main()
