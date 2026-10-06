from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_sufficiency_review_request as request_tests
from lightup.domain import AccessContext, Role, RoleError
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_sufficiency_verifier_preflight import (
    SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION,
    preflight_future_security_evidence_sufficiency_verifier,
    validate_future_security_evidence_sufficiency_verifier_preflight,
)


class FutureSecurityEvidenceSufficiencyVerifierPreflightTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityEvidenceSufficiencyReviewRequestTest(
            "test_live_metadata_review_becomes_bounded_independent_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _inputs(self, *, suffix: str):
        return self.base._request(suffix=suffix)

    def _preflight(
        self,
        *,
        suffix: str,
        verifier: AccessContext | None = None,
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
        ) = self._inputs(suffix=suffix)
        verifier = verifier or AccessContext(
            user_id=f"operator-{suffix}",
            role=Role.OPERATOR,
        )
        current_before = dataclasses.asdict(current)
        preflight = preflight_future_security_evidence_sufficiency_verifier(
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
        self.assertEqual(dataclasses.asdict(current), current_before)
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
        )

    def test_operator_context_creates_bounded_eligibility_only(self):
        (
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            sufficiency_request,
            verifier,
            preflight,
        ) = self._preflight(suffix="verifier-preflight-operator")

        self.assertEqual(
            preflight.schema_version,
            SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION,
        )
        self.assertEqual(preflight.client_id, sufficiency_request.client_id)
        self.assertEqual(
            preflight.sufficiency_request_sha256,
            sufficiency_request.sufficiency_request_sha256,
        )
        self.assertEqual(preflight.verifier_user_id, verifier.user_id)
        self.assertEqual(preflight.verifier_role, "operator")
        self.assertEqual(
            preflight.candidate_classification_claim,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )
        self.assertTrue(preflight.eligible_for_sufficiency_review)
        self.assertFalse(preflight.sufficiency_decision_created)
        self.assertFalse(preflight.evidence_sufficiency_evaluated)
        self.assertFalse(preflight.classification_selected)
        self.assertFalse(preflight.transition_resolution_created)
        self.assertFalse(preflight.collection_authorized)
        self.assertFalse(preflight.tool_call_created)
        self.assertFalse(preflight.execution_allowed)
        self.assertFalse(preflight.target_interaction_allowed)
        self.assertFalse(preflight.remediation_authoring_allowed)
        self.assertFalse(preflight.future_state_retest_allowed)
        self.assertFalse(preflight.deployment_authorized)
        self.assertFalse(preflight.attack_path_mutation_allowed)
        self.assertEqual(preflight.future_semantics, "unresolved")
        self.assertEqual(preflight.security_verdict, "not_evaluated")

        exported = json.loads(preflight.to_json())
        self.assertEqual(exported["verifier_role"], "operator")
        self.assertTrue(exported["eligible_for_sufficiency_review"])
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

    def test_client_roles_fail_closed(self):
        inputs = self._inputs(suffix="verifier-preflight-client-role")
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
        ) = inputs

        for role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER):
            verifier = AccessContext(
                user_id=f"{role.value}-verifier",
                role=role,
                client_id=sufficiency_request.client_id,
            )
            with self.subTest(role=role.value):
                with self.assertRaises(RoleError):
                    preflight_future_security_evidence_sufficiency_verifier(
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

    def test_empty_or_noncanonical_operator_identity_fails_closed(self):
        inputs = self._inputs(suffix="verifier-preflight-identity")
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
        ) = inputs

        for user_id in ("", " operator ", "operator\nforged"):
            with self.subTest(user_id=user_id):
                verifier = AccessContext(user_id=user_id, role=Role.OPERATOR)
                with self.assertRaisesRegex(ValueError, "verifier user_id"):
                    preflight_future_security_evidence_sufficiency_verifier(
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

    def test_tampered_sufficiency_request_fails_before_verifier_eligibility(self):
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
        ) = self._inputs(suffix="verifier-preflight-tampered-request")
        tampered = dataclasses.replace(
            sufficiency_request,
            sufficiency_request_sha256="0" * 64,
        )
        verifier = AccessContext("operator-tamper", Role.OPERATOR)

        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            preflight_future_security_evidence_sufficiency_verifier(
                tampered,
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

    def test_preflight_is_deterministic_and_persisted_copy_is_live_validated(self):
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
            first,
        ) = self._preflight(suffix="verifier-preflight-deterministic")

        second = preflight_future_security_evidence_sufficiency_verifier(
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
        self.assertEqual(first, second)
        self.assertEqual(len(first.preflight_sha256), 64)
        int(first.preflight_sha256, 16)

        validated = validate_future_security_evidence_sufficiency_verifier_preflight(
            first,
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
            dataclasses.replace(first, sufficiency_decision_created=True),
            dataclasses.replace(first, evidence_sufficiency_evaluated=True),
            dataclasses.replace(first, classification_selected=True),
            dataclasses.replace(first, execution_allowed=True),
            dataclasses.replace(first, eligible_for_sufficiency_review=False),
        )
        for tampered in forged:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(ValueError, "live validated lineage"):
                    validate_future_security_evidence_sufficiency_verifier_preflight(
                        tampered,
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
