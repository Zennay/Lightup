from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_classification_review_request_consumer as consumer_tests
from lightup.domain import AccessContext, Role, RoleError
from lightup.future_security_classification_reviewer_preflight import (
    CLASSIFICATION_REVIEWER_PREFLIGHT_SCHEMA_VERSION,
    preflight_future_security_classification_reviewer,
    validate_future_security_classification_reviewer_preflight,
)


_AUTHORITY_FLAGS = (
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityClassificationReviewerPreflightTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityClassificationReviewRequestConsumerTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _inputs(self, *, suffix: str):
        return self.base._producer(suffix=suffix)

    def _preflight(
        self,
        *,
        suffix: str,
        classification_reviewer: AccessContext | None = None,
    ):
        produced = self._inputs(suffix=suffix)
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            collection_request,
            constraints,
            candidate_context,
            admission,
            review,
            sufficiency_request,
            sufficiency_verifier,
            sufficiency_preflight,
            attestation,
            classification_request,
        ) = produced
        classification_reviewer = classification_reviewer or AccessContext(
            user_id=f"classification-reviewer-{suffix}",
            role=Role.OPERATOR,
        )
        reviewer_preflight = preflight_future_security_classification_reviewer(
            classification_request.to_json(),
            attestation,
            sufficiency_preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            sufficiency_verifier=sufficiency_verifier,
            classification_reviewer=classification_reviewer,
            candidate_context=candidate_context,
            request=collection_request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        return produced, classification_reviewer, reviewer_preflight

    def test_distinct_operator_creates_independent_eligibility_only(self):
        produced, classification_reviewer, preflight = self._preflight(
            suffix="classification-preflight-operator"
        )
        classification_request = produced[-1]
        sufficiency_verifier = produced[13]

        self.assertEqual(
            preflight.schema_version,
            CLASSIFICATION_REVIEWER_PREFLIGHT_SCHEMA_VERSION,
        )
        self.assertEqual(
            preflight.classification_review_request_sha256,
            classification_request.classification_review_request_sha256,
        )
        self.assertEqual(
            preflight.sufficiency_verifier_user_id,
            sufficiency_verifier.user_id,
        )
        self.assertEqual(
            preflight.classification_reviewer_user_id,
            classification_reviewer.user_id,
        )
        self.assertNotEqual(
            preflight.classification_reviewer_user_id,
            preflight.sufficiency_verifier_user_id,
        )
        self.assertEqual(preflight.classification_reviewer_role, "operator")
        self.assertTrue(preflight.independent_reviewer_verified)
        self.assertTrue(preflight.eligible_for_classification_review)
        self.assertFalse(preflight.classification_decision_created)
        self.assertFalse(preflight.classification_selected)
        self.assertFalse(preflight.transition_resolution_created)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(preflight, field), field)
        self.assertEqual(preflight.future_semantics, "unresolved")
        self.assertEqual(preflight.security_verdict, "not_evaluated")

        exported = json.loads(preflight.to_json())
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
        for role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER):
            with self.subTest(role=role.value):
                reviewer = AccessContext(
                    user_id=f"{role.value}-classification-reviewer",
                    role=role,
                    client_id="client-1",
                )
                with self.assertRaises(RoleError):
                    self._preflight(
                        suffix=f"classification-preflight-{role.value}",
                        classification_reviewer=reviewer,
                    )

    def test_sufficiency_verifier_cannot_review_own_classification_claim(self):
        produced = self._inputs(suffix="classification-preflight-independence")
        sufficiency_verifier = produced[13]

        with self.assertRaisesRegex(ValueError, "must be independent"):
            self._preflight(
                suffix="classification-preflight-independence-second",
                classification_reviewer=sufficiency_verifier,
            )

    def test_empty_or_noncanonical_reviewer_identity_fails_closed(self):
        for user_id in ("", " reviewer ", "reviewer\nforged"):
            with self.subTest(user_id=user_id):
                reviewer = AccessContext(user_id=user_id, role=Role.OPERATOR)
                with self.assertRaisesRegex(
                    ValueError,
                    "classification reviewer user_id",
                ):
                    self._preflight(
                        suffix="classification-preflight-identity",
                        classification_reviewer=reviewer,
                    )

    def test_tampered_persisted_classification_request_fails_before_eligibility(self):
        produced = self._inputs(suffix="classification-preflight-tampered")
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            collection_request,
            constraints,
            candidate_context,
            admission,
            review,
            sufficiency_request,
            sufficiency_verifier,
            sufficiency_preflight,
            attestation,
            classification_request,
        ) = produced
        payload = json.loads(classification_request.to_json())
        payload["classification_review_request_sha256"] = "0" * 64
        reviewer = AccessContext("classification-reviewer-tamper", Role.OPERATOR)

        with self.assertRaises(ValueError):
            preflight_future_security_classification_reviewer(
                payload,
                attestation,
                sufficiency_preflight,
                sufficiency_request,
                review,
                admission,
                constraints,
                sufficiency_verifier=sufficiency_verifier,
                classification_reviewer=reviewer,
                candidate_context=candidate_context,
                request=collection_request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_preflight_is_deterministic_and_live_validator_rejects_forgery(self):
        produced, classification_reviewer, first = self._preflight(
            suffix="classification-preflight-deterministic"
        )
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            collection_request,
            constraints,
            candidate_context,
            admission,
            review,
            sufficiency_request,
            sufficiency_verifier,
            sufficiency_preflight,
            attestation,
            classification_request,
        ) = produced

        second = preflight_future_security_classification_reviewer(
            classification_request.to_json(),
            attestation,
            sufficiency_preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            sufficiency_verifier=sufficiency_verifier,
            classification_reviewer=classification_reviewer,
            candidate_context=candidate_context,
            request=collection_request,
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

        validated = validate_future_security_classification_reviewer_preflight(
            first,
            classification_request.to_json(),
            attestation,
            sufficiency_preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            sufficiency_verifier=sufficiency_verifier,
            classification_reviewer=classification_reviewer,
            candidate_context=candidate_context,
            request=collection_request,
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
            dataclasses.replace(first, classification_decision_created=True),
            dataclasses.replace(first, classification_selected=True),
            dataclasses.replace(first, transition_resolution_created=True),
            dataclasses.replace(first, execution_allowed=True),
            dataclasses.replace(first, independent_reviewer_verified=False),
            dataclasses.replace(first, eligible_for_classification_review=False),
            dataclasses.replace(first, security_verdict="secure"),
        )
        for tampered in forged:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(ValueError, "live validated lineage"):
                    validate_future_security_classification_reviewer_preflight(
                        tampered,
                        classification_request.to_json(),
                        attestation,
                        sufficiency_preflight,
                        sufficiency_request,
                        review,
                        admission,
                        constraints,
                        sufficiency_verifier=sufficiency_verifier,
                        classification_reviewer=classification_reviewer,
                        candidate_context=candidate_context,
                        request=collection_request,
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
