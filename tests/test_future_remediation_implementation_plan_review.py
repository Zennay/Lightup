from __future__ import annotations

from dataclasses import replace
import json
import unittest

import test_future_remediation_implementation_plan_review_request_handoff as request_handoff_tests
import test_future_remediation_text_proposal as proposal_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_implementation_plan_review import (
    FutureRemediationImplementationPlanReview,
    RemediationImplementationPlanReviewDecision,
    REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_SCHEMA_VERSION,
    review_future_remediation_implementation_plan,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


def _review_json(
    decision: str = "approved",
    *,
    evidence_alignment: str = "pass",
    least_privilege: str = "pass",
    verification_separation: str = "pass",
    rollback_sufficiency: str = "pass",
    non_executable_scope: str = "pass",
    summary: str = (
        "The bounded implementation plan is evidence-aligned, least-privilege, "
        "reversible, and keeps later verification separate."
    ),
) -> str:
    return json.dumps(
        {
            "decision": decision,
            "check_results": {
                "evidence_alignment": evidence_alignment,
                "least_privilege": least_privilege,
                "verification_separation": verification_separation,
                "rollback_sufficiency": rollback_sufficiency,
                "non_executable_scope": non_executable_scope,
            },
            "summary": summary,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class FutureRemediationImplementationPlanReviewTest(unittest.TestCase):
    def setUp(self):
        self.base = (
            request_handoff_tests.
            FutureRemediationImplementationPlanReviewRequestHandoffTest(
                "test_json_and_dict_round_trip_require_live_plan_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review_request = self.base.request
        self.implementation_plan = self.base.base.base.plan

    def _review_gateway(self, content: str, **provider_kwargs):
        provider = proposal_tests.RecordingProvider(
            content,
            provider_id="implementation-plan-reviewer",
            **provider_kwargs,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            "implementation-plan-verifier-v1",
        )
        return gateway, provider

    def _review(self, gateway: ModelGateway):
        return review_future_remediation_implementation_plan(
            self.review_request.to_json(),
            self.implementation_plan.to_json(),
            self.base.base.base.planning_request.to_json(),
            self.base.base.base.base.review.to_json(),
            self.base.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.base.request,
            self.base.base.base.base.base.base.bundle,
            self.base.base.base.base.base.base.plan,
            self.base.base.base.base.base.base.report,
            self.base.base.base.base.base.base.preview,
            self.base.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.base.context,),
            self.base.base.base.base.base.base.state,
            gateway,
        )

    def test_all_pass_review_accepts_plan_without_action_authority(self):
        gateway, provider = self._review_gateway(_review_json())

        review = self._review(gateway)

        self.assertEqual(
            review.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_SCHEMA_VERSION,
        )
        self.assertEqual(
            review.decision,
            RemediationImplementationPlanReviewDecision.APPROVED,
        )
        self.assertTrue(review.implementation_plan_review_completed)
        self.assertTrue(review.implementation_plan_accepted)
        self.assertEqual(
            review.review_request_sha256,
            self.review_request.review_request_sha256,
        )
        self.assertEqual(review.plan_sha256, self.implementation_plan.plan_sha256)
        self.assertEqual(
            review.implementation_request_sha256,
            self.implementation_plan.implementation_request_sha256,
        )
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(review, field))
        self.assertEqual(review.future_semantics, "unresolved")
        self.assertEqual(review.security_verdict, "not_evaluated")
        self.assertEqual(len(review.review_sha256), 64)

        self.assertEqual(len(provider.requests), 1)
        model_request = provider.requests[0]
        self.assertEqual(model_request.role, ModelRole.VERIFIER)
        self.assertEqual(model_request.max_output_tokens, 900)
        self.assertIn(self.implementation_plan.summary, model_request.messages[1].content)
        self.assertEqual(
            dict(model_request.metadata)["plan_sha256"],
            self.implementation_plan.plan_sha256,
        )

    def test_decision_must_be_coherent_with_check_results(self):
        cases = (
            (
                _review_json(decision="approved", evidence_alignment="fail"),
                "every check to pass",
            ),
            (
                _review_json(decision="revision_required"),
                "requires a non-pass check",
            ),
            (
                _review_json(
                    decision="insufficient_evidence",
                    evidence_alignment="fail",
                ),
                "requires an unclear check",
            ),
        )
        for content, message in cases:
            with self.subTest(message=message):
                gateway, _ = self._review_gateway(content)
                with self.assertRaisesRegex(ValueError, message):
                    self._review(gateway)

    def test_revision_and_insufficient_evidence_never_accept_plan(self):
        cases = (
            _review_json(
                decision="revision_required",
                rollback_sufficiency="fail",
            ),
            _review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            ),
        )
        for content in cases:
            with self.subTest(content=content):
                gateway, _ = self._review_gateway(content)
                review = self._review(gateway)
                self.assertFalse(review.implementation_plan_accepted)
                for field in _AUTHORITY_FLAGS:
                    self.assertFalse(getattr(review, field))
                self.assertEqual(review.security_verdict, "not_evaluated")

    def test_duplicate_and_invalid_reviewer_json_fail_closed(self):
        raw = _review_json()
        duplicate = raw[:-1] + ',"summary":"forged"}'
        gateway, _ = self._review_gateway(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self._review(gateway)

        payload = json.loads(_review_json())
        payload["check_results"]["unexpected"] = "pass"
        gateway, _ = self._review_gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        with self.assertRaisesRegex(ValueError, "check_results mismatch"):
            self._review(gateway)

        gateway, _ = self._review_gateway(
            _review_json(decision="not-a-decision")
        )
        with self.assertRaisesRegex(ValueError, "decision is invalid"):
            self._review(gateway)

    def test_summary_is_bounded_nul_free_and_canonicalized(self):
        for summary, message in (
            (" ", "non-empty"),
            ("safe\x00unsafe", "contains NUL"),
            ("x" * 4001, "bounded size"),
        ):
            with self.subTest(message=message):
                gateway, _ = self._review_gateway(_review_json(summary=summary))
                with self.assertRaisesRegex(ValueError, message):
                    self._review(gateway)

        clean_gateway, _ = self._review_gateway(_review_json(summary="bounded"))
        padded_gateway, _ = self._review_gateway(
            _review_json(summary="  bounded  ")
        )
        clean = self._review(clean_gateway)
        padded = self._review(padded_gateway)
        self.assertEqual(clean.summary, padded.summary)
        self.assertEqual(clean.review_sha256, padded.review_sha256)

    def test_live_evidence_drift_fails_before_reviewer_invocation(self):
        gateway, provider = self._review_gateway(_review_json())
        evidence = self.base.base.base.base.base.base.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        with self.assertRaises(ValueError):
            self._review(gateway)

        self.assertEqual(provider.requests, [])

    def test_reviewer_model_identity_substitution_is_rejected(self):
        gateway, provider = self._review_gateway(
            _review_json(),
            response_model_id="unexpected-verifier",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._review(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_same_review_and_lineage_produce_same_digest(self):
        first_gateway, _ = self._review_gateway(_review_json())
        second_gateway, _ = self._review_gateway(_review_json())

        first = self._review(first_gateway)
        second = self._review(second_gateway)

        self.assertEqual(first.review_sha256, second.review_sha256)
        self.assertEqual(first.to_json(), second.to_json())

    def test_reviewer_context_remains_bounded_and_payload_free(self):
        gateway, provider = self._review_gateway(_review_json())
        self._review(gateway)

        content = provider.requests[0].messages[1].content.lower()
        self.assertIn(self.implementation_plan.plan_sha256, content)
        self.assertIn(self.implementation_plan.summary.lower(), content)
        for forbidden in (
            '"patch"',
            '"command"',
            '"tool_arguments"',
            '"target_arguments"',
            '"credentials"',
            '"source"',
            '"metadata"',
            '"authorization_ref"',
        ):
            self.assertNotIn(forbidden, content)

    def test_direct_construction_rejects_authority_and_acceptance_forgery(self):
        gateway, _ = self._review_gateway(_review_json())
        review = self._review(gateway)

        with self.assertRaisesRegex(ValueError, "accepted mismatch"):
            replace(review, implementation_plan_accepted=False)
        with self.assertRaisesRegex(ValueError, "review_completed"):
            replace(review, implementation_plan_review_completed=False)
        with self.assertRaisesRegex(ValueError, "future_semantics"):
            replace(review, future_semantics="resolved")
        with self.assertRaisesRegex(ValueError, "security_verdict"):
            replace(review, security_verdict="pass")

        for field in _AUTHORITY_FLAGS:
            for value in (True, 0):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, "authority flag"):
                        replace(review, **{field: value})

    def test_direct_construction_rejects_digest_and_check_drift(self):
        gateway, _ = self._review_gateway(_review_json())
        review = self._review(gateway)

        alternate = (
            "0" * 64 if review.plan_sha256 != "0" * 64 else "f" * 64
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(review, plan_sha256=alternate)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(review, reviewer_model_id="forged-model")

        forged_checks = list(review.checks)
        forged_checks[0] = replace(forged_checks[0], check="forged")
        with self.assertRaisesRegex(ValueError, "order or name mismatch"):
            replace(review, checks=tuple(forged_checks))

        with self.assertRaisesRegex(ValueError, "decision must be"):
            replace(review, decision="approved")

    def test_canonical_dict_reconstructs_exact_review(self):
        gateway, _ = self._review_gateway(_review_json())
        review = self._review(gateway)

        reconstructed = FutureRemediationImplementationPlanReview(
            schema_version=review.schema_version,
            review_request_sha256=review.review_request_sha256,
            plan_sha256=review.plan_sha256,
            implementation_request_sha256=review.implementation_request_sha256,
            reviewer_provider_id=review.reviewer_provider_id,
            reviewer_model_id=review.reviewer_model_id,
            decision=review.decision,
            checks=review.checks,
            summary=review.summary,
            review_sha256=review.review_sha256,
            implementation_plan_review_completed=(
                review.implementation_plan_review_completed
            ),
            implementation_plan_accepted=review.implementation_plan_accepted,
        )
        self.assertEqual(reconstructed, review)


if __name__ == "__main__":
    unittest.main()
