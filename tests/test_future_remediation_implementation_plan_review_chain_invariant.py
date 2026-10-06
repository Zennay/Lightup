from __future__ import annotations

import json
import unittest

import test_future_remediation_implementation_plan_review as review_tests
import test_future_remediation_implementation_plan_review_handoff as handoff_tests


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationImplementationPlanReviewChainInvariantTest(unittest.TestCase):
    def setUp(self):
        self.handoff = (
            handoff_tests.FutureRemediationImplementationPlanReviewHandoffTest(
                "test_approved_review_round_trips_without_action_authority"
            )
        )
        self.handoff.setUp()
        self.addCleanup(self.handoff.tearDown)
        self.base = self.handoff.base

    def _produce_and_load(self, content: str):
        gateway, provider = self.base._review_gateway(content)
        review = self.base._review(gateway)
        loaded = self.handoff._load(persisted=review.to_json())
        return review, loaded, provider

    def _assert_non_executable(self, review, *, accepted: bool):
        self.assertTrue(review.implementation_plan_review_completed)
        self.assertIs(review.implementation_plan_accepted, accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertIs(getattr(review, field), False, field)
        self.assertEqual(review.future_semantics, "unresolved")
        self.assertEqual(review.security_verdict, "not_evaluated")

    def test_approved_review_advances_acceptance_only(self):
        review, loaded, provider = self._produce_and_load(
            review_tests._review_json()
        )

        self._assert_non_executable(review, accepted=True)
        self._assert_non_executable(loaded, accepted=True)
        self.assertEqual(loaded, review)
        self.assertEqual(len(provider.requests), 1)

    def test_non_approved_outcomes_never_gain_action_authority(self):
        cases = (
            review_tests._review_json(
                decision="revision_required",
                rollback_sufficiency="fail",
            ),
            review_tests._review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            ),
        )
        for content in cases:
            with self.subTest(content=content):
                review, loaded, _ = self._produce_and_load(content)
                self._assert_non_executable(review, accepted=False)
                self._assert_non_executable(loaded, accepted=False)

    def test_review_and_reload_do_not_mutate_upstream_planning_artifacts(self):
        planning_request = self.base.base.base.base.base.planning_request
        remediation_review = self.base.base.base.base.base.base.review
        review_request = self.base.review_request
        implementation_plan = self.base.implementation_plan

        before = tuple(
            artifact.to_json()
            for artifact in (
                planning_request,
                remediation_review,
                review_request,
                implementation_plan,
            )
        )

        review, loaded, _ = self._produce_and_load(review_tests._review_json())

        after = tuple(
            artifact.to_json()
            for artifact in (
                planning_request,
                remediation_review,
                review_request,
                implementation_plan,
            )
        )
        self.assertEqual(after, before)
        self._assert_non_executable(review, accepted=True)
        self._assert_non_executable(loaded, accepted=True)

    def test_persisted_review_contains_no_executable_payload_surface(self):
        review, loaded, _ = self._produce_and_load(review_tests._review_json())
        payload = json.loads(loaded.to_json())

        self.assertIs(payload["implementation_plan_accepted"], True)
        for field in _AUTHORITY_FLAGS:
            self.assertIs(payload[field], False)

        serialized = loaded.to_json().lower()
        for forbidden in (
            '"command"',
            '"commands"',
            '"patch"',
            '"code"',
            '"tool_arguments"',
            '"target_arguments"',
            '"credentials"',
            '"deployment_plan"',
            '"retest_result"',
            '"security_verdict":"pass"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_acceptance_boolean_cannot_be_reinterpreted_as_authority(self):
        _, loaded, _ = self._produce_and_load(review_tests._review_json())
        payload = json.loads(loaded.to_json())

        self.assertIs(payload["implementation_plan_accepted"], True)
        self.assertTrue(
            all(payload[field] is False for field in _AUTHORITY_FLAGS)
        )
        self.assertEqual(payload["future_semantics"], "unresolved")
        self.assertEqual(payload["security_verdict"], "not_evaluated")


    def test_verifier_keeps_plan_content_in_untrusted_user_channel(self):
        gateway, provider = self.base._review_gateway(review_tests._review_json())
        review = self.base._review(gateway)

        self.assertEqual(len(provider.requests), 1)
        request = provider.requests[0]
        system = request.messages[0].content.lower()
        user = request.messages[1].content

        self.assertIn("untrusted data", system)
        for guard in (
            "do not invoke tools",
            "generate code",
            "patches",
            "commands",
            "perform a retest",
            "authorize deployment",
            "security verdict",
        ):
            self.assertIn(guard, system)

        self.assertNotIn(self.base.implementation_plan.summary, request.messages[0].content)
        self.assertIn(self.base.implementation_plan.summary, user)

        payload = json.loads(user)
        self.assertEqual(
            payload["plan_sha256"],
            self.base.implementation_plan.plan_sha256,
        )
        for forbidden_key in (
            "command",
            "commands",
            "patch",
            "code",
            "tool_arguments",
            "target_arguments",
            "credentials",
        ):
            self.assertNotIn(forbidden_key, payload)

        self._assert_non_executable(review, accepted=True)


if __name__ == "__main__":
    unittest.main()
