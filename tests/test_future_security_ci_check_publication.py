from __future__ import annotations

import dataclasses
import unittest

import test_future_security_ci_verdict as verdict_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_ci_check_publication import (
    GitHubCheckPublicationAuthorization,
    build_github_check_publication_request,
    publish_future_security_ci_verdict_check,
)
from lightup.future_security_ci_verdict import (
    FutureSecurityCIVerdictPolicy,
    SecurityCIVerdict,
)


class FakeGitHubCheckPublisher:
    def __init__(self):
        self.calls = 0
        self.requests = {}
        self.receipts = {}

    def publish_once(self, request):
        if request.external_id not in self.receipts:
            self.calls += 1
            self.requests[request.external_id] = request
            self.receipts[request.external_id] = (
                f"fake-check:{request.request_sha256[:16]}"
            )
        return self.receipts[request.external_id]


class FutureSecurityCICheckPublicationTest(unittest.TestCase):
    REPOSITORY = "Zennay/Lightup"
    SOURCE_SHA = "a" * 40

    def setUp(self):
        self.v = verdict_tests.FutureSecurityCIVerdictTest(
            "test_improved_delta_passes_under_strict_default"
        )
        self.v.setUp()
        self.addCleanup(self.v.tearDown)
        self.publisher = FakeGitHubCheckPublisher()

    def _fixture(self, classification, *, suffix, policy=None):
        active_policy = policy or self.v.policy
        (
            _current,
            proposal,
            context,
            resolution,
            preview,
            report,
            graph_policy,
            decision,
        ) = self.v._verdict(
            classification,
            suffix=suffix,
            policy=active_policy,
        )
        authorization = GitHubCheckPublicationAuthorization(
            client_id=decision.client_id,
            repository=self.REPOSITORY,
            source_sha=self.SOURCE_SHA,
            verdict_sha256=decision.verdict_sha256,
            reporting_allowed=True,
        )
        return {
            "decision": decision,
            "report": report,
            "graph_diff_policy_decision": graph_policy,
            "policy": active_policy,
            "preview": preview,
            "proposal": proposal,
            "resolutions": (resolution,),
            "contexts": (context,),
            "state": self.v.state,
            "authorization": authorization,
            "repository": self.REPOSITORY,
            "source_sha": self.SOURCE_SHA,
        }

    def test_all_four_verdicts_map_to_exact_github_check_conclusions(self):
        cases = (
            (
                AttackPathTransitionClassification.IMPROVED,
                self.v.policy,
                SecurityCIVerdict.PASS,
                "success",
                "pub-pass",
            ),
            (
                AttackPathTransitionClassification.INTRODUCED,
                FutureSecurityCIVerdictPolicy(
                    policy_id="warning",
                    policy_version=1,
                    introduced=SecurityCIVerdict.PASS_WITH_WARNING,
                ),
                SecurityCIVerdict.PASS_WITH_WARNING,
                "neutral",
                "pub-warning",
            ),
            (
                AttackPathTransitionClassification.INTRODUCED,
                FutureSecurityCIVerdictPolicy(
                    policy_id="review",
                    policy_version=1,
                    introduced=SecurityCIVerdict.REVIEW_REQUIRED,
                ),
                SecurityCIVerdict.REVIEW_REQUIRED,
                "action_required",
                "pub-review",
            ),
            (
                AttackPathTransitionClassification.INTRODUCED,
                self.v.policy,
                SecurityCIVerdict.BLOCK,
                "failure",
                "pub-block",
            ),
        )

        for classification, policy, verdict, conclusion, suffix in cases:
            with self.subTest(verdict=verdict.value):
                inputs = self._fixture(
                    classification,
                    suffix=suffix,
                    policy=policy,
                )
                request = build_github_check_publication_request(**inputs)
                self.assertEqual(request.verdict, verdict.value)
                self.assertEqual(request.conclusion, conclusion)
                self.assertFalse(request.merge_authorized)
                self.assertFalse(request.deployment_authorized)
                self.assertEqual(len(request.request_sha256), 64)
                self.assertTrue(request.external_id.startswith("lightup:"))

    def test_stale_source_sha_fails_before_publisher_call(self):
        inputs = self._fixture(
            AttackPathTransitionClassification.IMPROVED,
            suffix="pub-stale-sha",
        )
        inputs["source_sha"] = "b" * 40

        with self.assertRaisesRegex(ValueError, "authorization source SHA"):
            publish_future_security_ci_verdict_check(
                publisher=self.publisher,
                **inputs,
            )
        self.assertEqual(self.publisher.calls, 0)

    def test_reporting_requires_explicit_non_merge_non_deploy_authorization(self):
        inputs = self._fixture(
            AttackPathTransitionClassification.IMPROVED,
            suffix="pub-auth",
        )
        auth = inputs["authorization"]
        inputs["authorization"] = dataclasses.replace(
            auth,
            reporting_allowed=False,
        )
        with self.assertRaisesRegex(ValueError, "reporting is not authorized"):
            publish_future_security_ci_verdict_check(
                publisher=self.publisher,
                **inputs,
            )

        inputs["authorization"] = dataclasses.replace(
            auth,
            merge_allowed=True,
        )
        with self.assertRaisesRegex(ValueError, "must not grant merge"):
            publish_future_security_ci_verdict_check(
                publisher=self.publisher,
                **inputs,
            )
        self.assertEqual(self.publisher.calls, 0)

    def test_tampered_verdict_is_live_revalidated_and_rejected(self):
        inputs = self._fixture(
            AttackPathTransitionClassification.IMPROVED,
            suffix="pub-tampered",
        )
        decision = dataclasses.replace(
            inputs["decision"],
            verdict_sha256="0" * 64,
        )
        inputs["decision"] = decision
        inputs["authorization"] = dataclasses.replace(
            inputs["authorization"],
            verdict_sha256=decision.verdict_sha256,
        )

        with self.assertRaisesRegex(ValueError, "CI verdict is stale"):
            publish_future_security_ci_verdict_check(
                publisher=self.publisher,
                **inputs,
            )
        self.assertEqual(self.publisher.calls, 0)

    def test_replay_is_idempotent_for_repository_sha_and_verdict_digest(self):
        inputs = self._fixture(
            AttackPathTransitionClassification.REMOVED,
            suffix="pub-replay",
        )

        first = publish_future_security_ci_verdict_check(
            publisher=self.publisher,
            **inputs,
        )
        second = publish_future_security_ci_verdict_check(
            publisher=self.publisher,
            **inputs,
        )

        self.assertEqual(first, second)
        self.assertEqual(self.publisher.calls, 1)
        self.assertEqual(first.repository, self.REPOSITORY)
        self.assertEqual(first.source_sha, self.SOURCE_SHA)
        self.assertEqual(first.verdict_sha256, inputs["decision"].verdict_sha256)
        self.assertFalse(first.merge_authorized)
        self.assertFalse(first.deployment_authorized)


if __name__ == "__main__":
    unittest.main()
