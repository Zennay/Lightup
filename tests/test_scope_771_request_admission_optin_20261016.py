"""Real offline acceptance for the opt-in #771 exact outer request boundary.

Exercises original installed owner policy only with imaginary in-memory data.
No handler, network, scan, permit or real customer authorization is created.
"""
import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import (
    ExecutionPolicy, ExecutionRequest, InteractionKind, PolicyDecision,
)
from lightup.scope_771_request_admission_optin import decide_exact_execution_request


class DuckWithPoisonGetters:
    def __init__(self):
        self.reads = 0

    def __getattribute__(self, name):
        if name == "interaction":
            object.__setattr__(self, "reads", object.__getattribute__(self, "reads") + 1)
            raise AssertionError("untrusted request getter must not be called")
        return object.__getattribute__(self, name)


class UntrustedRequestSubclass(ExecutionRequest):
    def __getattribute__(self, name):
        if name == "interaction":
            raise AssertionError("subclass getter must never be called")
        return object.__getattribute__(self, name)


class UntrustedPolicySubclass(ExecutionPolicy):
    def decide(self, request):
        raise AssertionError("subclass policy method must never be called")


class SpyPolicy:
    def __init__(self):
        self.called = False

    def decide(self, request):
        self.called = True
        raise AssertionError("duck policy method must never be called")


class ExactExecutionRequestOptinAcceptance(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="fictional-grant", client_id="fictional-client",
            engagement_id="fictional-engagement", approved_by="offline@example.test",
            reference="fictional-offline-review",
            scope=ScopeDefinition(
                assets=("fictional.example.test",), max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("offline-only",)
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(minutes=10),
        )

    def assert_deny(self, request, policy=None):
        decision = decide_exact_execution_request(
            self.policy if policy is None else policy, request
        )
        self.assertIs(type(decision), PolicyDecision)
        self.assertIs(decision.allowed, False)
        return decision

    def target(self, **updates):
        kwargs = dict(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="fictional.example.test", capability_id="offline-only",
            requested_risk=RiskLevel.LOW_IMPACT, authorization=self.grant,
            client_id="fictional-client", engagement_id="fictional-engagement",
        )
        kwargs.update(updates)
        return ExecutionRequest(**kwargs)

    def test_exact_analysis_preserved(self):
        request = ExecutionRequest(
            InteractionKind.ANALYSIS, "fictional.example.test",
            "offline-only", RiskLevel.ANALYSIS_ONLY
        )
        decision = decide_exact_execution_request(self.policy, request)
        self.assertIs(type(decision), PolicyDecision)
        self.assertIs(decision.allowed, True)
        self.assertEqual(decision, self.policy.decide(request))

    def test_exact_passive_preserved(self):
        request = ExecutionRequest(
            InteractionKind.PASSIVE_PUBLIC, "fictional.example.test",
            "offline-only", RiskLevel.PASSIVE
        )
        self.assertIs(decide_exact_execution_request(self.policy, request).allowed, True)

    def test_exact_lab_bool_true_preserved(self):
        request = ExecutionRequest(
            InteractionKind.LAB_ACTIVE, "lab.invalid",
            "offline-only", RiskLevel.STANDARD, is_lab=True
        )
        self.assertIs(decide_exact_execution_request(self.policy, request).allowed, True)

    def test_exact_lab_false_stays_denied(self):
        self.assert_deny(ExecutionRequest(
            InteractionKind.LAB_ACTIVE, "lab.invalid",
            "offline-only", RiskLevel.STANDARD, is_lab=False
        ))

    def test_exact_lab_truthy_nonbool_stays_denied(self):
        self.assert_deny(ExecutionRequest(
            InteractionKind.LAB_ACTIVE, "lab.invalid",
            "offline-only", RiskLevel.STANDARD, is_lab="true"
        ))

    def test_exact_analysis_noncanonical_risk_denied(self):
        self.assert_deny(ExecutionRequest(
            InteractionKind.ANALYSIS, "fictional.example.test",
            "offline-only", "analysis_only"
        ))

    def test_exact_analysis_overrisk_stays_denied(self):
        self.assert_deny(ExecutionRequest(
            InteractionKind.ANALYSIS, "fictional.example.test",
            "offline-only", RiskLevel.STANDARD
        ))

    def test_exact_passive_overrisk_stays_denied(self):
        self.assert_deny(ExecutionRequest(
            InteractionKind.PASSIVE_PUBLIC, "fictional.example.test",
            "offline-only", RiskLevel.STANDARD
        ))

    def test_valid_fictional_target_grant_preserved(self):
        request = self.target()
        previous = repr(request)
        decision = decide_exact_execution_request(self.policy, request)
        self.assertIs(decision.allowed, True)
        self.assertEqual(decision, self.policy.decide(request))
        self.assertEqual(repr(request), previous)

    def test_missing_fictional_grant_stays_denied(self):
        self.assert_deny(self.target(authorization=None))

    def test_revoked_fictional_grant_stays_denied(self):
        self.assert_deny(self.target(authorization=replace(
            self.grant, revoked_at=datetime.now(timezone.utc),
            revoked_by="fictional-offline-operator"
        )))

    def test_expired_fictional_grant_stays_denied(self):
        self.assert_deny(self.target(authorization=replace(
            self.grant, valid_until=datetime.now(timezone.utc) - timedelta(seconds=1)
        )))

    def test_wrong_client_stays_denied(self):
        self.assert_deny(self.target(client_id="other-fictional-client"))

    def test_wrong_engagement_stays_denied(self):
        self.assert_deny(self.target(engagement_id="other-fictional-engagement"))

    def test_wrong_asset_stays_denied(self):
        self.assert_deny(self.target(asset="not-authorized.example.test"))

    def test_wrong_capability_stays_denied(self):
        self.assert_deny(self.target(capability_id="not-in-fictitious-grant"))

    def test_excess_risk_stays_denied(self):
        self.assert_deny(self.target(requested_risk=RiskLevel.ELEVATED))

    def test_nonrequest_object_is_controlled_deny(self):
        self.assert_deny(object())

    def test_none_request_is_controlled_deny(self):
        self.assert_deny(None)

    def test_duck_request_getters_never_read(self):
        request = DuckWithPoisonGetters()
        self.assert_deny(request)
        self.assertEqual(request.reads, 0)

    def test_subclass_with_poison_getter_never_read(self):
        self.assert_deny(UntrustedRequestSubclass(
            InteractionKind.ANALYSIS, "fictional.example.test",
            "offline-only", RiskLevel.ANALYSIS_ONLY
        ))

    def test_plain_subclass_is_denied_even_without_override(self):
        class PlainSubclass(ExecutionRequest):
            pass
        self.assert_deny(PlainSubclass(
            InteractionKind.ANALYSIS, "fictional.example.test",
            "offline-only", RiskLevel.ANALYSIS_ONLY
        ))

    def test_subclass_of_policy_is_denied_before_method_dispatch(self):
        request = self.target()
        self.assert_deny(request, policy=UntrustedPolicySubclass())

    def test_duck_policy_is_denied_before_method_dispatch(self):
        policy = SpyPolicy()
        self.assert_deny(self.target(), policy=policy)
        self.assertIs(policy.called, False)

    def test_none_policy_returns_canonical_denial(self):
        request = self.target()
        result = decide_exact_execution_request(None, request)
        self.assertIs(type(result), PolicyDecision)
        self.assertIs(result.allowed, False)

    def test_denial_does_not_mutate_exact_request_or_grant(self):
        request = self.target(client_id="other-fictional-client")
        before = (repr(request), repr(self.grant))
        self.assert_deny(request)
        self.assertEqual((repr(request), repr(self.grant)), before)


if __name__ == "__main__":
    unittest.main()
