"""#771: exact outer ExecutionRequest admission on the frozen #163 source owner.

All objects are synthetic and in-memory. The expected failures describe OPEN source
authorization defects; they are not evidence of a fixed or safe production gate.
"""
import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, ScopeDefinition, RiskLevel
from lightup.execution_policy import (
    ExecutionPolicy, ExecutionRequest, InteractionKind, PolicyDecision,
)


class DuckRequest:
    """A non-ExecutionRequest that happens to expose the same attributes."""
    def __init__(self, interaction=InteractionKind.ANALYSIS, risk=RiskLevel.ANALYSIS_ONLY):
        self.interaction = interaction
        self.requested_risk = risk
        self.is_lab = False


class SubclassRequest(ExecutionRequest):
    """Frozen dataclass subclass is not the trusted exact envelope."""
    pass


class AttributeSpyRequest:
    """An untrusted getter must not run before outer-envelope rejection."""
    def __init__(self):
        self.reads = 0

    @property
    def interaction(self):
        self.reads += 1
        return InteractionKind.ANALYSIS

    @property
    def requested_risk(self):
        self.reads += 1
        return RiskLevel.ANALYSIS_ONLY

    @property
    def is_lab(self):
        self.reads += 1
        return False


class CanonicalExecutionRequestOwner163Contract(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="fictional-grant", client_id="fictional-client",
            engagement_id="fictional-engagement", approved_by="offline@example.test",
            reference="fictional-reviewed-authority",
            scope=ScopeDefinition(assets=("fictional.example.test",),
                                  max_risk=RiskLevel.STANDARD,
                                  allowed_capabilities=("offline-only",)),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=30),
        )

    def target_kwargs(self, grant=None):
        return dict(interaction=InteractionKind.TARGET_ACTIVE,
                    asset="fictional.example.test", capability_id="offline-only",
                    requested_risk=RiskLevel.LOW_IMPACT,
                    authorization=self.grant if grant is None else grant,
                    client_id="fictional-client",
                    engagement_id="fictional-engagement")

    def assert_denied(self, candidate):
        # A returned denial is required; raising is not a compliant fail-closed
        # PolicyDecision and must not be hidden by a broad assertRaises.
        decision = self.policy.decide(candidate)
        self.assertIs(type(decision), PolicyDecision)
        self.assertIs(decision.allowed, False)

    def assert_untrusted_envelope_denied(self, candidate, source_marker):
        decision = self.policy.decide(candidate)
        self.assertIs(type(decision), PolicyDecision)
        if decision.allowed is True:
            self.fail(source_marker)
        self.assertIs(decision.allowed, False)

    def test_exact_analysis_stays_allowed(self):
        req = ExecutionRequest(InteractionKind.ANALYSIS, "fictional.example.test",
                               "offline-only", RiskLevel.ANALYSIS_ONLY)
        before = repr(req)
        decision = self.policy.decide(req)
        self.assertIs(type(decision), PolicyDecision)
        self.assertTrue(decision.allowed)
        self.assertEqual(repr(req), before)

    def test_exact_passive_stays_allowed(self):
        req = ExecutionRequest(InteractionKind.PASSIVE_PUBLIC, "fictional.example.test",
                               "offline-only", RiskLevel.PASSIVE)
        self.assertTrue(self.policy.decide(req).allowed)

    def test_exact_lab_marker_false_denied(self):
        req = ExecutionRequest(InteractionKind.LAB_ACTIVE, "lab.invalid",
                               "offline-only", RiskLevel.STANDARD, is_lab=False)
        self.assert_denied(req)

    def test_exact_lab_marker_true_remains_owner_behavior(self):
        req = ExecutionRequest(InteractionKind.LAB_ACTIVE, "lab.invalid",
                               "offline-only", RiskLevel.STANDARD, is_lab=True)
        self.assertTrue(self.policy.decide(req).allowed)

    def test_exact_target_active_without_grant_denied(self):
        req = ExecutionRequest(InteractionKind.TARGET_ACTIVE, "fictional.example.test",
                               "offline-only", RiskLevel.LOW_IMPACT)
        self.assert_denied(req)

    def test_exact_target_active_valid_fictional_grant_preserved(self):
        req = ExecutionRequest(**self.target_kwargs())
        self.assertTrue(self.policy.decide(req).allowed)

    def test_exact_target_active_revoked_grant_denied(self):
        revoked = replace(self.grant, revoked_at=datetime.now(timezone.utc),
                          revoked_by="fictional-operator")
        req = ExecutionRequest(**self.target_kwargs(revoked))
        self.assert_denied(req)

    def test_exact_target_active_wrong_client_denied(self):
        req = ExecutionRequest(**{**self.target_kwargs(),
                                  "client_id": "other-fictional-client"})
        self.assert_denied(req)

    @unittest.expectedFailure
    def test_red_duck_target_active_with_grant_must_be_denied(self):
        duck = DuckRequest(InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT)
        for key, value in self.target_kwargs().items():
            setattr(duck, key, value)
        self.assert_untrusted_envelope_denied(
            duck, "SOURCE_RED_DUCK_VALID_GRANT_TARGET_ADMITTED")

    @unittest.expectedFailure
    def test_red_subclass_target_active_with_grant_must_be_denied(self):
        self.assert_untrusted_envelope_denied(
            SubclassRequest(**self.target_kwargs()),
            "SOURCE_RED_SUBCLASS_VALID_GRANT_TARGET_ADMITTED")

    @unittest.expectedFailure
    def test_red_object_without_members_returns_denial_not_exception(self):
        try:
            decision = self.policy.decide(object())
        except AttributeError:
            self.fail("SOURCE_RED_NONREQUEST_ATTRIBUTE_ERROR")
        self.assertIs(type(decision), PolicyDecision)
        self.assertIs(decision.allowed, False)

    @unittest.expectedFailure
    def test_red_duck_analysis_must_be_denied(self):
        self.assert_untrusted_envelope_denied(
            DuckRequest(), "SOURCE_RED_DUCK_ANALYSIS_ADMITTED")

    @unittest.expectedFailure
    def test_red_duck_passive_must_be_denied(self):
        self.assert_untrusted_envelope_denied(
            DuckRequest(InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE),
            "SOURCE_RED_DUCK_PASSIVE_ADMITTED")

    @unittest.expectedFailure
    def test_red_subclass_analysis_must_be_denied(self):
        self.assert_untrusted_envelope_denied(
            SubclassRequest(InteractionKind.ANALYSIS, "fictional.example.test",
                            "offline-only", RiskLevel.ANALYSIS_ONLY),
            "SOURCE_RED_SUBCLASS_ANALYSIS_ADMITTED")

    @unittest.expectedFailure
    def test_red_subclass_lab_must_be_denied_even_with_true_marker(self):
        self.assert_untrusted_envelope_denied(
            SubclassRequest(InteractionKind.LAB_ACTIVE, "lab.invalid",
                            "offline-only", RiskLevel.STANDARD, is_lab=True),
            "SOURCE_RED_SUBCLASS_LAB_ADMITTED")

    @unittest.expectedFailure
    def test_red_no_untrusted_property_read_before_outer_validation(self):
        candidate = AttributeSpyRequest()
        decision = self.policy.decide(candidate)
        self.assertIs(type(decision), PolicyDecision)
        if candidate.reads:
            self.fail("SOURCE_RED_UNTRUSTED_GETTER_READ")
        self.assertIs(decision.allowed, False)

    def test_expected_red_replay_oracle(self):
        names = sorted(n for n in dir(type(self)) if n.startswith("test_red_"))
        self.assertEqual(len(names), 8)
        runner = unittest.TestSuite(type(self)(name) for name in names)
        result = unittest.TestResult()
        runner.run(result)
        self.assertEqual(result.testsRun, 8)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.unexpectedSuccesses, [],
                         "source changed: promote fixed cases to ordinary assertions")
        self.assertEqual(len(result.expectedFailures), 8,
                         "each of eight owner-source defects must be genuinely reproduced")
        markers = {
            "test_red_duck_target_active_with_grant_must_be_denied":
                "SOURCE_RED_DUCK_VALID_GRANT_TARGET_ADMITTED",
            "test_red_subclass_target_active_with_grant_must_be_denied":
                "SOURCE_RED_SUBCLASS_VALID_GRANT_TARGET_ADMITTED",
            "test_red_object_without_members_returns_denial_not_exception":
                "SOURCE_RED_NONREQUEST_ATTRIBUTE_ERROR",
            "test_red_duck_analysis_must_be_denied":
                "SOURCE_RED_DUCK_ANALYSIS_ADMITTED",
            "test_red_duck_passive_must_be_denied":
                "SOURCE_RED_DUCK_PASSIVE_ADMITTED",
            "test_red_subclass_analysis_must_be_denied":
                "SOURCE_RED_SUBCLASS_ANALYSIS_ADMITTED",
            "test_red_subclass_lab_must_be_denied_even_with_true_marker":
                "SOURCE_RED_SUBCLASS_LAB_ADMITTED",
            "test_red_no_untrusted_property_read_before_outer_validation":
                "SOURCE_RED_UNTRUSTED_GETTER_READ",
        }
        self.assertEqual(set(names), set(markers))
        for case, traceback_text in result.expectedFailures:
            self.assertIn("AssertionError: " + markers[case._testMethodName],
                          traceback_text,
                          "unexpected crash cannot count as intentional source RED")


if __name__ == "__main__":
    unittest.main()
