"""#771: exact outer ExecutionRequest admission on the frozen #163 source owner.

All objects are synthetic and in-memory. The expected failures describe OPEN source
authorization defects; they are not evidence of a fixed or safe production gate.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel
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

    def assert_denied(self, candidate):
        # A returned denial is required; raising is not a compliant fail-closed
        # PolicyDecision and must not be hidden by a broad assertRaises.
        decision = self.policy.decide(candidate)
        self.assertIs(type(decision), PolicyDecision)
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

    @unittest.expectedFailure
    def test_red_duck_analysis_must_be_denied(self):
        self.assert_denied(DuckRequest())

    @unittest.expectedFailure
    def test_red_duck_passive_must_be_denied(self):
        self.assert_denied(DuckRequest(InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE))

    @unittest.expectedFailure
    def test_red_subclass_analysis_must_be_denied(self):
        self.assert_denied(SubclassRequest(InteractionKind.ANALYSIS, "fictional.example.test",
                                          "offline-only", RiskLevel.ANALYSIS_ONLY))

    @unittest.expectedFailure
    def test_red_subclass_lab_must_be_denied_even_with_true_marker(self):
        self.assert_denied(SubclassRequest(InteractionKind.LAB_ACTIVE, "lab.invalid",
                                          "offline-only", RiskLevel.STANDARD, is_lab=True))

    @unittest.expectedFailure
    def test_red_no_untrusted_property_read_before_outer_validation(self):
        candidate = AttributeSpyRequest()
        self.assert_denied(candidate)
        self.assertEqual(candidate.reads, 0, "untrusted getter ran before admission")

    def test_red_count_oracle_requires_all_real_source_failures(self):
        names = sorted(n for n in dir(type(self)) if n.startswith("test_red_")
                       and n != "test_red_count_oracle_requires_all_real_source_failures")
        self.assertEqual(len(names), 5)
        runner = unittest.TestSuite(type(self)(name) for name in names)
        result = unittest.TestResult()
        runner.run(result)
        self.assertEqual(result.testsRun, 5)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.unexpectedSuccesses, [],
                         "source changed: promote fixed cases to ordinary assertions")
        self.assertEqual(len(result.expectedFailures), 5,
                         "each of five owner-source defects must be genuinely reproduced")


if __name__ == "__main__":
    unittest.main()
