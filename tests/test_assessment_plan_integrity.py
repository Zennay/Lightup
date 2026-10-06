import unittest
from unittest.mock import patch

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.orchestrator import AssessmentPlan
from lightup.scope import ScopeDecision, ScopeReason


class AssessmentPlanIntegrityTest(unittest.TestCase):
    def test_direct_plan_rejects_execution_authority(self):
        with self.assertRaises(ValueError):
            AssessmentPlan(
                "127.0.0.1",
                ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK),
                ("web-baseline",),
                execution_enabled=True,
            )

    def test_direct_plan_rejects_non_boolean_execution_flag(self):
        with self.assertRaises(ValueError):
            AssessmentPlan(
                "127.0.0.1",
                ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK),
                ("web-baseline",),
                execution_enabled=0,
            )

    def test_direct_plan_rejects_unknown_capability(self):
        with self.assertRaisesRegex(ValueError, "unknown capability ID"):
            AssessmentPlan(
                "127.0.0.1",
                ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK),
                ("not-in-registry",),
            )

    def test_direct_plan_rejects_duplicate_capability(self):
        with self.assertRaisesRegex(ValueError, "duplicate capability"):
            AssessmentPlan(
                "127.0.0.1",
                ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK),
                ("web-baseline", "web-baseline"),
            )

    def test_direct_plan_rejects_disabled_capability(self):
        disabled = Capability(
            "disabled-test",
            "Disabled test",
            "Disabled capability fixture",
            CapabilityState.DISABLED,
        )
        with patch(
            "lightup.orchestrator.get_capabilities",
            return_value=get_capabilities() + (disabled,),
        ):
            with self.assertRaisesRegex(ValueError, "disabled capability"):
                AssessmentPlan(
                    "127.0.0.1",
                    ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK),
                    ("disabled-test",),
                )

    def test_public_scope_rejects_lab_only_capability(self):
        with self.assertRaisesRegex(ValueError, "lab-only capability"):
            AssessmentPlan(
                "security.example.test",
                ScopeDecision(True, "security.example.test", ScopeReason.EXPLICIT_HOST),
                ("wireless-lab",),
            )

    def test_denied_scope_rejects_capabilities(self):
        with self.assertRaisesRegex(ValueError, "denied assessment plans"):
            AssessmentPlan(
                "8.8.8.8",
                ScopeDecision(False, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
                ("web-baseline",),
            )

    def test_incoherent_scope_metadata_fails_closed(self):
        cases = (
            ScopeDecision(True, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
            ScopeDecision(False, "127.0.0.1", ScopeReason.LOOPBACK),
        )
        for decision in cases:
            with self.subTest(decision=decision), self.assertRaisesRegex(
                ValueError, "incoherent allow/reason"
            ):
                AssessmentPlan("example.test", decision, ())

    def test_scope_allowed_must_be_real_boolean(self):
        with self.assertRaises(TypeError):
            AssessmentPlan(
                "127.0.0.1",
                ScopeDecision(1, "127.0.0.1", ScopeReason.LOOPBACK),
                ("web-baseline",),
            )

    def test_valid_lab_plan_accepts_planning_and_lab_only_capabilities(self):
        plan = AssessmentPlan(
            "127.0.0.1",
            ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK),
            ("web-baseline", "wireless-lab"),
        )
        self.assertFalse(plan.execution_enabled)

    def test_valid_public_plan_accepts_planning_capability_only(self):
        plan = AssessmentPlan(
            "security.example.test",
            ScopeDecision(True, "security.example.test", ScopeReason.EXPLICIT_HOST),
            ("web-baseline",),
        )
        self.assertEqual(plan.capability_ids, ("web-baseline",))
        self.assertFalse(plan.execution_enabled)


if __name__ == "__main__":
    unittest.main()
