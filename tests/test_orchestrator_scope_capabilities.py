import unittest
from unittest.mock import patch

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.models import Authorization, Target
from lightup.orchestrator import Planner
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


class PlannerScopeCapabilityBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.lab_only_ids = {
            item.capability_id
            for item in get_capabilities()
            if item.state is CapabilityState.LAB_ONLY
        }
        self.planning_ids = {
            item.capability_id
            for item in get_capabilities()
            if item.state is CapabilityState.PLANNING
        }

    def test_loopback_plan_may_include_lab_only_capabilities(self):
        plan = Planner(ScopePolicy()).build(Target("127.0.0.1"))

        self.assertTrue(plan.scope.allowed)
        self.assertEqual(plan.scope.reason, ScopeReason.LOOPBACK)
        self.assertTrue(self.lab_only_ids)
        self.assertTrue(self.lab_only_ids.issubset(set(plan.capability_ids)))
        self.assertTrue(self.planning_ids.issubset(set(plan.capability_ids)))
        self.assertFalse(plan.execution_enabled)

    def test_private_lab_plan_may_include_lab_only_capabilities(self):
        plan = Planner(ScopePolicy()).build(Target("10.20.30.40"))

        self.assertTrue(plan.scope.allowed)
        self.assertEqual(plan.scope.reason, ScopeReason.PRIVATE_LAB)
        self.assertTrue(self.lab_only_ids.issubset(set(plan.capability_ids)))
        self.assertTrue(self.planning_ids.issubset(set(plan.capability_ids)))
        self.assertFalse(plan.execution_enabled)

    def test_authorized_public_host_excludes_lab_only_capabilities(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )
        plan = Planner(policy).build(
            Target(
                "https://security.example.test/app",
                authorization=Authorization("client", "AUTH-203"),
            )
        )

        self.assertTrue(plan.scope.allowed)
        self.assertEqual(plan.scope.reason, ScopeReason.EXPLICIT_HOST)
        self.assertEqual(set(plan.capability_ids), self.planning_ids)
        self.assertTrue(self.lab_only_ids.isdisjoint(plan.capability_ids))
        self.assertFalse(plan.execution_enabled)

    def test_authorized_public_network_excludes_lab_only_capabilities(self):
        policy = ScopePolicy(
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        plan = Planner(policy).build(
            Target("8.8.8.8", authorization=Authorization("client", "AUTH-203-NET"))
        )

        self.assertTrue(plan.scope.allowed)
        self.assertEqual(plan.scope.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertEqual(set(plan.capability_ids), self.planning_ids)
        self.assertTrue(self.lab_only_ids.isdisjoint(plan.capability_ids))
        self.assertFalse(plan.execution_enabled)

    def test_denied_target_has_no_capabilities(self):
        plan = Planner(ScopePolicy()).build(Target("8.8.8.8"))

        self.assertFalse(plan.scope.allowed)
        self.assertEqual(plan.capability_ids, ())
        self.assertFalse(plan.execution_enabled)

    def test_inconsistent_scope_decision_fails_closed(self):
        class InconsistentPolicy:
            def __init__(self, decision):
                self.decision = decision

            def decide(self, _target):
                return self.decision

        cases = (
            ScopeDecision(True, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
            ScopeDecision(True, "8.8.8.8", ScopeReason.AUTHORIZATION_MISSING),
            ScopeDecision(False, "127.0.0.1", ScopeReason.LOOPBACK),
            ScopeDecision(False, "security.example.test", ScopeReason.EXPLICIT_HOST),
        )
        for decision in cases:
            with self.subTest(decision=decision), self.assertRaises(ValueError):
                Planner(InconsistentPolicy(decision)).build(Target("example.test"))


    def test_disabled_capability_is_never_planned(self):
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
            lab_plan = Planner(ScopePolicy()).build(Target("127.0.0.1"))
            public_plan = Planner(
                ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))
            ).build(
                Target(
                    "security.example.test",
                    authorization=Authorization("client", "AUTH-203-DISABLED"),
                )
            )

        self.assertNotIn(disabled.capability_id, lab_plan.capability_ids)
        self.assertNotIn(disabled.capability_id, public_plan.capability_ids)


if __name__ == "__main__":
    unittest.main()
