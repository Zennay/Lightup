"""#935 — exact ExecutionPolicy instance cannot be rewired after acceptance.

Real ToolExecutor and disposable SQLite; inert synthetic TARGET_ACTIVE handler.
Intentional expected failures are NOT security fixes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, InteractionKind, PolicyDecision
from lightup.state import StateStore


def _fake_decide(request):
    return PolicyDecision(True, "untrusted local policy override")


class ExecutionPolicyInstanceIntegrity935(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-935-")
        self.addCleanup(temp.cleanup)
        self.state = StateStore(Path(temp.name) / "evidence.sqlite")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        self.calls = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "inert-scope-935", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "inert local-only handler",
            ),
            self._handler,
        )
        self.policy = ExecutionPolicy()
        self.original_bound_decide = self.policy.decide
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="grant-935", client_id="client-935",
            engagement_id="engagement-935", approved_by="offline-fixture",
            reference="SYNTHETIC-935",
            scope=ScopeDefinition(
                assets=("allowed.invalid",),
                allowed_capabilities=("network-services",),
                max_risk=RiskLevel.LOW_IMPACT,
            ),
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=1),
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="client-935",
            engagement_id="engagement-935",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant, is_lab=False, created_at=now,
        )
        self.executor = ToolExecutor(
            self.registry, self.state, policy=self.policy,
            authorization_resolver=lambda grant: grant,
        )

    def _handler(self, context, args):
        self.calls.append(context.run_id)
        return ToolOutput("synthetic", "test", b"synthetic")

    def _count(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _mutation_denied_without_side_effect(self, mutate):
        before = self._count()
        try:
            mutate()
        except (AttributeError, TypeError):
            pass
        self.assertIs(self.executor.policy, self.policy)
        self.assertEqual(self.policy.decide, self.original_bound_decide,
                         "trusted exact ExecutionPolicy instance must not be rewired")
        with self.assertRaises(ToolDenied):
            self.executor.execute(
                self.context, ToolCall("inert-scope-935", "outside.invalid")
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), before)

    @unittest.expectedFailure  # source owner #100 instance method mutable
    def test_direct_decide_override_does_not_widen_scope(self):
        self._mutation_denied_without_side_effect(
            lambda: setattr(self.policy, "decide", _fake_decide)
        )

    @unittest.expectedFailure  # object-level setter bypasses normal attribute access
    def test_object_setattr_cannot_rewire_decide(self):
        self._mutation_denied_without_side_effect(
            lambda: object.__setattr__(self.policy, "decide", _fake_decide)
        )

    @unittest.expectedFailure  # instance dictionary shadow
    def test_instance_dictionary_cannot_shadow_decide(self):
        self._mutation_denied_without_side_effect(
            lambda: vars(self.policy).__setitem__("decide", _fake_decide)
        )

    @unittest.expectedFailure  # bulk dictionary mutation cannot replace decide
    def test_bulk_dictionary_update_cannot_rewire_decide(self):
        self._mutation_denied_without_side_effect(
            lambda: vars(self.policy).update({"decide": _fake_decide})
        )

    def test_canonical_policy_denies_out_of_scope_asset(self):
        self._mutation_denied_without_side_effect(lambda: None)

    def test_canonical_policy_allows_synthetic_in_scope_control(self):
        result = self.executor.execute(
            self.context, ToolCall("inert-scope-935", "allowed.invalid")
        )
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.calls, [self.run_id])
        self.assertEqual(self._count(), 1)

    def test_missing_grant_denied_before_handler(self):
        from dataclasses import replace
        with self.assertRaises(ToolDenied):
            self.executor.execute(
                replace(self.context, authorization=None),
                ToolCall("inert-scope-935", "allowed.invalid"),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), 0)

    def test_passive_mode_never_borrows_grant_for_active_execution(self):
        from dataclasses import replace
        passive = replace(
            self.context, mode=AssessmentMode.PASSIVE_DISCOVERY,
            approved_risk=RiskLevel.PASSIVE,
        )
        with self.assertRaises(ToolDenied):
            self.executor.execute(
                passive, ToolCall("inert-scope-935", "allowed.invalid")
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), 0)

    def test_exact_unmodified_policy_decide_method_is_original_class_method(self):
        self.assertIs(type(self.policy), ExecutionPolicy)
        self.assertIs(self.policy.decide.__func__, ExecutionPolicy.decide)
        self.assertEqual(self._count(), 0)


if __name__ == "__main__":
    unittest.main()
