from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolDenied,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode,
    AuthorizationGrant,
    RiskLevel,
    ScopeDefinition,
)
from lightup.execution_policy import ExecutionPolicy, InteractionKind, PolicyDecision
from lightup.state import StateStore


class _AllowAllPolicy(ExecutionPolicy):
    def decide(self, request):
        return PolicyDecision(True, "replacement policy bypass")


class ToolExecutorPolicyBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "policy-binding-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "offline test-only policy binding probe",
            ),
            lambda context, arguments: (
                self.calls.append("ran")
                or ToolOutput("ran", "test", b"offline")
            ),
        )

    def grant(self) -> AuthorizationGrant:
        now = datetime.now(timezone.utc)
        return AuthorizationGrant(
            grant_id="grant-policy-binding",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator",
            reference="AUTH-POLICY-BINDING-1",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )

    def context(self, grant: AuthorizationGrant) -> RunContext:
        return RunContext(
            run_id="run-policy-binding",
            client_id=grant.client_id,
            engagement_id=grant.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_policy_binding_rejects_post_construction_replacement(self):
        executor = ToolExecutor(
            self.registry,
            self.state,
            policy=ExecutionPolicy(),
            authorization_resolver=lambda current: current,
        )

        with self.assertRaises((AttributeError, TypeError)):
            executor.policy = _AllowAllPolicy()

    def test_policy_replacement_cannot_turn_out_of_scope_denial_into_execution(self):
        grant = self.grant()
        executor = ToolExecutor(
            self.registry,
            self.state,
            policy=ExecutionPolicy(),
            authorization_resolver=lambda current: current,
        )

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(grant),
                ToolCall("policy-binding-probe", "outside.test"),
            )
        self.assertEqual(self.calls, [])

        try:
            executor.policy = _AllowAllPolicy()
        except (AttributeError, TypeError):
            pass

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(grant),
                ToolCall("policy-binding-probe", "outside.test"),
            )

        self.assertEqual(self.calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-policy-binding",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)


if __name__ == "__main__":
    unittest.main()
