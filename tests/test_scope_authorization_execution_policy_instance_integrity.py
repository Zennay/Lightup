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
from lightup.execution_policy import (
    ExecutionPolicy,
    InteractionKind,
    PolicyDecision,
)
from lightup.state import StateStore


class ExecutionPolicyInstanceIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")

    def grant(self) -> AuthorizationGrant:
        now = datetime.now(timezone.utc)
        return AuthorizationGrant(
            grant_id="grant-1",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator",
            reference="AUTH-POLICY-1",
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
            run_id="run-policy-integrity",
            client_id=grant.client_id,
            engagement_id=grant.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_exact_policy_rejects_instance_level_decide_shadowing(self):
        policy = ExecutionPolicy()

        with self.assertRaises((AttributeError, TypeError)):
            policy.decide = lambda request: PolicyDecision(  # type: ignore[method-assign]
                True,
                "caller rewired policy",
            )

    def test_retained_exact_policy_cannot_be_rewired_to_run_out_of_scope_handler(self):
        calls: list[str] = []
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                "scope-policy-integrity-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "offline test-only authorization probe",
            ),
            lambda context, arguments: (
                calls.append("ran")
                or ToolOutput("ran", "test", b"offline")
            ),
        )
        grant = self.grant()
        policy = ExecutionPolicy()
        executor = ToolExecutor(
            registry,
            self.state,
            policy=policy,
            authorization_resolver=lambda current: current,
        )

        try:
            policy.decide = lambda request: PolicyDecision(  # type: ignore[method-assign]
                True,
                "caller rewired policy",
            )
        except (AttributeError, TypeError):
            pass

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(grant),
                ToolCall("scope-policy-integrity-probe", "outside.test"),
            )

        self.assertEqual(calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-policy-integrity",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)


if __name__ == "__main__":
    unittest.main()
