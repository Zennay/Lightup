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
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class ToolExecutorAuthorizationResolverBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "resolver-binding-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "offline test-only resolver binding probe",
            ),
            lambda context, arguments: (
                self.calls.append("ran")
                or ToolOutput("ran", "test", b"offline")
            ),
        )

    def grant(self) -> AuthorizationGrant:
        now = datetime.now(timezone.utc)
        return AuthorizationGrant(
            grant_id="grant-resolver-binding",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator",
            reference="AUTH-RESOLVER-1",
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
            run_id="run-resolver-binding",
            client_id=grant.client_id,
            engagement_id=grant.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_authorization_resolver_binding_rejects_post_construction_replacement(self):
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda current: None,
        )

        with self.assertRaises((AttributeError, TypeError)):
            executor.authorization_resolver = lambda current: current

    def test_revoked_resolution_cannot_be_bypassed_by_replacing_retained_resolver(self):
        grant = self.grant()
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda current: None,
        )

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(grant),
                ToolCall("resolver-binding-probe", "allowed.test"),
            )
        self.assertEqual(self.calls, [])

        try:
            executor.authorization_resolver = lambda current: current
        except (AttributeError, TypeError):
            pass

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(grant),
                ToolCall("resolver-binding-probe", "allowed.test"),
            )

        self.assertEqual(self.calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-resolver-binding",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)


if __name__ == "__main__":
    unittest.main()
