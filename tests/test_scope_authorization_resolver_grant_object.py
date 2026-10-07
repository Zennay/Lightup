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


class _DuckGrant:
    def __init__(self, source: AuthorizationGrant, scope: ScopeDefinition):
        self.grant_id = source.grant_id
        self.client_id = source.client_id
        self.engagement_id = source.engagement_id
        self.approved_by = source.approved_by
        self.reference = source.reference
        self.scope = scope
        self.valid_from = source.valid_from
        self.valid_until = source.valid_until
        self.recurring_retest_allowed = source.recurring_retest_allowed
        self.revoked_at = None
        self.revoked_by = None
        self.revocation_reason = None

    def is_current(self, now=None):
        return True


class _GrantSubclass(AuthorizationGrant):
    pass


class ToolExecutorResolverGrantObjectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.registry = ToolRegistry()
        self.handler_calls = []
        self.registry.register(
            ToolDefinition(
                "service-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "Authorized inert test probe",
            ),
            self._handler,
        )

    def _handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("ok", "probe", b"inert-evidence")

    def _grant(self, assets=("allowed.test",)):
        now = datetime.now(timezone.utc)
        return AuthorizationGrant(
            grant_id="grant-1",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator@example.test",
            reference="AUTH-1",
            scope=ScopeDefinition(
                assets=tuple(assets),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )

    def _context(self, grant):
        run_id = self.state.create_run(
            "allowed.test",
            activation_mode=AssessmentMode.AUTHORIZED_ASSESSMENT.value,
            authorization_ref=grant.reference,
        )
        return RunContext(
            run_id=run_id,
            client_id=grant.client_id,
            engagement_id=grant.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def test_exact_live_grant_remains_accepted(self):
        grant = self._grant()
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda snapshot: grant,
        )

        result = executor.execute(
            self._context(grant),
            ToolCall("service-probe", "allowed.test"),
        )

        self.assertEqual(result.capability_id, "network-services")
        self.assertEqual(len(self.handler_calls), 1)
        self.assertEqual(self._evidence_count(), 1)

    def test_duck_live_grant_cannot_widen_scope(self):
        snapshot = self._grant()
        forged = _DuckGrant(
            snapshot,
            ScopeDefinition(
                assets=("outside.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
        )
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda grant: forged,
        )

        with self.assertRaisesRegex(
            ToolDenied,
            "live authorization resolver must return an exact AuthorizationGrant",
        ):
            executor.execute(
                self._context(snapshot),
                ToolCall("service-probe", "outside.test"),
            )

        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)

    def test_authorization_grant_subclass_cannot_widen_scope(self):
        snapshot = self._grant()
        broad = _GrantSubclass(
            grant_id=snapshot.grant_id,
            client_id=snapshot.client_id,
            engagement_id=snapshot.engagement_id,
            approved_by=snapshot.approved_by,
            reference=snapshot.reference,
            scope=ScopeDefinition(
                assets=("outside.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=snapshot.valid_from,
            valid_until=snapshot.valid_until,
        )
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda grant: broad,
        )

        with self.assertRaisesRegex(
            ToolDenied,
            "live authorization resolver must return an exact AuthorizationGrant",
        ):
            executor.execute(
                self._context(snapshot),
                ToolCall("service-probe", "outside.test"),
            )

        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
