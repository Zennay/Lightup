"""Offline risk-5 revocation-window contract, stacked on #1172.

All handlers are in-memory no-ops. RED tests are expected failures until the
source owner installs a transactionally fenced, live operator approval gate.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.destructive_lab_step_up import (
    DestructiveLabApproval, DestructiveLabStepUpExecutor,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class RevocationWindowOfflineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.handled = []
        self.verifier_calls = []
        registry = ToolRegistry()
        definition = ToolDefinition(
            tool_id="synthetic-risk-five-noop",
            capability_id="wireless-lab",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            description="in-memory marker only",
        )

        def handler(context, arguments):
            self.handled.append(context.run_id)
            return ToolOutput("synthetic", "note", b"offline-only")

        registry.register(definition, handler)
        self.executor = ToolExecutor(
            registry, StateStore(Path(temporary.name) / "state.sqlite")
        )
        now = datetime.now(timezone.utc)
        self.context = RunContext(
            run_id="offline-run", client_id="offline-tenant",
            engagement_id="offline-engagement",
            mode=AssessmentMode.LAB_AUTONOMOUS,
            approved_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=None, is_lab=True,
            created_at=now - timedelta(minutes=1),
        )
        self.call = ToolCall(definition.tool_id, "offline-simulator")
        self.approval = DestructiveLabApproval(
            approval_id="offline-operator-record",
            run_id=self.context.run_id,
            client_id=self.context.client_id,
            engagement_id=self.context.engagement_id,
            asset=self.call.asset,
            capability_id=definition.capability_id,
            tool_id=definition.tool_id,
            approved_by="offline-operator",
            approved_at=now - timedelta(minutes=2),
            expires_at=now + timedelta(minutes=10),
        )
        self.live = self.approval

    def wrapper(self, isolation):
        return DestructiveLabStepUpExecutor(
            self.executor,
            approval_resolver=lambda run_id: self.live,
            isolation_verifier=isolation,
        )

    def test_already_revoked_record_denies_before_isolation(self):
        self.live = replace(self.approval, revoked=True)

        def isolation(context, call):
            self.verifier_calls.append("called")
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.verifier_calls, [])
        self.assertEqual(self.handled, [])

    def test_missing_record_denies_before_isolation(self):
        self.live = None

        def isolation(context, call):
            self.verifier_calls.append("called")
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.verifier_calls, [])
        self.assertEqual(self.handled, [])


    def test_foreign_tenant_approval_denies_before_isolation(self):
        self.live = replace(self.approval, client_id="foreign-tenant")

        def isolation(context, call):
            self.verifier_calls.append("called")
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.verifier_calls, [])
        self.assertEqual(self.handled, [])

    def test_foreign_capability_approval_denies_before_isolation(self):
        self.live = replace(self.approval, capability_id="foreign-capability")

        def isolation(context, call):
            self.verifier_calls.append("called")
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.verifier_calls, [])
        self.assertEqual(self.handled, [])

    @unittest.expectedFailure
    def test_red_approval_expiry_during_isolation_prevents_handler(self):
        def isolation(context, call):
            self.live = replace(
                self.approval, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
            )
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.handled, [])

    @unittest.expectedFailure
    def test_red_approval_replacement_during_isolation_prevents_handler(self):
        def isolation(context, call):
            self.live = replace(self.approval, approval_id="replacement-approval")
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.handled, [])

    @unittest.expectedFailure
    def test_red_revocation_during_isolation_prevents_handler(self):
        def isolation(context, call):
            self.live = replace(self.approval, revoked=True)
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.handled, [])

    @unittest.expectedFailure
    def test_red_scope_substitution_during_isolation_prevents_handler(self):
        def isolation(context, call):
            self.live = replace(self.approval, asset="different-simulator")
            return True

        with self.assertRaises(ToolDenied):
            self.wrapper(isolation).execute(self.context, self.call)
        self.assertEqual(self.handled, [])


if __name__ == "__main__":
    unittest.main()
