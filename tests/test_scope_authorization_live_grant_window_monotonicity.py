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
from lightup.engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class ToolExecutorLiveGrantWindowMonotonicityTest(unittest.TestCase):
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
                "Inert authorized test probe",
            ),
            self._handler,
        )
        self.now = datetime.now(timezone.utc)

    def _handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("ok", "probe", b"inert-evidence")

    def _grant(self, valid_from, valid_until):
        return AuthorizationGrant(
            grant_id="grant-1",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator@example.test",
            reference="AUTH-1",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=valid_from,
            valid_until=valid_until,
        )

    def _context(self, snapshot):
        run_id = self.state.create_run(
            "allowed.test",
            activation_mode=AssessmentMode.AUTHORIZED_ASSESSMENT.value,
            authorization_ref=snapshot.reference,
        )
        return RunContext(
            run_id=run_id,
            client_id=snapshot.client_id,
            engagement_id=snapshot.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=snapshot,
            is_lab=False,
            created_at=self.now,
        )

    def _executor(self, live):
        return ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda snapshot: live,
        )

    def _evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def assert_window_widening_denied(self, snapshot, live):
        with self.assertRaisesRegex(
            ToolDenied,
            "live authorization cannot widen the run validity window",
        ):
            self._executor(live).execute(
                self._context(snapshot),
                ToolCall("service-probe", "allowed.test"),
            )
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)

    def test_live_grant_may_narrow_snapshot_validity_window(self):
        snapshot = self._grant(
            self.now - timedelta(hours=1),
            self.now + timedelta(hours=2),
        )
        live = self._grant(
            self.now - timedelta(minutes=30),
            self.now + timedelta(hours=1),
        )

        result = self._executor(live).execute(
            self._context(snapshot),
            ToolCall("service-probe", "allowed.test"),
        )

        self.assertEqual(result.capability_id, "network-services")
        self.assertEqual(len(self.handler_calls), 1)
        self.assertEqual(self._evidence_count(), 1)

    def test_live_grant_cannot_move_valid_from_earlier(self):
        snapshot = self._grant(
            self.now - timedelta(minutes=5),
            self.now + timedelta(hours=1),
        )
        live = self._grant(
            self.now - timedelta(hours=1),
            self.now + timedelta(hours=1),
        )

        self.assert_window_widening_denied(snapshot, live)

    def test_live_grant_cannot_move_valid_until_later(self):
        snapshot = self._grant(
            self.now - timedelta(hours=1),
            self.now + timedelta(minutes=30),
        )
        live = self._grant(
            self.now - timedelta(hours=1),
            self.now + timedelta(hours=2),
        )

        self.assert_window_widening_denied(snapshot, live)

    def test_expired_snapshot_cannot_be_revived_by_live_extension(self):
        snapshot = self._grant(
            self.now - timedelta(hours=2),
            self.now - timedelta(minutes=1),
        )
        live = self._grant(
            self.now - timedelta(hours=2),
            self.now + timedelta(hours=1),
        )

        self.assert_window_widening_denied(snapshot, live)

    def test_future_snapshot_cannot_be_activated_early(self):
        snapshot = self._grant(
            self.now + timedelta(hours=1),
            self.now + timedelta(hours=2),
        )
        live = self._grant(
            self.now - timedelta(minutes=5),
            self.now + timedelta(hours=2),
        )

        self.assert_window_widening_denied(snapshot, live)


if __name__ == "__main__":
    unittest.main()
