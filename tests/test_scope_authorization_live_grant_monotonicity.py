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


class ToolExecutorLiveGrantMonotonicityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.registry = ToolRegistry()
        self.handler_calls = []
        self.registry.register(
            ToolDefinition(
                "standard-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "Inert standard-risk probe",
            ),
            self._handler,
        )
        self.registry.register(
            ToolDefinition(
                "elevated-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.ELEVATED,
                "Inert elevated-risk probe",
            ),
            self._handler,
        )

    def _handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("ok", "probe", b"inert-evidence")

    def _grant(
        self,
        *,
        assets=("allowed.test",),
        capabilities=("network-services",),
        max_risk=RiskLevel.STANDARD,
        excluded_assets=(),
    ):
        now = datetime.now(timezone.utc)
        return AuthorizationGrant(
            grant_id="grant-1",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator@example.test",
            reference="AUTH-1",
            scope=ScopeDefinition(
                assets=tuple(assets),
                max_risk=max_risk,
                allowed_capabilities=tuple(capabilities),
                excluded_assets=tuple(excluded_assets),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )

    def _context(self, snapshot, approved_risk=RiskLevel.ELEVATED):
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
            approved_risk=approved_risk,
            authorization=snapshot,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _executor(self, live):
        return ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda snapshot: live,
        )

    def assert_denied_without_side_effects(self, executor, context, call):
        with self.assertRaisesRegex(
            ToolDenied,
            "live authorization cannot widen the run snapshot",
        ):
            executor.execute(context, call)
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)

    def test_live_grant_may_narrow_snapshot_authority(self):
        snapshot = self._grant(
            assets=("allowed.test", "other.test"),
            capabilities=("network-services", "web-baseline"),
            max_risk=RiskLevel.ELEVATED,
        )
        live = self._grant(
            assets=("allowed.test",),
            capabilities=("network-services",),
            max_risk=RiskLevel.STANDARD,
        )

        result = self._executor(live).execute(
            self._context(snapshot),
            ToolCall("standard-probe", "allowed.test"),
        )

        self.assertEqual(result.capability_id, "network-services")
        self.assertEqual(len(self.handler_calls), 1)
        self.assertEqual(self._evidence_count(), 1)

    def test_live_grant_cannot_add_asset_authority(self):
        snapshot = self._grant(assets=("allowed.test",))
        live = self._grant(assets=("allowed.test", "outside.test"))

        self.assert_denied_without_side_effects(
            self._executor(live),
            self._context(snapshot),
            ToolCall("standard-probe", "outside.test"),
        )

    def test_live_grant_cannot_remove_snapshot_asset_exclusion(self):
        snapshot = self._grant(
            assets=("allowed.test",),
            excluded_assets=("allowed.test",),
        )
        live = self._grant(
            assets=("allowed.test",),
            excluded_assets=(),
        )

        self.assert_denied_without_side_effects(
            self._executor(live),
            self._context(snapshot),
            ToolCall("standard-probe", "allowed.test"),
        )

    def test_live_grant_cannot_add_capability_authority(self):
        snapshot = self._grant(capabilities=("web-baseline",))
        live = self._grant(capabilities=("web-baseline", "network-services"))

        self.assert_denied_without_side_effects(
            self._executor(live),
            self._context(snapshot),
            ToolCall("standard-probe", "allowed.test"),
        )

    def test_live_grant_cannot_raise_max_risk(self):
        snapshot = self._grant(max_risk=RiskLevel.STANDARD)
        live = self._grant(max_risk=RiskLevel.ELEVATED)

        self.assert_denied_without_side_effects(
            self._executor(live),
            self._context(snapshot, approved_risk=RiskLevel.ELEVATED),
            ToolCall("elevated-probe", "allowed.test"),
        )


if __name__ == "__main__":
    unittest.main()
