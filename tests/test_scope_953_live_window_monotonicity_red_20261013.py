"""Issue #953: real ToolExecutor temporal grant monotonicity acceptance.

Offline-only, disposable SQLite and an inert test handler. Expected failures
prove the source-owner's currently unresolved temporal-widening defect.
Run with: PYTHONPATH=src python -m unittest discover -s tests
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class GrantWindowMonotonicity953(unittest.TestCase):
    """All inputs and effects are local and synthetic; no network-capable tool."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-953-")
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "evidence.db")
        self.run_id = self.state.create_run(
            target="allowed.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-953",
        )
        self.now = datetime.now(timezone.utc)
        self.handler_calls = []
        self.resolver_calls = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "synthetic-temporal-test", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "Inert unit-test-only handler with no transport",
            ),
            self._inert_handler,
        )
        self.call = ToolCall("synthetic-temporal-test", "allowed.invalid")

    def _inert_handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("synthetic", "synthetic-test", b"synthetic-only")

    def _grant(self, start_days, end_days):
        return AuthorizationGrant(
            grant_id="grant-953", client_id="client-953",
            engagement_id="engagement-953", approved_by="offline-test",
            reference="SYNTHETIC-953",
            scope=ScopeDefinition(
                assets=("allowed.invalid",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("network-services",),
            ),
            valid_from=self.now + timedelta(days=start_days),
            valid_until=self.now + timedelta(days=end_days),
        )

    def _execute(self, snapshot, live):
        self.snapshot_original, self.live_original = snapshot, live

        def resolver(presented):
            self.resolver_calls.append(presented)
            return live

        executor = ToolExecutor(
            self.registry, self.state, authorization_resolver=resolver,
        )
        context = RunContext(
            run_id=self.run_id,
            client_id="client-953", engagement_id="engagement-953",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT, authorization=snapshot,
            is_lab=False, created_at=self.now,
        )
        return executor.execute(context, self.call)

    def _evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _assert_denial_before_effects(self, snapshot, live):
        before = self._evidence_count()
        with self.assertRaises(ToolDenied):
            self._execute(snapshot, live)
        self.assertEqual(self.handler_calls, [], "denial must precede dispatch")
        self.assertEqual(self._evidence_count(), before, "denial must not write evidence")
        self.assertEqual(self.resolver_calls, [snapshot])
        self.assertIs(self.snapshot_original, snapshot)
        self.assertIs(self.live_original, live)

    @unittest.expectedFailure  # #953 unresolved on source-owner #107 head
    def test_expired_snapshot_cannot_be_revived_by_live_expiry_extension(self):
        self._assert_denial_before_effects(
            self._grant(-4, -2), self._grant(-4, 2),
        )

    @unittest.expectedFailure  # #953 unresolved on source-owner #107 head
    def test_future_snapshot_cannot_be_activated_by_earlier_live_start(self):
        self._assert_denial_before_effects(
            self._grant(2, 4), self._grant(-2, 4),
        )

    @unittest.expectedFailure  # #953 unresolved even when both grants current
    def test_current_snapshot_rejects_live_expiry_extension(self):
        self._assert_denial_before_effects(
            self._grant(-2, 2), self._grant(-2, 4),
        )

    @unittest.expectedFailure  # #953 unresolved even when both grants current
    def test_current_snapshot_rejects_live_start_backdating(self):
        self._assert_denial_before_effects(
            self._grant(-2, 2), self._grant(-4, 2),
        )

    def test_identical_current_windows_remain_allowed(self):
        grant = self._grant(-2, 2)
        result = self._execute(grant, grant)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 1)
        self.assertEqual(self.resolver_calls, [grant])

    def test_strictly_narrower_current_window_remains_allowed(self):
        snapshot, live = self._grant(-4, 4), self._grant(-1, 1)
        self._execute(snapshot, live)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 1)
        self.assertEqual(snapshot.valid_from, self.now - timedelta(days=4))
        self.assertEqual(live.valid_until, self.now + timedelta(days=1))

    def test_narrowed_live_expiry_past_now_is_denied(self):
        self._assert_denial_before_effects(
            self._grant(-4, 4), self._grant(-4, -1),
        )

    def test_narrowed_live_start_future_is_denied(self):
        self._assert_denial_before_effects(
            self._grant(-4, 4), self._grant(1, 4),
        )

    def test_missing_live_grant_is_denied_without_side_effect(self):
        self._assert_denial_before_effects(self._grant(-4, 4), None)

    def test_different_live_grant_id_is_denied(self):
        snapshot = self._grant(-4, 4)
        live = replace(snapshot, grant_id="different-grant-953")
        self._assert_denial_before_effects(snapshot, live)


if __name__ == "__main__":
    unittest.main()
