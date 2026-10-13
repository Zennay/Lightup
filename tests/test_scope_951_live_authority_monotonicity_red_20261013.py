"""Issue #951: live persisted grant must not widen immutable run authority.

Real ToolExecutor boundary, inert handler, disposable SQLite, no network.
The expectedFailure checks are unresolved security requirements, not a fix.
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


class LiveAuthorityMonotonicity951(unittest.TestCase):
    """Synthetic deterministic fixtures; zero network-capable handlers."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-951-")
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "synthetic-evidence.db")
        self.run_id = self.state.create_run(
            target="allowed.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-951",
        )
        now = datetime.now(timezone.utc)
        self.start = now - timedelta(days=2)
        self.end = now + timedelta(days=2)
        self.executed = []
        self.resolved = []
        self.registry = ToolRegistry()
        for risk, identifier in (
            (RiskLevel.LOW_IMPACT, "synthetic-low-951"),
            (RiskLevel.STANDARD, "synthetic-standard-951"),
        ):
            self.registry.register(
                ToolDefinition(
                    identifier, "network-services", InteractionKind.TARGET_ACTIVE,
                    risk, "offline assertion-only handler",
                ),
                self._inert_handler,
            )

    def _inert_handler(self, context, arguments):
        self.executed.append(context.run_id)
        return ToolOutput("synthetic output", "test-only", b"test-only-evidence")

    def _scope(
        self, assets=("allowed.invalid",), capabilities=("network-services",),
        max_risk=RiskLevel.STANDARD, excluded=(),
    ):
        return ScopeDefinition(
            assets=assets, max_risk=max_risk,
            allowed_capabilities=capabilities, excluded_assets=excluded,
        )

    def _grant(self, scope):
        return AuthorizationGrant(
            grant_id="synthetic-grant-951", client_id="synthetic-client-951",
            engagement_id="synthetic-engagement-951", approved_by="offline-owner",
            reference="SYNTHETIC-951", scope=scope,
            valid_from=self.start, valid_until=self.end,
        )

    def _count_evidence(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _run(
        self, snapshot, live, asset="allowed.invalid",
        tool="synthetic-low-951",
    ):
        def resolver(presented):
            self.resolved.append(presented)
            return live

        ctx = RunContext(
            run_id=self.run_id, client_id="synthetic-client-951",
            engagement_id="synthetic-engagement-951",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD, authorization=snapshot,
            is_lab=False, created_at=self.start,
        )
        return ToolExecutor(
            self.registry, self.state, authorization_resolver=resolver,
        ).execute(ctx, ToolCall(tool, asset))

    def _assert_denied(self, snapshot, live, **kwargs):
        original_snapshot = snapshot
        original_live = live
        rows_before = self._count_evidence()
        with self.assertRaises(ToolDenied):
            self._run(snapshot, live, **kwargs)
        self.assertEqual(self.executed, [], "denial must precede handler")
        self.assertEqual(self._count_evidence(), rows_before, "no evidence on denial")
        self.assertEqual(self.resolved, [snapshot])
        self.assertIs(snapshot, original_snapshot)
        self.assertIs(live, original_live)

    @unittest.expectedFailure  # #951 source-owner #107 not fixed
    def test_new_live_asset_not_in_snapshot_cannot_enter_run(self):
        snap = self._grant(self._scope(assets=("original.invalid",)))
        live = replace(snap, scope=self._scope(assets=("original.invalid", "allowed.invalid")))
        self._assert_denied(snap, live)

    @unittest.expectedFailure  # #951 source-owner #107 not fixed
    def test_added_live_capability_cannot_enter_run(self):
        snap = self._grant(self._scope(capabilities=("web-baseline",)))
        live = replace(snap, scope=self._scope(capabilities=("web-baseline", "network-services")))
        self._assert_denied(snap, live)

    @unittest.expectedFailure  # #951 source-owner #107 not fixed
    def test_increased_live_max_risk_rejected_even_for_low_risk_call(self):
        snap = self._grant(self._scope(max_risk=RiskLevel.LOW_IMPACT))
        live = replace(snap, scope=self._scope(max_risk=RiskLevel.STANDARD))
        self._assert_denied(snap, live)

    @unittest.expectedFailure  # #951 effective scope can expand by removal
    def test_removed_snapshot_exclusion_is_authority_widening(self):
        snap = self._grant(self._scope(excluded=("allowed.invalid",)))
        live = replace(snap, scope=self._scope(excluded=()))
        self._assert_denied(snap, live)

    @unittest.expectedFailure  # no compensation of widening by other narrowing
    def test_risk_narrowing_cannot_offset_capability_expansion(self):
        snap = self._grant(self._scope(max_risk=RiskLevel.STANDARD))
        live = replace(snap, scope=self._scope(
            capabilities=("network-services", "web-baseline"),
            max_risk=RiskLevel.LOW_IMPACT,
        ))
        self._assert_denied(snap, live)

    def test_identical_grants_allow_inert_handler(self):
        snapshot = self._grant(self._scope())
        result = self._run(snapshot, snapshot)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.executed, [self.run_id])
        self.assertEqual(self._count_evidence(), 1)

    def test_live_narrowed_assets_caps_and_risk_allows_intersection(self):
        snap = self._grant(self._scope(
            assets=("allowed.invalid", "extra.invalid"),
            capabilities=("network-services", "web-baseline"),
            max_risk=RiskLevel.STANDARD,
        ))
        live = replace(snap, scope=self._scope(max_risk=RiskLevel.LOW_IMPACT))
        self._run(snap, live)
        self.assertEqual(self.executed, [self.run_id])
        self.assertEqual(self._count_evidence(), 1)
        self.assertEqual(snap.scope.assets, ("allowed.invalid", "extra.invalid"))
        self.assertEqual(live.scope.assets, ("allowed.invalid",))

    def test_narrowed_live_assets_rejects_original_eligible_asset(self):
        snap = self._grant(self._scope(assets=("allowed.invalid", "extra.invalid")))
        live = replace(snap, scope=self._scope(assets=("extra.invalid",)))
        self._assert_denied(snap, live)

    def test_narrowed_live_capabilities_rejects_legacy_call(self):
        snap = self._grant(self._scope(
            capabilities=("network-services", "web-baseline"),
        ))
        live = replace(snap, scope=self._scope(capabilities=("web-baseline",)))
        self._assert_denied(snap, live)

    def test_narrowed_live_max_risk_rejects_standard_tool(self):
        snap = self._grant(self._scope(max_risk=RiskLevel.STANDARD))
        live = replace(snap, scope=self._scope(max_risk=RiskLevel.LOW_IMPACT))
        self._assert_denied(snap, live, tool="synthetic-standard-951")


if __name__ == "__main__":
    unittest.main()
