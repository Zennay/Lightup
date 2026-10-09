"""Offline integration: real ToolExecutor mode boundary, with no network access.

This is deliberately NOT a persisted-consent/revocation proof. The production
owner must separately prove trusted-grant revalidation before network I/O.
"""
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor, ToolOutput,
    RiskElevationRequired,
)
from lightup.engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, InteractionKind


class RealExecutorModeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.handler = Mock(return_value=ToolOutput(
            summary="synthetic", evidence_kind="offline", evidence_payload=b"offline"
        ))
        self.state = Mock()
        self.state.add_evidence.return_value = "synthetic-evidence"
        self.policy = Mock()
        self.policy.decide.return_value = Mock(allowed=True, reason="offline lab")
        self.registry = Mock()
        self.definition = ToolDefinition(
            tool_id="synthetic-lab", capability_id="http_headers",
            description="Offline-only synthetic execution boundary",
            interaction=InteractionKind.LAB_ACTIVE, min_risk=RiskLevel.LOW_IMPACT,
        )
        self.registry.get.return_value = (self.definition, self.handler)
        self.executor = ToolExecutor(self.registry, self.state, self.policy)
        self.call = ToolCall(tool_id="synthetic-lab", asset="127.0.0.1")

    def context(self, mode):
        return RunContext(
            run_id="offline-run", client_id="offline-client",
            engagement_id="offline-engagement", mode=mode,
            approved_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=None, is_lab=True,
            created_at=datetime.now(timezone.utc),
        )

    def test_analysis_only_never_dispatches_or_writes_evidence(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(self.context(AssessmentMode.ANALYSIS_ONLY), self.call)
        self.policy.decide.assert_not_called()
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_passive_discovery_never_dispatches_or_writes_evidence(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(self.context(AssessmentMode.PASSIVE_DISCOVERY), self.call)
        self.policy.decide.assert_not_called()
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_policy_denial_never_dispatches_or_writes_evidence(self):
        self.policy.decide.return_value = Mock(allowed=False, reason="denied")
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(self.context(AssessmentMode.LAB_AUTONOMOUS), self.call)
        self.policy.decide.assert_called_once()
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_approved_synthetic_lab_positive_control(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            result = self.executor.execute(self.context(AssessmentMode.LAB_AUTONOMOUS), self.call)
        self.assertEqual(result.evidence_id, "synthetic-evidence")
        self.policy.decide.assert_called_once()
        self.handler.assert_called_once()
        self.state.add_evidence.assert_called_once()


    def test_real_policy_denies_target_without_authorization_before_handler(self):
        # Production ExecutionPolicy, actual ToolExecutor; no fake policy approval.
        self.definition = replace(
            self.definition, interaction=InteractionKind.TARGET_ACTIVE
        )
        self.registry.get.return_value = (self.definition, self.handler)
        self.executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT), is_lab=False
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_executor_rejects_lab_tool_in_nonlab_context(self):
        self.executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(self.context(AssessmentMode.AUTHORIZED_ASSESSMENT), is_lab=False)
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_risk_elevation_denied_before_policy_handler_and_evidence(self):
        context = replace(
            self.context(AssessmentMode.LAB_AUTONOMOUS),
            approved_risk=RiskLevel.ANALYSIS_ONLY,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(RiskElevationRequired):
                self.executor.execute(context, self.call)
        self.policy.decide.assert_not_called()
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_rejects_target_active_inside_lab(self):
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        self.executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(self.context(AssessmentMode.LAB_AUTONOMOUS), self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_analysis_only_denies_target_tool_even_if_policy_would_allow(self):
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        context = replace(self.context(AssessmentMode.ANALYSIS_ONLY), is_lab=False)
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(context, self.call)
        self.policy.decide.assert_not_called()
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_passive_discovery_denies_target_tool_even_if_policy_would_allow(self):
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        context = replace(self.context(AssessmentMode.PASSIVE_DISCOVERY), is_lab=False)
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                self.executor.execute(context, self.call)
        self.policy.decide.assert_not_called()
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denies_expired_grant_before_handler(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="expired-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-expired", scope=ScopeDefinition(
                assets=("127.0.0.1",), max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("http_headers",),
            ), valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denies_asset_outside_synthetic_grant_scope(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="restricted-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-restricted", scope=ScopeDefinition(
                assets=("127.0.0.2",), max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("http_headers",),
            ), valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denies_capability_outside_grant(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="capability-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-capability", scope=ScopeDefinition(
                assets=("127.0.0.1",), max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("tls_baseline",),
            ), valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_synthetic_grant_positive_control(self):
        # Proves the negative grant tests do not pass merely because execution
        # always fails. This test uses mock handlers and never opens a socket.
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="positive-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-positive", scope=ScopeDefinition(
                assets=("127.0.0.1",), max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("http_headers",),
            ), valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            result = executor.execute(context, self.call)
        self.assertEqual(result.evidence_id, "synthetic-evidence")
        self.handler.assert_called_once()
        self.state.add_evidence.assert_called_once()
        evidence = self.state.add_evidence.call_args.kwargs
        self.assertEqual(evidence["run_id"], "offline-run")
        self.assertEqual(evidence["capability_id"], "http_headers")
        self.assertEqual(evidence["source"], "synthetic-lab")
        self.assertEqual(evidence["payload"], b"offline")
        self.assertEqual(evidence["metadata"]["asset"], "127.0.0.1")
        self.assertEqual(evidence["metadata"]["client_id"], "offline-client")
        self.assertEqual(evidence["metadata"]["engagement_id"], "offline-engagement")
        self.assertEqual(evidence["metadata"]["mode"], AssessmentMode.AUTHORIZED_ASSESSMENT.value)
        self.assertEqual(evidence["metadata"]["is_lab"], "false")

    def test_real_policy_denies_risk_above_grant_ceiling(self):
        # Run ceiling permits LOW_IMPACT, but persisted-looking synthetic grant
        # explicitly permits PASSIVE only. No handler or evidence may run.
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="low-risk-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-low-risk", scope=ScopeDefinition(
                assets=("127.0.0.1",), max_risk=RiskLevel.PASSIVE,
                allowed_capabilities=("http_headers",),
            ), valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denies_not_yet_valid_grant(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="future-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-future", scope=ScopeDefinition(
                assets=("127.0.0.1",), max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("http_headers",),
            ), valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=2),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denies_explicitly_excluded_asset(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="excluded-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-exclusion", scope=ScopeDefinition(
                assets=("127.0.0.1",), excluded_assets=("127.0.0.1",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("http_headers",),
            ), valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
        )
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denies_destructive_risk_outside_lab_even_with_grant(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="destructive-synthetic", client_id="offline-client",
            engagement_id="offline-engagement", approved_by="offline-operator",
            reference="offline-destructive", scope=ScopeDefinition(
                assets=("127.0.0.1",),
                max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                allowed_capabilities=("http_headers",),
            ), valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(hours=1),
        )
        self.definition = replace(
            self.definition, interaction=InteractionKind.TARGET_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
        )
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(
            self.context(AssessmentMode.AUTHORIZED_ASSESSMENT),
            authorization=grant, is_lab=False,
        )
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            with self.assertRaises(ToolDenied):
                executor.execute(context, self.call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_real_policy_denied_grant_never_writes_evidence_across_replays(self):
        # Repeated unauthorized calls must not make their way into the ledger.
        self.definition = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry.get.return_value = (self.definition, self.handler)
        executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        context = replace(self.context(AssessmentMode.AUTHORIZED_ASSESSMENT), is_lab=False)
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            for _ in range(5):
                with self.assertRaises(ToolDenied):
                    executor.execute(context, self.call)
        self.assertEqual(self.registry.get.call_count, 5)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

if __name__ == "__main__":
    unittest.main()
