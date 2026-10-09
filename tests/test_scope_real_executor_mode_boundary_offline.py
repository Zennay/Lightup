"""Offline integration: real ToolExecutor mode boundary, with no network access.

This is deliberately NOT a persisted-consent/revocation proof. The production
owner must separately prove trusted-grant revalidation before network I/O.
"""
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor, ToolOutput,
)
from lightup.engagements import AssessmentMode, RiskLevel
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

if __name__ == "__main__":
    unittest.main()
