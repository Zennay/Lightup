"""Offline opt-in real-executor acceptance for #1039. No socket/target I/O."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    OrchestrationError,
    RiskElevationRequired,
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolDenied,
    ToolExecutor,
    ToolOutput,
)
from lightup.emergency_dispatch_optin import execute_with_emergency_gate
from lightup.engagements import (
    AssessmentMode,
    AuthorizationGrant,
    RiskLevel,
    ScopeDefinition,
)
from lightup.execution_policy import ExecutionPolicy, InteractionKind


class EmergencyDispatchOptinTests(unittest.TestCase):
    def setUp(self):
        self.handler = Mock(
            return_value=ToolOutput(
                summary="synthetic only",
                evidence_kind="offline",
                evidence_payload=b"not a network capture",
            )
        )
        self.state = Mock()
        self.state.add_evidence.return_value = "synthetic-id"
        self.registry = Mock()
        self.definition = ToolDefinition(
            tool_id="offline-target",
            capability_id="http_headers",
            interaction=InteractionKind.TARGET_ACTIVE,
            min_risk=RiskLevel.STANDARD,
            description="synthetic mock handler, never a scanner",
        )
        self.registry.get.return_value = (self.definition, self.handler)
        self.executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="offline-g",
            client_id="offline-client",
            engagement_id="offline-engagement",
            approved_by="synthetic-operator",
            reference="SYNTHETIC-ONLY",
            scope=ScopeDefinition(
                assets=("127.0.0.1",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("http_headers",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(minutes=5),
        )
        self.context = RunContext(
            run_id="synthetic-run",
            client_id="offline-client",
            engagement_id="offline-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=self.grant,
            is_lab=False,
            created_at=now,
        )
        self.call = ToolCall(tool_id="offline-target", asset="127.0.0.1")

    def run_gate(self, *, stop=False, override=False, context=None, call=None):
        # Any attempt to create a real socket is a failed offline acceptance.
        with patch("socket.socket", side_effect=AssertionError("network not allowed")):
            return execute_with_emergency_gate(
                self.executor,
                self.context if context is None else context,
                self.call if call is None else call,
                stop_active=stop,
                override_requested=override,
            )

    def assert_no_effects(self):
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    def test_canonical_authorized_control_reaches_mock_and_ledger(self):
        result = self.run_gate()
        self.assertEqual(result.evidence_id, "synthetic-id")
        self.handler.assert_called_once()
        self.state.add_evidence.assert_called_once()

    def test_stop_dominates_valid_grant_and_both_override_values(self):
        for override in (False, True):
            with self.subTest(override=override):
                with self.assertRaises(ToolDenied):
                    self.run_gate(stop=True, override=override)
                self.registry.get.assert_not_called()
                self.assert_no_effects()

    def test_stop_dominates_lab_mode_as_well(self):
        lab = RunContext.for_lab(run_id="synthetic-lab")
        with self.assertRaises(ToolDenied):
            self.run_gate(stop=True, override=True, context=lab)
        self.assert_no_effects()

    def test_override_cannot_mint_missing_grant(self):
        denied = replace(self.context, authorization=None)
        with self.assertRaises(ToolDenied):
            self.run_gate(override=True, context=denied)
        self.assert_no_effects()

    def test_override_cannot_bypass_out_of_scope_asset(self):
        with self.assertRaises(ToolDenied):
            self.run_gate(override=True, call=replace(self.call, asset="127.0.0.2"))
        self.assert_no_effects()

    def test_override_cannot_resurrect_expired_grant(self):
        now = datetime.now(timezone.utc)
        expired = replace(
            self.grant,
            valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )
        with self.assertRaises(ToolDenied):
            self.run_gate(override=True, context=replace(self.context, authorization=expired))
        self.assert_no_effects()

    def test_override_cannot_bypass_capability_scope(self):
        grant = replace(
            self.grant,
            scope=replace(self.grant.scope, allowed_capabilities=("tls_baseline",)),
        )
        with self.assertRaises(ToolDenied):
            self.run_gate(override=True, context=replace(self.context, authorization=grant))
        self.assert_no_effects()

    def test_override_cannot_promote_passive_mode(self):
        passive = replace(self.context, mode=AssessmentMode.PASSIVE_DISCOVERY)
        with self.assertRaises(ToolDenied):
            self.run_gate(override=True, context=passive)
        self.assert_no_effects()

    def test_override_cannot_raise_approved_risk(self):
        reduced = replace(self.context, approved_risk=RiskLevel.PASSIVE)
        with self.assertRaises(RiskElevationRequired):
            self.run_gate(override=True, context=reduced)
        self.assert_no_effects()

    def test_truthy_nonboolean_stop_signals_fail_closed_before_lookup(self):
        for invalid in (1, 0, "false", "true", None, (), [], {}, object()):
            with self.subTest(type=type(invalid).__name__, value=repr(invalid)):
                with self.assertRaises(ToolDenied):
                    self.run_gate(stop=invalid)
                self.assert_no_effects()
                self.registry.get.assert_not_called()

    def test_truthy_nonboolean_override_signals_fail_closed_before_lookup(self):
        for invalid in (1, 0, "false", "true", None, (), [], {}, object()):
            with self.subTest(type=type(invalid).__name__, value=repr(invalid)):
                with self.assertRaises(ToolDenied):
                    self.run_gate(override=invalid)
                self.assert_no_effects()
                self.registry.get.assert_not_called()

    def test_override_does_not_change_valid_grant_result(self):
        control = self.run_gate(override=True)
        self.assertEqual(control.evidence_id, "synthetic-id")
        self.handler.assert_called_once()
        self.state.add_evidence.assert_called_once()

    def test_argument_smuggling_not_recognized_as_override_permission(self):
        # An untrusted model-supplied option cannot rewrite trusted grant state.
        forged = ToolCall(
            tool_id="offline-target",
            asset="127.0.0.1",
            arguments=(("emergency_override", True),),
        )
        with self.assertRaises(OrchestrationError):
            self.run_gate(override=True, context=replace(self.context, authorization=None), call=forged)
        self.assert_no_effects()

    def test_input_objects_remain_unchanged(self):
        before = (self.context, self.call, self.grant)
        with self.assertRaises(ToolDenied):
            self.run_gate(stop=True, override=True)
        self.assertEqual(before, (self.context, self.call, self.grant))
        self.assert_no_effects()


if __name__ == "__main__":
    unittest.main()
