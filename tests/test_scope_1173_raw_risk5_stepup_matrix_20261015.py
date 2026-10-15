"""Issue #1173: installed-source destructive-lab step-up acceptance.

All inputs are synthetic and all handlers are in-memory no-ops. No target adapter,
DNS lookup, socket, customer authorization, real approval or external IO is used.
Expected-RED methods document *missing* raw-executor enforcement, not success.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, expectedFailure
from unittest.mock import Mock, patch
import socket

from lightup.ai.orchestration import (
    RiskElevationRequired,
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolDenied,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from lightup.state import StateStore


class RiskFiveSeparateApprovalContract(TestCase):
    """Real policy/executor boundaries, disposable SQLite and inert handlers."""

    def setUp(self):
        self.temp = TemporaryDirectory(prefix="lightup-risk5-1173-")
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "evidence.db")
        self.run_id = self.state.create_run("fixture-lab-only", activation_mode="lab_only")
        self.context = RunContext.for_lab(self.run_id)
        self.handler = Mock(return_value=ToolOutput(
            summary="synthetic-only",
            evidence_kind="test-fixture",
            evidence_payload=b"offline-fixture-no-target",
        ))
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                tool_id="fixture-risk-five",
                capability_id="web-baseline",
                interaction=InteractionKind.LAB_ACTIVE,
                min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                description="inert, non-network regression fixture",
            ),
            self.handler,
        )
        self.executor = ToolExecutor(self.registry, self.state)
        self.call = ToolCall("fixture-risk-five", "127.0.0.1")

    def _execute_offline(self, context=None, call=None):
        """Tripwire proves no network is needed even for a defective permit."""
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            return self.executor.execute(context or self.context, call or self.call)

    def _evidence_count(self):
        with self.state.connect() as db:
            return db.execute("SELECT count(*) FROM evidence").fetchone()[0]

    @expectedFailure
    def test_risk_five_cannot_dispatch_on_for_lab_flag_without_step_up(self):
        """RED: absent independent operator approval must deny before handler."""
        before = self._evidence_count()
        with self.assertRaises(ToolDenied):
            self._execute_offline()
        self.handler.assert_not_called()
        self.assertEqual(before, self._evidence_count())

    @expectedFailure
    def test_risk_five_policy_cannot_treat_is_lab_as_operator_approval(self):
        """RED: lab status is not an approval decision at the policy boundary."""
        request = ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="127.0.0.1",
            capability_id="web-baseline",
            requested_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=None,
            is_lab=True,
        )
        before = (request.interaction, request.asset, request.authorization, request.is_lab)
        result = ExecutionPolicy().decide(request)
        self.assertFalse(result.allowed, "no independent per-target step-up exists")
        self.assertEqual(
            before, (request.interaction, request.asset, request.authorization, request.is_lab)
        )

    @expectedFailure
    def test_forged_risk_five_context_cannot_supply_missing_approval(self):
        """RED: replacing a frozen context does not create trusted provenance."""
        forged = replace(
            self.context,
            client_id="different-synthetic-tenant",
            engagement_id="unrelated-synthetic-engagement",
        )
        with self.assertRaises(ToolDenied):
            self._execute_offline(forged)
        self.handler.assert_not_called()
        self.assertEqual(0, self._evidence_count())

    def test_ceiling_four_blocks_risk_five_before_handler_and_evidence(self):
        """GREEN: existing numerical ceiling protects ordinary lower-risk runs."""
        context = replace(self.context, approved_risk=RiskLevel.ELEVATED)
        with self.assertRaises(RiskElevationRequired) as caught:
            self._execute_offline(context)
        self.assertEqual(caught.exception.required, RiskLevel.DESTRUCTIVE_LAB_ONLY)
        self.assertEqual(caught.exception.approved, RiskLevel.ELEVATED)
        self.handler.assert_not_called()
        self.assertEqual(0, self._evidence_count())

    def test_non_lab_run_denies_lab_only_tool_before_handler_and_evidence(self):
        """GREEN: the real lab-mode boundary is separately effective."""
        context = replace(
            self.context,
            is_lab=False,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
        )
        with self.assertRaises(ToolDenied):
            self._execute_offline(context)
        self.handler.assert_not_called()
        self.assertEqual(0, self._evidence_count())

    def test_context_and_call_are_not_mutated_by_denial(self):
        context = replace(self.context, approved_risk=RiskLevel.ELEVATED)
        original = (context, self.call)
        with self.assertRaises(RiskElevationRequired):
            self._execute_offline(context)
        self.assertEqual(original, (context, self.call))
        self.assertEqual(self.call.asset, "127.0.0.1")
        self.handler.assert_not_called()

    def test_approval_shape_not_present_in_raw_lab_context(self):
        """GREEN: a lab preset contains no trusted approval/attestation record."""
        self.assertIsNone(self.context.authorization)
        self.assertIs(self.context.approved_risk, RiskLevel.DESTRUCTIVE_LAB_ONLY)
        self.assertTrue(self.context.is_lab)
        self.assertFalse(hasattr(self.context, "operator_step_up"))
        self.assertFalse(hasattr(self.context, "lab_isolation_attestation"))
        self.handler.assert_not_called()

    def test_temporal_mutation_does_not_upgrade_lower_risk_run(self):
        """GREEN: shifting creation time alone must not bypass risk ceiling."""
        old = replace(
            self.context,
            created_at=self.context.created_at - timedelta(days=1),
            approved_risk=RiskLevel.ELEVATED,
        )
        with self.assertRaises(RiskElevationRequired):
            self._execute_offline(old)
        self.handler.assert_not_called()
        self.assertEqual(0, self._evidence_count())


    @expectedFailure
    def test_unapproved_risk_five_run_cannot_change_target_asset(self):
        """RED: lab context alone cannot authorize another synthetic target."""
        different_target = ToolCall("fixture-risk-five", "127.0.0.2")
        with self.assertRaises(ToolDenied):
            self._execute_offline(call=different_target)
        self.handler.assert_not_called()
        self.assertEqual(0, self._evidence_count())

    @expectedFailure
    def test_unapproved_risk_five_run_cannot_change_tool_capability(self):
        """RED: step-up must bind tool AND capability, not only run/lab flag."""
        second_handler = Mock(return_value=ToolOutput(
            summary="synthetic-api-only",
            evidence_kind="test-fixture",
            evidence_payload=b"offline-fixture-second-tool",
        ))
        self.registry.register(
            ToolDefinition(
                tool_id="fixture-risk-five-api",
                capability_id="api-baseline",
                interaction=InteractionKind.LAB_ACTIVE,
                min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                description="second inert fixture; no external interaction",
            ),
            second_handler,
        )
        different_tool = ToolCall("fixture-risk-five-api", "127.0.0.1")
        with self.assertRaises(ToolDenied):
            self._execute_offline(call=different_tool)
        self.handler.assert_not_called()
        second_handler.assert_not_called()
        self.assertEqual(0, self._evidence_count())

    def test_intentional_red_methods_fail_only_on_missing_denial(self):
        """GREEN witness: don't mask wrong fixture/setup/runtime as expected RED.

        Call each method directly, outside unittest's expectedFailure runner,
        so an unrelated AttributeError, TypeError or socket exception is fatal.
        Re-check each case against its own disposable SQLite and inert handler.
        After a source fix this fails and the RED declarations must be promoted.
        """
        cases = (
            ("test_risk_five_cannot_dispatch_on_for_lab_flag_without_step_up",
             "ToolDenied not raised"),
            ("test_risk_five_policy_cannot_treat_is_lab_as_operator_approval",
             "True is not false"),
            ("test_forged_risk_five_context_cannot_supply_missing_approval",
             "ToolDenied not raised"),
            ("test_unapproved_risk_five_run_cannot_change_target_asset",
             "ToolDenied not raised"),
            ("test_unapproved_risk_five_run_cannot_change_tool_capability",
             "ToolDenied not raised"),
        )
        for method, witness in cases:
            with self.subTest(red_method=method):
                probe = type(self)(method)
                probe.setUp()
                try:
                    with self.assertRaises(AssertionError) as actual:
                        getattr(probe, method)()
                    self.assertIn(witness, str(actual.exception))
                finally:
                    probe.doCleanups()
