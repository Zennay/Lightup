"""#1143 original ToolExecutor NUMBER source gap: safe, synthetic expected-REDs.

Independent of existing #1142 characterization and the already-existing opt-in
finite-number reviewer. Nothing here is a production gate or a release signal.
No real target, socket, subprocess, grant, filesystem ledger or handler I/O.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.finite_number_offline_review import snapshot_finite_number_arguments


class NumberSourceRed1143Tests(unittest.TestCase):
    """Exercise installed validation and executor using entirely synthetic mocks."""

    def setUp(self):
        self.handler = Mock(return_value=ToolOutput(
            summary="synthetic", evidence_kind="synthetic",
            evidence_payload=b"synthetic-only",
        ))
        self.ledger = Mock()
        self.ledger.add_evidence.return_value = "synthetic-evidence-id"
        self.registry = ToolRegistry()
        self.registry.register(ToolDefinition(
            tool_id="fixture.number.1143",
            capability_id="web-baseline",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="offline NUMBER admission fixture, not a target adapter",
            parameters=(ToolParameter("measurement", ParamKind.NUMBER),),
        ), self.handler)
        # ALLOW is deliberately only a synthetic mock after argument validation,
        # not an actual approval or consent. This isolates the original source
        # typed-argument behavior from unrelated grant/issuer ownership.
        self.policy = Mock()
        self.policy.decide.return_value = SimpleNamespace(
            allowed=True, reason="synthetic-test-only"
        )
        self.executor = ToolExecutor(self.registry, self.ledger, self.policy)
        self.context = RunContext.for_lab("fake-number-run-1143")

    def _call(self, value: object) -> ToolCall:
        return ToolCall("fixture.number.1143", "fixture.example.test",
                        (("measurement", value),))

    def _assert_original_executor_denies_before_side_effects(self, value: float) -> None:
        # This is intentionally an UNRESOLVED source-owner requirement.
        # Existing ParamKind.NUMBER accepts NaN/Infinity; expectedFailure
        # records the original source RED without turning CI falsely green.
        with patch.object(socket, "socket", side_effect=AssertionError("socket forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            with self.assertRaises(OrchestrationError):
                self.executor.execute(self.context, self._call(value))
        self.handler.assert_not_called()
        self.ledger.add_evidence.assert_not_called()
        self.policy.decide.assert_not_called()

    @unittest.expectedFailure
    def test_original_executor_must_reject_nan_before_handler(self):
        self._assert_original_executor_denies_before_side_effects(math.nan)

    @unittest.expectedFailure
    def test_original_executor_must_reject_positive_infinity_before_handler(self):
        self._assert_original_executor_denies_before_side_effects(math.inf)

    @unittest.expectedFailure
    def test_original_executor_must_reject_negative_infinity_before_handler(self):
        self._assert_original_executor_denies_before_side_effects(-math.inf)

    @unittest.expectedFailure
    def test_original_executor_must_reject_integer_above_resource_budget(self):
        # Distinct from finiteness: normal Python integers are exact/finite but
        # unconstrained sizes can amplify downstream conversion workloads.
        self._assert_original_executor_denies_before_side_effects(1 << 4096)

    def test_existing_unwired_strict_snapshot_denies_nonfinite_without_dispatch(self):
        for value in (math.nan, math.inf, -math.inf, 1 << 4096):
            with self.subTest(kind=str(type(value))):
                with self.assertRaises(ValueError):
                    snapshot_finite_number_arguments((("measurement", value),))
        self.handler.assert_not_called()
        self.ledger.add_evidence.assert_not_called()
        self.policy.decide.assert_not_called()

    def test_exact_finite_numbers_reach_mocked_analysis_control_only(self):
        for value in (0, 12, -3, 0.25, -0.0, 1 << 4095):
            with self.subTest(kind=type(value).__name__, bits=value.bit_length() if isinstance(value, int) else 0):
                self.handler.reset_mock()
                self.ledger.reset_mock()
                canonical = snapshot_finite_number_arguments((("measurement", value),))
                result = self.executor.execute(
                    self.context,
                    ToolCall("fixture.number.1143", "fixture.example.test", canonical),
                )
                self.assertEqual(result.evidence_id, "synthetic-evidence-id")
                self.handler.assert_called_once()
                self.ledger.add_evidence.assert_called_once()
        # A synthetic mock success does not authenticate any live grant.

    def test_installed_source_gap_is_not_misreported_as_repaired(self):
        # This is a factual red characterization, never a normative assertion.
        # Delete this check when the original source owner fixes #1143.
        self.assertTrue(ParamKind.NUMBER.accepts(float("nan")))
        self.assertTrue(ParamKind.NUMBER.accepts(float("inf")))
        self.assertTrue(ParamKind.NUMBER.accepts(float("-inf")))



class NumberOriginalPolicyRed1143Tests(unittest.TestCase):
    """Second integration: original unmodified ExecutionPolicy, no mock allow."""

    def setUp(self):
        self.handler = Mock(return_value=ToolOutput(
            "mocked-analysis", "synthetic", b"synthetic-only"
        ))
        self.state = Mock()
        self.state.add_evidence.return_value = "mock-evidence"
        registry = ToolRegistry()
        registry.register(ToolDefinition(
            "fixture.real-policy-number.1143", "web-baseline",
            InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
            "pure offline analysis fixture",
            (ToolParameter("measurement", ParamKind.NUMBER),),
        ), self.handler)
        # ORIGINAL ExecutionPolicy, unlike synthetic allow in schema tests.
        self.executor = ToolExecutor(registry, self.state, ExecutionPolicy())
        self.context = RunContext(
            run_id="fictional-realpolicy-run", client_id="fictional-client",
            engagement_id="fictional-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _request(self, measurement):
        return ToolCall(
            "fixture.real-policy-number.1143", "fixture.example.test",
            (("measurement", measurement),),
        )

    def _assert_denial_before_handler(self, measurement):
        with patch.object(socket, "socket", side_effect=AssertionError("no socket")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("no process")):
            with self.assertRaises(OrchestrationError):
                self.executor.execute(self.context, self._request(measurement))
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    @unittest.expectedFailure
    def test_real_policy_executor_must_deny_nan_pre_handler(self):
        self._assert_denial_before_handler(math.nan)

    @unittest.expectedFailure
    def test_real_policy_executor_must_deny_positive_inf_pre_handler(self):
        self._assert_denial_before_handler(math.inf)

    @unittest.expectedFailure
    def test_real_policy_executor_must_deny_negative_inf_pre_handler(self):
        self._assert_denial_before_handler(-math.inf)


    def _multifield_request(self, third):
        # This second fixture uses three actual NUMBER parameters to catch a
        # late invalid value after two already-validated, harmless arguments.
        self.executor.registry.register(ToolDefinition(
            "fixture.real-policy-multi-number.1143", "web-baseline",
            InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
            "atomic offline NUMBER batch",
            (ToolParameter("first", ParamKind.NUMBER),
             ToolParameter("second", ParamKind.NUMBER),
             ToolParameter("third", ParamKind.NUMBER)),
        ), self.handler)
        return ToolCall(
            "fixture.real-policy-multi-number.1143", "fixture.example.test",
            (("first", 1), ("second", -0.125), ("third", third)),
        )

    def _assert_late_denial_no_partial_effects(self, value):
        call = self._multifield_request(value)
        with patch.object(socket, "socket", side_effect=AssertionError("no socket")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("no process")):
            with self.assertRaises(OrchestrationError):
                self.executor.execute(self.context, call)
        self.handler.assert_not_called()
        self.state.add_evidence.assert_not_called()

    @unittest.expectedFailure
    def test_real_policy_late_nan_requires_atomic_rejection(self):
        self._assert_late_denial_no_partial_effects(math.nan)

    @unittest.expectedFailure
    def test_real_policy_late_positive_inf_requires_atomic_rejection(self):
        self._assert_late_denial_no_partial_effects(math.inf)

    @unittest.expectedFailure
    def test_real_policy_late_negative_inf_requires_atomic_rejection(self):
        self._assert_late_denial_no_partial_effects(-math.inf)

    @unittest.expectedFailure
    def test_real_policy_late_giant_integer_requires_atomic_rejection(self):
        self._assert_late_denial_no_partial_effects(1 << 4096)

    def test_real_policy_atomic_multifield_finite_control(self):
        call = self._multifield_request((1 << 4096) - 1)
        with patch.object(socket, "socket", side_effect=AssertionError("no socket")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("no process")):
            result = self.executor.execute(self.context, call)
        self.assertEqual(result.policy_reason, "analysis-only")
        self.handler.assert_called_once()
        self.state.add_evidence.assert_called_once()


    def test_real_policy_finite_control_stays_synthetic_and_mocked(self):
        with patch.object(socket, "socket", side_effect=AssertionError("no socket")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("no process")):
            result = self.executor.execute(
                self.context, self._request(0.25)
            )
        self.assertEqual(result.policy_reason, "analysis-only")
        self.assertEqual(result.evidence_id, "mock-evidence")
        self.handler.assert_called_once()
        self.state.add_evidence.assert_called_once()


if __name__ == "__main__":
    unittest.main()
