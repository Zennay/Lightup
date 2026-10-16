"""#1143 original ToolExecutor NUMBER source gap: safe, synthetic expected-REDs.

Independent of existing #1142 characterization and the already-existing opt-in
finite-number reviewer. Nothing here is a production gate or a release signal.
No real target, socket, subprocess, grant, filesystem ledger or handler I/O.
"""
from __future__ import annotations

import math
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
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


if __name__ == "__main__":
    unittest.main()
