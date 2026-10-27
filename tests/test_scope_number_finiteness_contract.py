"""Offline contract for finite NUMBER arguments; no external target interaction.

The pending production fix is owned by the orchestration source owner (#1143).
Expected failures are deliberately explicit: they must become regular assertions
when the finite-value policy is enforced before any handler invocation.
"""
from __future__ import annotations

import math
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


def _number_tool() -> ToolDefinition:
    return ToolDefinition(
        tool_id="offline-finite-number",
        capability_id="web-baseline",
        interaction=InteractionKind.LAB_ACTIVE,
        min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
        description="Offline type validation fixture; never registered or dispatched",
        parameters=(ToolParameter("limit", ParamKind.NUMBER),),
    )


class FiniteNumberContractTests(unittest.TestCase):
    def test_builtin_finite_numbers_remain_accepted(self) -> None:
        for value in (0, -1, 1, 0.5, -0.5, 1e200, -1e-200):
            with self.subTest(value=value):
                self.assertTrue(math.isfinite(value))
                _number_tool().validate_arguments({"limit": value})

    def test_boolean_is_not_a_number(self) -> None:
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(OrchestrationError):
                    _number_tool().validate_arguments({"limit": value})

    @unittest.expectedFailure
    def test_nonfinite_nan_must_be_denied(self) -> None:
        with self.assertRaises(OrchestrationError):
            _number_tool().validate_arguments({"limit": float("nan")})

    @unittest.expectedFailure
    def test_nonfinite_positive_infinity_must_be_denied(self) -> None:
        with self.assertRaises(OrchestrationError):
            _number_tool().validate_arguments({"limit": float("inf")})

    @unittest.expectedFailure
    def test_nonfinite_negative_infinity_must_be_denied(self) -> None:
        with self.assertRaises(OrchestrationError):
            _number_tool().validate_arguments({"limit": float("-inf")})


if __name__ == "__main__":
    unittest.main()
