from __future__ import annotations

import unittest
from enum import IntEnum

from lightup.ai.orchestration import (
    OrchestrationError,
    ParamKind,
    ToolDefinition,
    ToolParameter,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _FloatSubclass(float):
    pass


class _IntEnumValue(IntEnum):
    ONE = 1


def _definition(kind: ParamKind) -> ToolDefinition:
    return ToolDefinition(
        tool_id=f"value-{kind.value}",
        capability_id="network-services",
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="Primitive value identity acceptance schema",
        parameters=(ToolParameter("value", kind, required=True),),
    )


class ToolArgumentValueTypeAcceptanceTests(unittest.TestCase):
    def test_exact_builtin_controls_remain_valid(self):
        controls = (
            (ParamKind.STRING, "value"),
            (ParamKind.INTEGER, 7),
            (ParamKind.NUMBER, 7),
            (ParamKind.NUMBER, 1.5),
            (ParamKind.BOOLEAN, True),
            (ParamKind.BOOLEAN, False),
        )
        for kind, value in controls:
            with self.subTest(kind=kind, value=value):
                _definition(kind).validate_arguments({"value": value})

    def test_string_subclass_is_rejected(self):
        with self.assertRaises(OrchestrationError):
            _definition(ParamKind.STRING).validate_arguments(
                {"value": _StringSubclass("value")}
            )

    def test_integer_subclass_is_rejected(self):
        with self.assertRaises(OrchestrationError):
            _definition(ParamKind.INTEGER).validate_arguments(
                {"value": _IntSubclass(7)}
            )

    def test_int_enum_is_rejected_as_integer(self):
        with self.assertRaises(OrchestrationError):
            _definition(ParamKind.INTEGER).validate_arguments(
                {"value": _IntEnumValue.ONE}
            )

    def test_integer_subclass_is_rejected_as_number(self):
        with self.assertRaises(OrchestrationError):
            _definition(ParamKind.NUMBER).validate_arguments(
                {"value": _IntSubclass(7)}
            )

    def test_int_enum_is_rejected_as_number(self):
        with self.assertRaises(OrchestrationError):
            _definition(ParamKind.NUMBER).validate_arguments(
                {"value": _IntEnumValue.ONE}
            )

    def test_float_subclass_is_rejected_as_number(self):
        with self.assertRaises(OrchestrationError):
            _definition(ParamKind.NUMBER).validate_arguments(
                {"value": _FloatSubclass(1.5)}
            )

    def test_bool_does_not_gain_integer_or_number_authority(self):
        for kind in (ParamKind.INTEGER, ParamKind.NUMBER):
            with self.subTest(kind=kind):
                with self.assertRaises(OrchestrationError):
                    _definition(kind).validate_arguments({"value": True})


if __name__ == "__main__":
    unittest.main()
