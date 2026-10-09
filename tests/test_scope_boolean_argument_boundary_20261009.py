"""Offline regression for BOOLEAN argument admission; no target I/O."""
import unittest

from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter,
)


class BooleanArgumentBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.schema = ToolDefinition(
            tool_id="offline-boolean-contract",
            capability_id="offline-only",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="Inert schema validation only",
            parameters=(ToolParameter("enabled", ParamKind.BOOLEAN, required=True),),
        )

    def test_exact_boolean_true_false_accepted(self):
        for value in (True, False):
            with self.subTest(value=value):
                self.schema.validate_arguments({"enabled": value})

    def test_integer_and_string_lookalikes_rejected(self):
        for value in (0, 1, "true", "false", "0", "1", None, 0.0, 1.0):
            with self.subTest(value=repr(value)):
                with self.assertRaises(OrchestrationError):
                    self.schema.validate_arguments({"enabled": value})

    def test_boolean_is_not_integer_or_number(self):
        # bool subclasses int: typed admission must still distinguish these kinds.
        for kind in (ParamKind.INTEGER, ParamKind.NUMBER):
            with self.subTest(kind=kind):
                schema = ToolDefinition(
                    tool_id="offline-bool-not-number",
                    capability_id="offline-only",
                    interaction=InteractionKind.ANALYSIS,
                    min_risk=RiskLevel.ANALYSIS_ONLY,
                    description="Schema-only cross-kind check",
                    parameters=(ToolParameter("value", kind, required=True),),
                )
                for value in (True, False):
                    with self.assertRaises(OrchestrationError):
                        schema.validate_arguments({"value": value})

    def test_optional_boolean_is_optional_but_not_coerced(self):
        schema = ToolDefinition(
            tool_id="offline-optional-boolean",
            capability_id="offline-only",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="Schema-only optional contract",
            parameters=(ToolParameter("enabled", ParamKind.BOOLEAN, required=False),),
        )
        schema.validate_arguments({})
        schema.validate_arguments({"enabled": False})
        with self.assertRaises(OrchestrationError):
            schema.validate_arguments({"enabled": 0})

    def test_missing_boolean_rejected(self):
        with self.assertRaises(OrchestrationError):
            self.schema.validate_arguments({})

    def test_unknown_argument_rejected_without_mutating_input(self):
        original = {"enabled": False, "grant_approved": True}
        snapshot = dict(original)
        with self.assertRaises(OrchestrationError):
            self.schema.validate_arguments(original)
        self.assertEqual(original, snapshot)


if __name__ == "__main__":
    unittest.main()
