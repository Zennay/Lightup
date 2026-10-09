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

    def test_rejection_preserves_input_and_subsequent_valid_admission(self):
        # A malformed attempt must not poison subsequent in-memory admission.
        rejected = {"enabled": "false"}
        snapshot = dict(rejected)
        with self.assertRaises(OrchestrationError):
            self.schema.validate_arguments(rejected)
        self.assertEqual(rejected, snapshot)
        self.schema.validate_arguments({"enabled": False})
        self.schema.validate_arguments({"enabled": True})

    def test_mixed_known_boolean_and_unknown_field_is_rejected(self):
        for boolean in (True, False):
            payload = {"enabled": boolean, "override": False}
            before = dict(payload)
            with self.subTest(boolean=boolean):
                with self.assertRaises(OrchestrationError):
                    self.schema.validate_arguments(payload)
                self.assertEqual(payload, before)

    def test_boolean_schema_isolation_from_string_schema(self):
        # Tool-specific schemas must not be reused for a different tool.
        string_schema = ToolDefinition(
            tool_id="offline-string-contract",
            capability_id="offline-only",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="Separate inert string schema",
            parameters=(ToolParameter("enabled", ParamKind.STRING, required=True),),
        )
        self.schema.validate_arguments({"enabled": True})
        string_schema.validate_arguments({"enabled": "true"})
        for schema, payload in (
            (self.schema, {"enabled": "true"}),
            (string_schema, {"enabled": True}),
        ):
            with self.subTest(tool_id=schema.tool_id):
                with self.assertRaises(OrchestrationError):
                    schema.validate_arguments(payload)

    def test_repeated_admission_does_not_change_boolean_schema(self):
        # Reusing the same definition across calls must preserve its contract.
        before = self.schema.parameters
        for value in (True, False, "true", 1, None, False, True):
            with self.subTest(value=repr(value)):
                if type(value) is bool:
                    self.schema.validate_arguments({"enabled": value})
                else:
                    with self.assertRaises(OrchestrationError):
                        self.schema.validate_arguments({"enabled": value})
                self.assertEqual(self.schema.parameters, before)

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
