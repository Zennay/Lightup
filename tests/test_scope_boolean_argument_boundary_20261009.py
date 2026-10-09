"""Offline regression for BOOLEAN argument admission; no target I/O."""
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter,
)


class BooleanArgumentBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.schema = ToolDefinition(
            tool_id="offline-boolean-contract",
            capability_id="offline-only",
            interaction=__import__("lightup.execution_policy", fromlist=["InteractionKind"]).InteractionKind.PLAN_ONLY,
            min_risk=__import__("lightup.engagements", fromlist=["RiskLevel"]).RiskLevel.LOW,
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
