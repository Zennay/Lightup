from __future__ import annotations

import unittest

from lightup.ai.orchestration import (
    InteractionKind,
    OrchestrationError,
    ParamKind,
    ToolDefinition,
    ToolParameter,
    ToolRegistry,
)
from lightup.engagements import RiskLevel


def _definition(required: object) -> ToolDefinition:
    return ToolDefinition(
        tool_id="parameter-required-integrity",
        capability_id="web-baseline",
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="parameter required metadata contract",
        parameters=(
            ToolParameter(
                name="url",
                kind=ParamKind.STRING,
                required=required,
                description="target URL",
            ),
        ),
    )


class ToolParameterRequiredIntegrityTest(unittest.TestCase):
    def test_exact_true_remains_registerable_and_required(self):
        registry = ToolRegistry()
        definition = _definition(True)

        registry.register(definition, lambda *_args: None)

        with self.assertRaisesRegex(OrchestrationError, "missing required argument"):
            definition.validate_arguments({})

    def test_exact_false_remains_registerable_and_optional(self):
        registry = ToolRegistry()
        definition = _definition(False)

        registry.register(definition, lambda *_args: None)

        definition.validate_arguments({})

    def test_non_boolean_required_markers_fail_before_registry_insertion(self):
        for required in (0, 1, "", "false", None):
            with self.subTest(required=repr(required)):
                registry = ToolRegistry()
                definition = _definition(required)

                with self.assertRaisesRegex(
                    OrchestrationError, "required.*bool|bool.*required"
                ):
                    registry.register(definition, lambda *_args: None)

                self.assertEqual(registry.definitions(), ())


if __name__ == "__main__":
    unittest.main()
