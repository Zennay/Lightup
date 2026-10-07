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


class ParameterSubclass(ToolParameter):
    pass


class DuckParameter:
    name = "url"
    kind = ParamKind.STRING
    required = True
    description = "duck parameter"


def _definition(parameters) -> ToolDefinition:
    return ToolDefinition(
        tool_id="parameter-schema-integrity",
        capability_id="web-baseline",
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="parameter schema integrity",
        parameters=parameters,
    )


class ToolParameterSchemaIntegrityTest(unittest.TestCase):
    def test_exact_tuple_of_exact_parameters_remains_registerable(self):
        registry = ToolRegistry()
        parameter = ToolParameter("url", ParamKind.STRING, True, "target URL")
        definition = _definition((parameter,))

        registry.register(definition, lambda *_args: None)

        self.assertEqual(registry.definitions(), (definition,))
        with self.assertRaisesRegex(OrchestrationError, "missing required argument"):
            definition.validate_arguments({})

    def test_mutable_parameter_list_is_rejected_before_insertion(self):
        registry = ToolRegistry()
        parameters = [ToolParameter("url", ParamKind.STRING, True, "target URL")]
        definition = _definition(parameters)

        with self.assertRaisesRegex(
            OrchestrationError, "parameters.*tuple|tuple.*parameters"
        ):
            registry.register(definition, lambda *_args: None)

        self.assertEqual(registry.definitions(), ())
        self.assertEqual(len(parameters), 1)

    def test_parameter_subclass_is_rejected_before_insertion(self):
        registry = ToolRegistry()
        definition = _definition(
            (ParameterSubclass("url", ParamKind.STRING, True, "target URL"),)
        )

        with self.assertRaisesRegex(
            OrchestrationError, "ToolParameter|tool parameter"
        ):
            registry.register(definition, lambda *_args: None)

        self.assertEqual(registry.definitions(), ())

    def test_duck_parameter_is_rejected_before_insertion(self):
        registry = ToolRegistry()
        definition = _definition((DuckParameter(),))

        with self.assertRaisesRegex(
            OrchestrationError, "ToolParameter|tool parameter"
        ):
            registry.register(definition, lambda *_args: None)

        self.assertEqual(registry.definitions(), ())


if __name__ == "__main__":
    unittest.main()
