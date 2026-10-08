"""RED acceptance tests: schema parameter names must not collide.

Offline-only; no handler is invoked, no target is contacted.
"""
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter, ToolRegistry,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


class DuplicateToolSchemaAdmissionTests(unittest.TestCase):
    def test_duplicate_parameter_names_rejected_before_registry_mutation(self):
        registry = ToolRegistry()
        definition = ToolDefinition(
            tool_id="duplicate-schema",
            capability_id="web-baseline",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.PASSIVE,
            description="Offline duplicate-schema sentinel",
            parameters=(
                ToolParameter("target", ParamKind.STRING),
                ToolParameter("target", ParamKind.BOOLEAN),
            ),
        )
        before = registry.definitions()
        with self.assertRaises(OrchestrationError):
            registry.register(definition, lambda _ctx, _args: self.fail("handler executed"))
        self.assertEqual(before, registry.definitions())

    def test_duplicate_names_even_with_identical_kind_are_rejected(self):
        registry = ToolRegistry()
        definition = ToolDefinition(
            tool_id="duplicate-same-kind",
            capability_id="web-baseline",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.PASSIVE,
            description="Offline duplicate-schema sentinel",
            parameters=(
                ToolParameter("target", ParamKind.STRING),
                ToolParameter("target", ParamKind.STRING, required=False),
            ),
        )
        with self.assertRaises(OrchestrationError):
            registry.register(definition, lambda _ctx, _args: self.fail("handler executed"))
        self.assertEqual((), registry.definitions())


    def test_unique_parameters_remain_admissible(self):
        registry = ToolRegistry()
        definition = ToolDefinition(
            tool_id="unique-schema",
            capability_id="web-baseline",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.PASSIVE,
            description="Positive control: two distinct names",
            parameters=(
                ToolParameter("target", ParamKind.STRING),
                ToolParameter("limit", ParamKind.INTEGER, required=False),
            ),
        )
        registry.register(definition, lambda _ctx, _args: self.fail("handler executed"))
        self.assertEqual((definition,), registry.definitions())
        definition.validate_arguments({"target": "offline.example.test", "limit": 3})

    def test_empty_parameter_schema_remains_admissible(self):
        registry = ToolRegistry()
        definition = ToolDefinition(
            tool_id="no-params",
            capability_id="web-baseline",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.PASSIVE,
            description="Positive control: empty schema",
            parameters=(),
        )
        registry.register(definition, lambda _ctx, _args: self.fail("handler executed"))
        self.assertEqual((definition,), registry.definitions())
        definition.validate_arguments({})


if __name__ == "__main__":
    unittest.main()
