from __future__ import annotations

import unittest

from lightup.ai.orchestration import (
    InteractionKind,
    OrchestrationError,
    ToolDefinition,
    ToolOutput,
    ToolRegistry,
)
from lightup.engagements import RiskLevel


def _handler(_context, _arguments):
    return ToolOutput(
        summary="not executed",
        evidence_kind="test",
        evidence_payload=b"",
    )


class PolymorphicDefinition(ToolDefinition):
    def validate_arguments(self, arguments):
        # This intentionally replaces the canonical typed argument contract.
        return None


class DuckDefinition:
    tool_id = "duck-analysis"
    capability_id = "web-baseline"
    interaction = InteractionKind.ANALYSIS
    min_risk = RiskLevel.ANALYSIS_ONLY
    description = "structurally compatible but non-canonical"
    parameters = ()

    def validate_arguments(self, arguments):
        return None


def _canonical(tool_id: str = "canonical-analysis") -> ToolDefinition:
    return ToolDefinition(
        tool_id=tool_id,
        capability_id="web-baseline",
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="canonical analysis tool",
    )


class ToolDefinitionObjectIntegrityTest(unittest.TestCase):
    def test_exact_definition_remains_registerable(self):
        registry = ToolRegistry()
        definition = _canonical()

        registry.register(definition, _handler)

        self.assertEqual(registry.definitions(), (definition,))

    def test_definition_subclass_is_rejected_before_insertion(self):
        registry = ToolRegistry()
        definition = PolymorphicDefinition(
            tool_id="subclass-analysis",
            capability_id="web-baseline",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="polymorphic definition",
        )

        with self.assertRaisesRegex(
            OrchestrationError, "ToolDefinition|tool definition"
        ):
            registry.register(definition, _handler)

        self.assertEqual(registry.definitions(), ())

    def test_duck_definition_is_rejected_before_insertion(self):
        registry = ToolRegistry()

        with self.assertRaisesRegex(
            OrchestrationError, "ToolDefinition|tool definition"
        ):
            registry.register(DuckDefinition(), _handler)

        self.assertEqual(registry.definitions(), ())


if __name__ == "__main__":
    unittest.main()
