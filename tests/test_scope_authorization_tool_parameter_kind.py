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


class AcceptEverythingKind:
    value = "string"

    def accepts(self, _value):
        return True


def _definition(kind: object) -> ToolDefinition:
    return ToolDefinition(
        tool_id="parameter-kind-integrity",
        capability_id="web-baseline",
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="parameter kind integrity",
        parameters=(
            ToolParameter(
                name="url",
                kind=kind,
                required=True,
                description="target URL",
            ),
        ),
    )


class ToolParameterKindIntegrityTest(unittest.TestCase):
    def test_canonical_param_kind_remains_registerable(self):
        registry = ToolRegistry()
        definition = _definition(ParamKind.STRING)

        registry.register(definition, lambda *_args: None)

        self.assertEqual(registry.definitions(), (definition,))
        with self.assertRaisesRegex(OrchestrationError, "must be a string"):
            definition.validate_arguments({"url": 123})

    def test_raw_string_kind_is_rejected_before_insertion(self):
        registry = ToolRegistry()

        with self.assertRaisesRegex(
            OrchestrationError, "ParamKind|parameter kind"
        ):
            registry.register(_definition("string"), lambda *_args: None)

        self.assertEqual(registry.definitions(), ())

    def test_duck_kind_cannot_replace_acceptance_semantics(self):
        registry = ToolRegistry()

        with self.assertRaisesRegex(
            OrchestrationError, "ParamKind|parameter kind"
        ):
            registry.register(
                _definition(AcceptEverythingKind()),
                lambda *_args: None,
            )

        self.assertEqual(registry.definitions(), ())


if __name__ == "__main__":
    unittest.main()
