"""#907: exact outer ToolDefinition registry admission on frozen #156 owner source.

Only synthetic in-process objects; no registry handler is ever called.
Expected failures are real OPEN owner-source boundaries, NOT fixed authorizations.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter, ToolRegistry,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


def NEVER_INVOKE_HANDLER(*_args, **_kwargs):
    raise AssertionError("a registry admission test must never invoke a handler")


def canonical_definition(tool_id="offline-canonical"):
    return ToolDefinition(
        tool_id=tool_id, capability_id="external-attack-surface",
        interaction=InteractionKind.PASSIVE_PUBLIC, min_risk=RiskLevel.PASSIVE,
        description="synthetic offline registry contract",
        parameters=(ToolParameter("query", ParamKind.STRING),),
    )


class PlainSubclassDefinition(ToolDefinition):
    pass


class OverrideValidatorDefinition(ToolDefinition):
    def validate_arguments(self, arguments):
        # Dangerous if admitted by ToolRegistry: the required query vanishes.
        return None


class DuckDefinition:
    """Forged registry metadata with a bypass method, never a ToolDefinition."""
    tool_id = "offline-duck"
    capability_id = "external-attack-surface"
    interaction = InteractionKind.PASSIVE_PUBLIC
    min_risk = RiskLevel.PASSIVE
    description = "fictional duck"
    parameters = (ToolParameter("query", ParamKind.STRING),)

    def validate_arguments(self, arguments):
        return None


class PropertySpyDefinition:
    """Getters must never be read before exact outer-shape validation."""
    def __init__(self):
        self.reads = 0

    @property
    def tool_id(self):
        self.reads += 1
        return "offline-spy"

    @property
    def capability_id(self):
        self.reads += 1
        return "external-attack-surface"

    @property
    def interaction(self):
        self.reads += 1
        return InteractionKind.PASSIVE_PUBLIC

    @property
    def min_risk(self):
        self.reads += 1
        return RiskLevel.PASSIVE


class ToolDefinitionOwner156OuterBoundary(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()

    def assert_rejected_without_registration(self, candidate):
        # A controlled OrchestrationError denial is required (not AttributeError).
        with self.assertRaises(OrchestrationError):
            self.registry.register(candidate, NEVER_INVOKE_HANDLER)
        self.assertEqual(self.registry.definitions(), ())

    def test_exact_definition_registers_and_stays_same_identity(self):
        definition = canonical_definition()
        self.registry.register(definition, NEVER_INVOKE_HANDLER)
        found, handler = self.registry.get(definition.tool_id)
        self.assertIs(found, definition)
        self.assertIs(handler, NEVER_INVOKE_HANDLER)
        self.assertEqual(self.registry.definitions(), (definition,))

    def test_exact_definition_preserves_required_argument_validator(self):
        definition = canonical_definition()
        self.registry.register(definition, NEVER_INVOKE_HANDLER)
        with self.assertRaises(OrchestrationError):
            self.registry.get(definition.tool_id)[0].validate_arguments({})
        self.registry.get(definition.tool_id)[0].validate_arguments({"query": "offline"})

    def test_exact_duplicate_tool_id_remains_denied(self):
        definition = canonical_definition()
        self.registry.register(definition, NEVER_INVOKE_HANDLER)
        with self.assertRaises(OrchestrationError):
            self.registry.register(definition, NEVER_INVOKE_HANDLER)
        self.assertEqual(self.registry.definitions(), (definition,))

    def test_existing_lab_only_coherence_denies_passive_wireless(self):
        definition = ToolDefinition(
            "offline-wireless", "wireless-lab", InteractionKind.PASSIVE_PUBLIC,
            RiskLevel.PASSIVE, "fictional lab capability",
        )
        self.assert_rejected_without_registration(definition)

    def test_existing_malformed_inner_interaction_rejected(self):
        definition = ToolDefinition(
            "offline-bad-kind", "external-attack-surface", "passive_public",
            RiskLevel.PASSIVE, "fictional invalid interaction",
        )
        self.assert_rejected_without_registration(definition)

    @unittest.expectedFailure
    def test_red_plain_subclass_must_be_denied(self):
        original = canonical_definition()
        candidate = PlainSubclassDefinition(**vars(original))
        self.assert_rejected_without_registration(candidate)

    @unittest.expectedFailure
    def test_red_subclass_argument_override_must_not_enter_registry(self):
        original = canonical_definition("offline-override")
        candidate = OverrideValidatorDefinition(**vars(original))
        self.assert_rejected_without_registration(candidate)

    @unittest.expectedFailure
    def test_red_duck_definition_must_not_be_registered(self):
        self.assert_rejected_without_registration(DuckDefinition())

    @unittest.expectedFailure
    def test_red_no_getter_reads_before_type_check(self):
        candidate = PropertySpyDefinition()
        self.assert_rejected_without_registration(candidate)
        self.assertEqual(candidate.reads, 0)

    @unittest.expectedFailure
    def test_red_empty_nondefinition_returns_typed_rejection(self):
        self.assert_rejected_without_registration(object())

    def test_expected_red_replay_oracle(self):
        names = sorted(name for name in dir(type(self))
                       if name.startswith("test_red_"))
        self.assertEqual(len(names), 5)
        result = unittest.TestResult()
        unittest.TestSuite(type(self)(name) for name in names).run(result)
        self.assertEqual(result.testsRun, 5)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.unexpectedSuccesses, [],
                         "owner code changed: deliberately promote fixed RED assertions")
        self.assertEqual(len(result.expectedFailures), 5,
                         "all five installed owner-source RED cases must remain reproduced")


if __name__ == "__main__":
    unittest.main()
