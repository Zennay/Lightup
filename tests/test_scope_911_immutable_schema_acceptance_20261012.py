"""#911: ToolDefinition.parameters schema must be an exact immutable tuple.

Add-only, synthetic offline owner acceptance above ToolRegistry PR #156.
Expected failures mark the unfixed owner boundary, not successful enforcement.
No handler is ever invoked.
"""
from __future__ import annotations

import dataclasses
import unittest

from lightup.ai.orchestration import (
    OrchestrationError,
    ParamKind,
    ToolDefinition,
    ToolParameter,
    ToolRegistry,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


class _ParameterSubclass(ToolParameter):
    pass


class _DuckParameter:
    name = "query"
    kind = ParamKind.STRING
    required = True
    description = ""


class _HostileIterable:
    def __iter__(self):
        raise AssertionError("do not iterate untrusted schema before checking its exact type")


class ToolDefinitionParameterSchemaAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = ToolRegistry()
        self.handler_calls = 0

    def _handler(self, *_args):
        self.handler_calls += 1
        raise AssertionError("no handler may execute in registry-schema acceptance")

    def _definition(self, parameters, name="schema-contract"):
        return ToolDefinition(
            tool_id=name,
            capability_id="external-attack-surface",
            interaction=InteractionKind.PASSIVE_PUBLIC,
            min_risk=RiskLevel.PASSIVE,
            description="offline synthetic schema fixture",
            parameters=parameters,
        )

    def _assert_reject_atomic(self, parameters) -> None:
        prior = self.registry.definitions()
        bad = self._definition(parameters)
        with self.assertRaises(OrchestrationError):
            self.registry.register(bad, self._handler)
        self.assertEqual(self.registry.definitions(), prior)
        with self.assertRaises(OrchestrationError):
            self.registry.get(bad.tool_id)
        self.assertEqual(self.handler_calls, 0)

    def test_exact_tuple_parameter_is_stable_positive_control(self) -> None:
        parameter = ToolParameter("query", ParamKind.STRING, required=True)
        parameters = (parameter,)
        definition = self._definition(parameters)
        self.registry.register(definition, self._handler)
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({})
        definition.validate_arguments({"query": "synthetic"})
        self.assertIs(definition.parameters, parameters)
        self.assertIs(self.registry.get("schema-contract")[0], definition)
        self.assertEqual(self.handler_calls, 0)

    def test_exact_empty_tuple_is_valid_control(self) -> None:
        definition = self._definition(())
        self.registry.register(definition, self._handler)
        definition.validate_arguments({})
        self.assertEqual(self.registry.definitions(), (definition,))
        self.assertEqual(self.handler_calls, 0)

    def test_frozen_field_reassignment_is_not_mutable_container_proof(self) -> None:
        definition = self._definition((ToolParameter("query", ParamKind.STRING),))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            definition.parameters = ()
        self.assertEqual(len(definition.parameters), 1)
        self.assertEqual(self.handler_calls, 0)

    @unittest.expectedFailure
    def test_list_parameter_container_must_be_rejected(self) -> None:
        self._assert_reject_atomic([ToolParameter("query", ParamKind.STRING)])

    @unittest.expectedFailure
    def test_set_parameter_container_must_be_rejected(self) -> None:
        self._assert_reject_atomic({ToolParameter("query", ParamKind.STRING)})

    @unittest.expectedFailure
    def test_mapping_parameter_container_must_be_rejected(self) -> None:
        self._assert_reject_atomic({"query": ToolParameter("query", ParamKind.STRING)})

    @unittest.expectedFailure
    def test_hostile_iterable_container_must_not_run_callback(self) -> None:
        self._assert_reject_atomic(_HostileIterable())

    @unittest.expectedFailure
    def test_parameter_subclass_must_be_rejected(self) -> None:
        self._assert_reject_atomic((_ParameterSubclass("query", ParamKind.STRING),))

    @unittest.expectedFailure
    def test_duck_parameter_object_must_be_rejected(self) -> None:
        self._assert_reject_atomic((_DuckParameter(),))

    @unittest.expectedFailure
    def test_mutation_cannot_remove_registered_required_parameter(self) -> None:
        original = [ToolParameter("query", ParamKind.STRING, required=True)]
        definition = self._definition(original)
        self.registry.register(definition, self._handler)
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({})
        # This must remain a rejection even if the caller changes its list.
        original.clear()
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({})
        self.assertEqual(self.handler_calls, 0)

    @unittest.expectedFailure
    def test_invalid_later_parameter_fails_atomically_with_existing_tool(self) -> None:
        good = self._definition((ToolParameter("query", ParamKind.STRING),), "good-tool")
        self.registry.register(good, self._handler)
        before = self.registry.definitions()
        bad = self._definition(
            (ToolParameter("query", ParamKind.STRING), _DuckParameter()),
            "bad-later-parameter",
        )
        with self.assertRaises(OrchestrationError):
            self.registry.register(bad, self._handler)
        self.assertEqual(self.registry.definitions(), before)
        self.assertIs(self.registry.get("good-tool")[0], good)
        with self.assertRaises(OrchestrationError):
            self.registry.get("bad-later-parameter")
        self.assertEqual(self.handler_calls, 0)


if __name__ == "__main__":
    unittest.main()
