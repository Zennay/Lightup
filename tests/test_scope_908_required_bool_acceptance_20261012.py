"""#908: ToolParameter.required is an exact-bool authorization metadata boundary.

Acceptance-only child of the ToolRegistry source-owner PR #156.  Negative
cases are expected failures against the still-vulnerable source; turning
them green requires an owner repair followed by removing expectedFailure.
Nothing here executes any handler, performs DNS, or grants authority.
"""
from __future__ import annotations

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


class _ExplodingTruthiness:
    def __bool__(self) -> bool:
        raise AssertionError("untrusted required metadata must not be coerced")


class _FalsyTruthiness:
    def __bool__(self) -> bool:
        return False


class ToolParameterRequiredBoolAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = ToolRegistry()
        self.handler_calls = 0

    def _handler(self, *_args):
        self.handler_calls += 1
        raise AssertionError("handler must never run in metadata admission tests")

    def _definition(self, required: object, tool_id: str = "required-boundary") -> ToolDefinition:
        return ToolDefinition(
            tool_id=tool_id,
            capability_id="external-attack-surface",
            interaction=InteractionKind.PASSIVE_PUBLIC,
            min_risk=RiskLevel.PASSIVE,
            description="offline typed metadata fixture",
            parameters=(ToolParameter("query", ParamKind.STRING, required=required),),
        )

    def _assert_refused_atomically(self, marker: object) -> None:
        # A bad parameter must not be silently registered as an optional tool.
        original = self.registry.definitions()
        definition = self._definition(marker)
        with self.assertRaises(OrchestrationError):
            self.registry.register(definition, self._handler)
        self.assertEqual(self.registry.definitions(), original)
        with self.assertRaises(OrchestrationError):
            self.registry.get(definition.tool_id)
        self.assertEqual(self.handler_calls, 0)

    def test_exact_true_requires_present_typed_argument(self) -> None:
        definition = self._definition(True)
        self.registry.register(definition, self._handler)
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({})
        definition.validate_arguments({"query": "offline"})
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({"query": 2})
        self.assertEqual(len(self.registry.definitions()), 1)
        self.assertEqual(self.handler_calls, 0)

    def test_exact_false_allows_omitted_argument_but_checks_present_argument(self) -> None:
        definition = self._definition(False)
        self.registry.register(definition, self._handler)
        definition.validate_arguments({})
        definition.validate_arguments({"query": "offline"})
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({"query": object()})
        self.assertEqual(self.handler_calls, 0)

    def test_true_and_false_remain_distinct_even_though_bools_are_ints(self) -> None:
        self.assertIs(type(self._definition(True).parameters[0].required), bool)
        self.assertIs(type(self._definition(False).parameters[0].required), bool)
        self.assertIsNot(type(self._definition(1).parameters[0].required), bool)
        self.assertIsNot(type(self._definition(0).parameters[0].required), bool)

    @unittest.expectedFailure
    def test_zero_is_not_optional(self) -> None:
        self._assert_refused_atomically(0)

    @unittest.expectedFailure
    def test_empty_string_is_not_optional(self) -> None:
        self._assert_refused_atomically("")

    @unittest.expectedFailure
    def test_none_is_not_optional(self) -> None:
        self._assert_refused_atomically(None)

    @unittest.expectedFailure
    def test_empty_tuple_is_not_optional(self) -> None:
        self._assert_refused_atomically(())

    @unittest.expectedFailure
    def test_empty_dict_is_not_optional(self) -> None:
        self._assert_refused_atomically({})

    @unittest.expectedFailure
    def test_integer_one_is_not_true(self) -> None:
        self._assert_refused_atomically(1)

    @unittest.expectedFailure
    def test_nonempty_string_is_not_true(self) -> None:
        self._assert_refused_atomically("true")

    @unittest.expectedFailure
    def test_custom_falsey_object_is_rejected_without_coercion(self) -> None:
        self._assert_refused_atomically(_FalsyTruthiness())

    @unittest.expectedFailure
    def test_exploding_truthiness_is_rejected_without_callback(self) -> None:
        self._assert_refused_atomically(_ExplodingTruthiness())


    @unittest.expectedFailure
    def test_existing_registry_remains_intact_after_late_bad_parameter(self) -> None:
        # Do not partially register a new tool or replace a previous valid one.
        valid = self._definition(True, "already-registered")
        self.registry.register(valid, self._handler)
        before = self.registry.definitions()
        malformed = ToolDefinition(
            tool_id="two-parameters",
            capability_id="external-attack-surface",
            interaction=InteractionKind.PASSIVE_PUBLIC,
            min_risk=RiskLevel.PASSIVE,
            description="later nested marker fails atomically",
            parameters=(
                ToolParameter("query", ParamKind.STRING, required=True),
                ToolParameter("tag", ParamKind.STRING, required=0),
            ),
        )
        with self.assertRaises(OrchestrationError):
            self.registry.register(malformed, self._handler)
        self.assertEqual(self.registry.definitions(), before)
        self.assertIs(self.registry.get("already-registered")[0], valid)
        with self.assertRaises(OrchestrationError):
            self.registry.get("two-parameters")
        self.assertEqual(self.handler_calls, 0)

    @unittest.expectedFailure
    def test_direct_validator_must_not_silently_omit_falsey_nobool(self) -> None:
        # Direct validation is a second safety check, NOT a substitute for registry admission.
        with self.assertRaises(OrchestrationError):
            self._definition(0).validate_arguments({})
        self.assertEqual(self.handler_calls, 0)

if __name__ == "__main__":
    unittest.main()
