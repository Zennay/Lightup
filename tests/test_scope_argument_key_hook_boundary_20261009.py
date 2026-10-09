"""Offline rejection of attacker-defined argument-key hooks (no target I/O)."""
from __future__ import annotations

import unittest

from lightup.ai.orchestration import OrchestrationError, ParamKind, ToolDefinition, ToolParameter
from lightup.ai.typed_argument_integrity import validate_unambiguous_arguments
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


class ArgumentKeyHookBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.definition = ToolDefinition(
            "offline-key-fixture", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "synthetic input only",
            (ToolParameter("label", ParamKind.STRING),),
        )

    def test_str_subclass_key_does_not_execute_hash_or_equality(self):
        effects = []
        class TrapKey(str):
            def __hash__(self):
                effects.append("hash")
                raise AssertionError("untrusted hash hook executed")
            def __eq__(self, other):
                effects.append("eq")
                raise AssertionError("untrusted equality hook executed")
        with self.assertRaisesRegex(OrchestrationError, "names must be strings"):
            validate_unambiguous_arguments(
                self.definition, ((TrapKey("label"), "approved"),)
            )
        self.assertEqual(effects, [])

    def test_nonstring_key_hash_hook_is_never_called(self):
        effects = []
        class TrapKey:
            def __hash__(self):
                effects.append("hash")
                raise AssertionError("untrusted hash hook executed")
        with self.assertRaisesRegex(OrchestrationError, "names must be strings"):
            validate_unambiguous_arguments(self.definition, ((TrapKey(), "approved"),))
        self.assertEqual(effects, [])

    def test_canonical_string_key_and_value_positive_control(self):
        result = validate_unambiguous_arguments(
            self.definition, (("label", "approved"),)
        )
        self.assertEqual(result, {"label": "approved"})

    def test_second_duplicate_never_runs_user_key_hooks(self):
        effects = []
        class TrapKey(str):
            def __hash__(self):
                effects.append("hash")
                raise AssertionError("untrusted hash hook executed")
        with self.assertRaises(OrchestrationError):
            validate_unambiguous_arguments(
                self.definition, (("label", "first"), (TrapKey("label"), "second"))
            )
        self.assertEqual(effects, [])


    def test_registry_string_subclass_name_does_not_run_hash_or_equality(self):
        effects = []
        class TrapRegistryName(str):
            def __hash__(self):
                effects.append("hash")
                raise AssertionError("registry hash hook executed")
            def __eq__(self, other):
                effects.append("eq")
                raise AssertionError("registry equality hook executed")
        malformed = ToolDefinition(
            "offline-malformed", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "synthetic registry",
            (ToolParameter(TrapRegistryName("label"), ParamKind.STRING),),
        )
        with self.assertRaisesRegex(OrchestrationError, "parameter names must be strings"):
            validate_unambiguous_arguments(malformed, (("label", "safe"),))
        self.assertEqual(effects, [])

    def test_registry_nonstring_name_cannot_trigger_hash_hook(self):
        effects = []
        class TrapRegistryName:
            def __hash__(self):
                effects.append("hash")
                raise AssertionError("registry hash hook executed")
        malformed = ToolDefinition(
            "offline-malformed", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "synthetic registry",
            (ToolParameter(TrapRegistryName(), ParamKind.STRING),),
        )
        with self.assertRaisesRegex(OrchestrationError, "parameter names must be strings"):
            validate_unambiguous_arguments(malformed, (("label", "safe"),))
        self.assertEqual(effects, [])


    def test_invalid_key_is_rejected_before_untrusted_value_repr(self):
        effects = []
        class TrapValue:
            def __repr__(self):
                effects.append("repr")
                raise AssertionError("value repr executed")
        with self.assertRaisesRegex(OrchestrationError, "names must be strings"):
            validate_unambiguous_arguments(self.definition, ((None, TrapValue()),))
        self.assertEqual(effects, [])

    def test_duplicate_key_rejection_does_not_format_untrusted_value(self):
        effects = []
        class TrapValue:
            def __str__(self):
                effects.append("str")
                raise AssertionError("value str executed")
            def __repr__(self):
                effects.append("repr")
                raise AssertionError("value repr executed")
        with self.assertRaisesRegex(OrchestrationError, "duplicate tool argument name"):
            validate_unambiguous_arguments(
                self.definition, (("label", "valid"), ("label", TrapValue()))
            )
        self.assertEqual(effects, [])


    def test_malformed_nested_pair_subclass_cannot_run_unpack_hooks(self):
        events = []
        class TrapPair(list):
            def __len__(self):
                events.append("len")
                raise AssertionError("untrusted pair length hook executed")
            def __iter__(self):
                events.append("iter")
                raise AssertionError("untrusted pair iterator executed")
        with self.assertRaisesRegex(OrchestrationError, "entry must contain exactly two"):
            validate_unambiguous_arguments(
                self.definition, (TrapPair(["label", "safe"]),)
            )
        self.assertEqual(events, [])

    def test_malformed_registry_precedes_argument_container_hooks(self):
        events = []
        class TrapArguments(list):
            def __iter__(self):
                events.append("iter")
                raise AssertionError("untrusted arguments iterator executed")
        malformed = ToolDefinition(
            "bad-registry", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "synthetic registry",
            (ToolParameter("label", "string"),),
        )
        with self.assertRaisesRegex(OrchestrationError, "invalid kind or required"):
            validate_unambiguous_arguments(malformed, TrapArguments([("label", "safe")]))
        self.assertEqual(events, [])


    def test_argument_tuple_subclass_cannot_run_iterator(self):
        calls = []
        class TrapTuple(tuple):
            def __iter__(self):
                calls.append("iter")
                raise AssertionError("argument tuple hook executed")
        with self.assertRaisesRegex(OrchestrationError, "arguments must be ordered pairs"):
            validate_unambiguous_arguments(
                self.definition, TrapTuple((("label", "safe"),))
            )
        self.assertEqual(calls, [])

    def test_nested_tuple_subclass_cannot_run_unpack(self):
        calls = []
        class TrapTuple(tuple):
            def __len__(self):
                calls.append("len")
                raise AssertionError("pair length hook executed")
            def __iter__(self):
                calls.append("iter")
                raise AssertionError("pair iteration hook executed")
        with self.assertRaisesRegex(OrchestrationError, "entry must contain exactly two"):
            validate_unambiguous_arguments(
                self.definition, (TrapTuple(("label", "safe")),)
            )
        self.assertEqual(calls, [])


    def test_unknown_name_denied_before_value_hooks(self):
        effects = []
        class TrapValue:
            def __repr__(self):
                effects.append("repr")
                raise AssertionError("untrusted value formatted")
            def __str__(self):
                effects.append("str")
                raise AssertionError("untrusted value stringified")
        with self.assertRaisesRegex(OrchestrationError, "unknown tool argument name"):
            validate_unambiguous_arguments(self.definition, (("unknown", TrapValue()),))
        self.assertEqual(effects, [])

    def test_unknown_name_cannot_bypass_valid_other_argument(self):
        with self.assertRaisesRegex(OrchestrationError, "unknown tool argument name"):
            validate_unambiguous_arguments(
                self.definition, (("label", "valid"), ("unknown", "injected"))
            )
        self.assertEqual(
            validate_unambiguous_arguments(self.definition, (("label", "valid"),)),
            {"label": "valid"},
        )


    def test_unknown_argument_rejected_before_schema_validator(self):
        calls = []
        def trap_validate(definition, arguments):
            calls.append("called")
            raise AssertionError("schema invoked for unknown argument")
        from unittest.mock import patch
        with patch.object(ToolDefinition, "validate_arguments", trap_validate):
            with self.assertRaisesRegex(OrchestrationError, "unknown tool argument name"):
                validate_unambiguous_arguments(
                    self.definition, (("unknown", "injected"),)
                )
        self.assertEqual(calls, [])

    def test_duplicate_argument_rejected_before_schema_validator(self):
        calls = []
        def trap_validate(definition, arguments):
            calls.append("called")
            raise AssertionError("schema invoked for duplicate arguments")
        from unittest.mock import patch
        with patch.object(ToolDefinition, "validate_arguments", trap_validate):
            with self.assertRaisesRegex(OrchestrationError, "duplicate tool argument"):
                validate_unambiguous_arguments(
                    self.definition, (("label", "one"), ("label", "two"))
                )
        self.assertEqual(calls, [])


    def test_invalid_registry_denied_before_schema_callback(self):
        from unittest.mock import patch
        calls = []
        bad = ToolDefinition(
            "invalid-fixture", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "synthetic",
            (ToolParameter("label", "string"),),
        )
        def trap_validate(definition, arguments):
            calls.append("called")
            raise AssertionError("malformed registry reached validation")
        with patch.object(ToolDefinition, "validate_arguments", trap_validate):
            with self.assertRaisesRegex(OrchestrationError, "invalid kind or required"):
                validate_unambiguous_arguments(bad, (("label", "safe"),))
        self.assertEqual(calls, [])

    def test_valid_builtin_value_reaches_schema_exactly_once(self):
        from unittest.mock import patch
        calls = []
        original = ToolDefinition.validate_arguments
        def observed_validate(definition, arguments):
            calls.append(dict(arguments))
            return original(definition, arguments)
        with patch.object(ToolDefinition, "validate_arguments", observed_validate):
            result = validate_unambiguous_arguments(
                self.definition, (("label", "safe"),)
            )
        self.assertEqual(result, {"label": "safe"})
        self.assertEqual(calls, [{"label": "safe"}])


if __name__ == "__main__":
    unittest.main()
