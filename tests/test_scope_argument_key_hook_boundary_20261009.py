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


if __name__ == "__main__":
    unittest.main()
