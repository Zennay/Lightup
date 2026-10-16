"""Tests for the explicit opt-in #907 exact outer registration gate.

Synthetic metadata and inert never-called handlers only; no target or network.
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
from lightup.scope_907_registry_admission_optin import (
    register_exact_tool_definition,
)


def never_handler(*_args, **_kwargs):
    raise AssertionError("test handler MUST NOT run")


def valid(tool_id="fictional-tool"):
    return ToolDefinition(
        tool_id=tool_id,
        capability_id="external-attack-surface",
        interaction=InteractionKind.PASSIVE_PUBLIC,
        min_risk=RiskLevel.PASSIVE,
        description="offline only",
        parameters=(ToolParameter("query", ParamKind.STRING),),
    )


class SpyDuck:
    def __init__(self):
        self.reads = 0

    def __getattribute__(self, key):
        if key not in ("reads", "__class__"):
            object.__setattr__(self, "reads", object.__getattribute__(self, "reads") + 1)
            raise AssertionError("untrusted metadata read")
        return object.__getattribute__(self, key)


class MaliciousDefinition(ToolDefinition):
    def validate_arguments(self, args):
        return None


class MaliciousRegistry(ToolRegistry):
    def register(self, definition, handler):
        raise AssertionError("untrusted registry method invoked")


class CanonicalOptinRegistryAdmission(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()

    def assert_denied_atomic(self, definition):
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(self.registry, definition, never_handler)
        self.assertEqual(self.registry.definitions(), ())

    def test_real_canonical_definition_registers_exactly_once(self):
        d = valid()
        self.assertIsNone(register_exact_tool_definition(self.registry, d, never_handler))
        stored, handler = self.registry.get("fictional-tool")
        self.assertIs(stored, d)
        self.assertIs(handler, never_handler)

    def test_forged_class_definition_rejected_before_metadata_reads(self):
        class ForgedDefinition:
            @property
            def __class__(self):
                return ToolDefinition

            @property
            def tool_id(self):
                raise AssertionError("spoofed definition metadata getter read")

            def validate_arguments(self, _args):
                raise AssertionError("spoofed validator executed")
        forged = ForgedDefinition()
        self.assertIsInstance(forged, ToolDefinition)
        self.assertIsNot(type(forged), ToolDefinition)
        self.assert_denied_atomic(forged)

    def test_forged_class_registry_rejected_before_registrar_dispatch(self):
        class ForgedRegistry:
            def __init__(self):
                self.called = False

            @property
            def __class__(self):
                return ToolRegistry

            def register(self, definition, handler):
                self.called = True
                raise AssertionError("forged registry invoked")

        registry = ForgedRegistry()
        self.assertIsInstance(registry, ToolRegistry)
        self.assertIsNot(type(registry), ToolRegistry)
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(registry, valid(), never_handler)
        self.assertIs(registry.called, False)

    def test_untrusted_plain_object_rejected_before_fields(self):
        self.assert_denied_atomic(object())

    def test_none_rejected(self):
        self.assert_denied_atomic(None)

    def test_duck_property_spy_has_zero_getter_reads(self):
        spy = SpyDuck()
        self.assert_denied_atomic(spy)
        self.assertEqual(spy.reads, 0)

    def test_subclass_override_cannot_bypass_required_arguments(self):
        d = MaliciousDefinition(**vars(valid()))
        self.assert_denied_atomic(d)

    def test_unmodified_subclass_is_rejected(self):
        class Plain(ToolDefinition):
            pass
        self.assert_denied_atomic(Plain(**vars(valid())))

    def test_canonical_required_argument_validation_still_enforced(self):
        d = valid()
        register_exact_tool_definition(self.registry, d, never_handler)
        with self.assertRaises(OrchestrationError):
            self.registry.get("fictional-tool")[0].validate_arguments({})
        with self.assertRaises(OrchestrationError):
            self.registry.get("fictional-tool")[0].validate_arguments({"query": 1})

    def test_canonical_unknown_capability_still_rejected_by_owner(self):
        d = ToolDefinition(
            "fictional-unknown", "no-such-capability",
            InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE, "offline",
        )
        self.assert_denied_atomic(d)

    def test_canonical_lab_capability_passes_only_lab_interaction(self):
        d = ToolDefinition(
            "fictional-lab", "wireless-lab", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "fictional only",
        )
        register_exact_tool_definition(self.registry, d, never_handler)
        self.assertIs(self.registry.get("fictional-lab")[0], d)

    def test_canonical_lab_capability_cannot_be_passive(self):
        d = ToolDefinition(
            "fictional-lab-passive", "wireless-lab", InteractionKind.PASSIVE_PUBLIC,
            RiskLevel.PASSIVE, "fictional only",
        )
        self.assert_denied_atomic(d)

    def test_canonical_wrong_interaction_type_rejected_by_owner(self):
        d = ToolDefinition(
            "bad-kind", "external-attack-surface",
            "passive_public", RiskLevel.PASSIVE, "fictional",
        )
        self.assert_denied_atomic(d)

    def test_canonical_wrong_risk_type_rejected_by_owner(self):
        d = ToolDefinition(
            "bad-risk", "external-attack-surface",
            InteractionKind.PASSIVE_PUBLIC, 1, "fictional",
        )
        self.assert_denied_atomic(d)

    def test_duplicate_id_preserves_single_original_registration(self):
        d = valid()
        register_exact_tool_definition(self.registry, d, never_handler)
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(self.registry, valid(), never_handler)
        self.assertEqual(self.registry.definitions(), (d,))

    def test_rejected_forged_definition_cannot_modify_existing_registry(self):
        original = valid("safe-existing")
        register_exact_tool_definition(self.registry, original, never_handler)
        before = self.registry.definitions()
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(self.registry, SpyDuck(), never_handler)
        self.assertEqual(self.registry.definitions(), before)
        self.assertIs(self.registry.get("safe-existing")[0], original)

    def test_invalid_canonical_metadata_preserves_existing_registry(self):
        original = valid("safe-existing")
        register_exact_tool_definition(self.registry, original, never_handler)
        before = self.registry.definitions()
        invalid = ToolDefinition(
            "invalid-followup", "no-such-capability",
            InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE, "synthetic",
        )
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(self.registry, invalid, never_handler)
        self.assertEqual(self.registry.definitions(), before)
        self.assertIs(self.registry.get("safe-existing")[1], never_handler)

    def test_exact_registry_instance_rebound_register_cannot_bypass_controls(self):
        invoked = []
        self.registry.register = lambda definition, handler: invoked.append(
            (definition, handler))
        with self.assertRaisesRegex(OrchestrationError, "shadowed"):
            register_exact_tool_definition(self.registry, valid(), never_handler)
        self.assertEqual(invoked, [])
        self.assertEqual(self.registry.definitions(), ())

    def test_shadowed_registry_cannot_override_unknown_capability_rejection(self):
        invoked = []
        self.registry.register = lambda definition, handler: invoked.append(True)
        bad = ToolDefinition(
            "fictional-unknown", "forged-unknown",
            InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE, "fictional",
        )
        with self.assertRaisesRegex(OrchestrationError, "shadowed"):
            register_exact_tool_definition(self.registry, bad, never_handler)
        self.assertEqual(invoked, [])
        self.assertEqual(self.registry.definitions(), ())

    def test_removed_instance_shadow_restores_original_owner_registration(self):
        original = valid("fictional-normal")
        self.registry.register = lambda *_args: never_handler()
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(self.registry, original, never_handler)
        del self.registry.register
        register_exact_tool_definition(self.registry, original, never_handler)
        definition, handler = self.registry.get("fictional-normal")
        self.assertIs(definition, original)
        self.assertIs(handler, never_handler)

    def test_existing_registry_stays_unchanged_under_rebound_register(self):
        original = valid("safe-existing")
        register_exact_tool_definition(self.registry, original, never_handler)
        previous = self.registry.definitions()
        self.registry.register = lambda *_args: self.fail("shadow invoked")
        with self.assertRaisesRegex(OrchestrationError, "shadowed"):
            register_exact_tool_definition(self.registry, valid("new-tool"), never_handler)
        self.assertEqual(self.registry.definitions(), previous)
        self.assertIs(self.registry.get("safe-existing")[1], never_handler)

    def test_exact_frozen_definition_validator_shadow_is_rejected(self):
        definition = valid("shadowed-validator")
        bypass_called = []
        def forged_validator(_arguments):
            bypass_called.append(True)
        object.__setattr__(definition, "validate_arguments", forged_validator)
        with self.assertRaisesRegex(OrchestrationError, "validator was shadowed"):
            register_exact_tool_definition(self.registry, definition, never_handler)
        self.assertEqual(bypass_called, [])
        self.assertEqual(self.registry.definitions(), ())

    def test_validator_shadow_denial_preserves_preexisting_registry(self):
        original = valid("safe-existing")
        register_exact_tool_definition(self.registry, original, never_handler)
        before = self.registry.definitions()
        corrupted = valid("forged-next")
        object.__setattr__(corrupted, "validate_arguments", lambda _: None)
        with self.assertRaisesRegex(OrchestrationError, "validator was shadowed"):
            register_exact_tool_definition(self.registry, corrupted, never_handler)
        self.assertEqual(self.registry.definitions(), before)
        self.assertIs(self.registry.get("safe-existing")[0], original)

    def test_deleting_synthetic_validator_shadow_restores_original_validation(self):
        definition = valid("restored-validator")
        object.__setattr__(definition, "validate_arguments", lambda _: None)
        with self.assertRaisesRegex(OrchestrationError, "validator was shadowed"):
            register_exact_tool_definition(self.registry, definition, never_handler)
        object.__delattr__(definition, "validate_arguments")
        register_exact_tool_definition(self.registry, definition, never_handler)
        stored, handler = self.registry.get("restored-validator")
        self.assertIs(stored, definition)
        self.assertIs(handler, never_handler)
        with self.assertRaises(OrchestrationError):
            stored.validate_arguments({})
        stored.validate_arguments({"query": "fictional-only"})

    def test_registry_subclass_cannot_intercept_registration(self):
        spy = MaliciousRegistry()
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(spy, valid(), never_handler)
        self.assertEqual(spy.definitions(), ())

    def test_registry_duck_with_malicious_register_method_not_invoked(self):
        class DuckRegistry:
            def register(self, _definition, _handler):
                raise AssertionError("must never invoke duck method")
        with self.assertRaises(OrchestrationError):
            register_exact_tool_definition(DuckRegistry(), valid(), never_handler)


if __name__ == "__main__":
    unittest.main()
