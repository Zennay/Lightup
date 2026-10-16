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
