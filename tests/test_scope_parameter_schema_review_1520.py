"""Independent real-source and offline-only scope schema admission tests (#1520).

No target/network calls, authorizations, client data, handlers, or persisted evidence.
The two source-level REDs deliberately remain expected failures until #156 fixes
ToolRegistry.register. A passing suite does NOT imply authorization is safe.
"""
from __future__ import annotations

import os
import socket
import sys
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter, ToolRegistry,
)
from lightup.capabilities import get_capabilities
from lightup.execution_policy import InteractionKind
from lightup.engagements import RiskLevel
from lightup.scope_parameter_schema_review_1520 import (
    ParameterSchemaReview, review_parameter_schema,
)


def _definition(*parameters):
    return ToolDefinition(
        tool_id="fictional_schema_1520",
        capability_id=get_capabilities()[0].capability_id,
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="Offline schema metadata only; never dispatch",
        parameters=tuple(parameters),
    )


def _param(name="asset", kind=ParamKind.STRING, required=True, description=""):
    return ToolParameter(name=name, kind=kind, required=required, description=description)


def _no_handler(*_args, **_kwargs):
    raise AssertionError("offline schema tests must never invoke handlers")


class ParameterSchemaReview1520Tests(unittest.TestCase):
    def assert_hold(self, definition):
        result = review_parameter_schema(definition)
        self.assertEqual(result.status, "HOLD")
        self.assert_no_authority(result)

    def assert_review_only(self, definition):
        result = review_parameter_schema(definition)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assert_no_authority(result)

    def assert_no_authority(self, result):
        self.assertIs(type(result), ParameterSchemaReview)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, key), False)

    def test_zero_parameter_schema_is_review_only_not_permission(self):
        self.assert_review_only(_definition())

    def test_unique_real_parameter_objects_are_review_only(self):
        self.assert_review_only(_definition(_param(), _param("count", ParamKind.INTEGER, False)))

    def test_repeated_same_kind_parameter_is_hold(self):
        self.assert_hold(_definition(_param("x"), _param("x")))

    def test_repeated_conflicting_kind_parameter_is_hold(self):
        self.assert_hold(_definition(_param("x", ParamKind.STRING), _param("x", ParamKind.INTEGER)))

    def test_repeated_nonadjacent_parameter_is_hold(self):
        self.assert_hold(_definition(_param("a"), _param("b"), _param("a")))

    def test_no_collision_after_case_or_unicode_alias_normalization(self):
        self.assert_hold(_definition(_param("a"), _param("A")))
        self.assert_hold(_definition(_param("a"), _param("\N{CYRILLIC SMALL LETTER A}")))

    def test_blank_control_or_separator_names_are_hold(self):
        for name in ("", " ", "a b", "a-b", "a\x00b", "a\nb", "_a", "9a", "a.b"):
            with self.subTest(name=repr(name)):
                self.assert_hold(_definition(_param(name)))

    def test_long_name_and_parameter_limit(self):
        self.assert_hold(_definition(_param("a" * 65)))
        self.assert_review_only(_definition(*(_param("f" + str(i)) for i in range(32))))
        self.assert_hold(_definition(*(_param("f" + str(i)) for i in range(33))))

    def test_polymorphic_names_are_hold_even_when_equal(self):
        class Text(str):
            pass
        self.assert_hold(_definition(_param(Text("asset"))))
        self.assert_hold(_definition(_param(Text("asset")), _param("asset")))

    def test_malformed_nested_kind_and_required_are_hold(self):
        self.assert_hold(_definition(_param("x", "string")))
        self.assert_hold(_definition(_param("x", ParamKind.STRING, 1)))
        self.assert_hold(_definition(_param("x", ParamKind.STRING, None)))

    def test_noncanonical_nested_object_and_description_are_hold(self):
        class ParameterChild(ToolParameter):
            pass
        self.assert_hold(_definition(ParameterChild(name="x", kind=ParamKind.STRING)))
        self.assert_hold(_definition(_param("x", description=b"bytes")))
        self.assert_hold(_definition({"name": "x"}))

    def test_mutable_or_non_tuple_container_is_hold(self):
        good = _param()
        obj = _definition()
        object.__setattr__(obj, "parameters", [good])
        self.assert_hold(obj)
        object.__setattr__(obj, "parameters", {good})
        self.assert_hold(obj)

    def test_untrusted_outer_object_does_not_get_accepted(self):
        class DefinitionChild(ToolDefinition):
            pass
        actual = _definition(_param())
        self.assert_hold(DefinitionChild(**vars(actual)))
        self.assert_hold(object())
        self.assert_hold(None)

    def test_input_purity_and_frozen_receipts(self):
        obj = _definition(_param("one"), _param("two", required=False))
        before = repr(obj)
        self.assert_review_only(obj)
        self.assertEqual(repr(obj), before)
        with self.assertRaises(FrozenInstanceError):
            review_parameter_schema(obj).authorized = True

    def test_review_never_uses_network(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            self.assert_review_only(_definition(_param("safe")))
            self.assert_hold(_definition(_param("same"), _param("same")))

    def test_real_registry_unique_control_is_admitted_without_dispatch(self):
        registry = ToolRegistry()
        definition = _definition(_param("safe"))
        registry.register(definition, _no_handler)
        self.assertEqual(registry.definitions(), (definition,))

    @unittest.expectedFailure
    def test_source_red_duplicate_matching_names_cannot_register(self):
        registry = ToolRegistry()
        with self.assertRaises(OrchestrationError):
            registry.register(_definition(_param("a"), _param("a")), _no_handler)
        self.assertEqual(registry.definitions(), ())

    @unittest.expectedFailure
    def test_source_red_duplicate_incompatible_names_cannot_register(self):
        registry = ToolRegistry()
        with self.assertRaises(OrchestrationError):
            registry.register(
                _definition(_param("a", ParamKind.INTEGER), _param("a", ParamKind.STRING)),
                _no_handler,
            )
        self.assertEqual(registry.definitions(), ())


if __name__ == "__main__":
    unittest.main()
