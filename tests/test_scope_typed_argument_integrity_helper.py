"""Offline, zero-network tests of the independent argument integrity helper."""
from __future__ import annotations

import unittest

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, ToolDefinition, ToolParameter,
)
from lightup.ai.typed_argument_integrity import validate_unambiguous_arguments
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


class TypedArgumentIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.definition = ToolDefinition(
            "offline-only", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "offline only",
            (ToolParameter("value", ParamKind.NUMBER),),
        )

    def test_finite_values_preserved(self):
        for value in (0, -12, 2.5, -0.5, 1e200):
            with self.subTest(value=value):
                self.assertEqual(
                    validate_unambiguous_arguments(
                        self.definition, (("value", value),)
                    )["value"], value
                )

    def test_arbitrarily_large_finite_integer_does_not_overflow(self):
        huge = 10 ** 1000
        self.assertEqual(
            validate_unambiguous_arguments(
                self.definition, (("value", huge),)
            )["value"], huge
        )

    def test_nan_and_infinities_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=str(value)):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(
                        self.definition, (("value", value),)
                    )

    def test_duplicates_rejected_regardless_of_order(self):
        for values in ((1.0, 2.0), ("invalid", 2.0), (2.0, "invalid")):
            with self.subTest(values=values):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(
                        self.definition, tuple(("value", v) for v in values)
                    )

    def test_malformed_shapes_and_boolean_rejected(self):
        malformed = (("value",), ("value", 1, 2), "value")
        for entry in malformed:
            with self.subTest(entry=entry):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(self.definition, (entry,))
        for value in (True, False, None, "2.5"):
            with self.subTest(value=value):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(
                        self.definition, (("value", value),)
                    )

    def test_schema_missing_and_unknown_names_rejected(self):
        for pairs in ((), (("other", 1),)):
            with self.subTest(pairs=pairs):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(self.definition, pairs)

    def test_input_pairs_remain_unchanged_after_accept_or_reject(self):
        """The helper must not rewrite caller-owned arguments."""
        valid = [("value", 4.5)]
        snapshot = list(valid)
        self.assertEqual(
            validate_unambiguous_arguments(self.definition, valid),
            {"value": 4.5},
        )
        self.assertEqual(valid, snapshot)
        duplicate = [("value", 4.5), ("value", float("inf"))]
        with self.assertRaises(OrchestrationError):
            validate_unambiguous_arguments(self.definition, duplicate)
        self.assertEqual(len(duplicate), 2)
        self.assertEqual(duplicate[0], ("value", 4.5))
        self.assertEqual(duplicate[1][0], "value")

    def test_duplicate_key_preempts_invalid_second_value(self):
        """Ambiguous provenance is rejected regardless of second value type."""
        for second in (float("nan"), 1, True, None, {"nested": "input"}):
            with self.subTest(value=str(second)):
                with self.assertRaisesRegex(OrchestrationError, "duplicate"):
                    validate_unambiguous_arguments(
                        self.definition,
                        (("value", 0), ("value", second)),
                    )

    def test_non_sequence_iterators_are_rejected_before_consumption(self):
        """Do not permit partial validation or side effects from iterators."""
        seen = []
        def side_effectful():
            seen.append("iterated")
            yield ("value", 3.0)
        with self.assertRaises(OrchestrationError):
            validate_unambiguous_arguments(self.definition, side_effectful())
        self.assertEqual(seen, [])

    def test_argument_name_type_must_be_exact_string(self):
        """Reject ambiguous, non-string dictionary keys before schema checks."""
        for name in (b"value", None, 1, ("value",)):
            with self.subTest(name=name):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(
                        self.definition, ((name, 2.0),)
                    )

    def test_duplicate_registry_parameter_names_fail_closed(self):
        """An ambiguous registry schema must not choose a parameter silently."""
        ambiguous = ToolDefinition(
            "ambiguous-fixture", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "offline schema only",
            (
                ToolParameter("value", ParamKind.NUMBER),
                ToolParameter("value", ParamKind.NUMBER),
            ),
        )
        with self.assertRaisesRegex(OrchestrationError, "duplicate tool parameter"):
            validate_unambiguous_arguments(
                ambiguous, (("value", 5.0),)
            )

    def test_custom_sequence_subclasses_are_not_evaluated(self):
        """Do not call user-defined __iter__ or __len__ during parsing."""
        activity = []
        class TrapList(list):
            def __iter__(self):
                activity.append("iterated")
                raise AssertionError("untrusted subclass iterator ran")
            def __len__(self):
                activity.append("measured")
                raise AssertionError("untrusted subclass length ran")
        for argument in (TrapList([("value", 3.0)]),
                         (TrapList(["value", 3.0]),)):
            with self.subTest(kind=type(argument[0]).__name__):
                with self.assertRaises(OrchestrationError):
                    validate_unambiguous_arguments(self.definition, argument)
        self.assertEqual(activity, [])

    def test_nonstring_registry_parameter_name_is_rejected(self):
        """Do not accept malformed source registry metadata as a tool schema."""
        for name in (None, b"value", 7):
            with self.subTest(name=name):
                malformed = ToolDefinition(
                    "invalid-registry", "web-baseline", InteractionKind.LAB_ACTIVE,
                    RiskLevel.DESTRUCTIVE_LAB_ONLY, "offline",
                    (ToolParameter(name, ParamKind.NUMBER),),
                )
                with self.assertRaisesRegex(OrchestrationError, "parameter names"):
                    validate_unambiguous_arguments(malformed, ())

    def test_malformed_registry_rejected_before_argument_iteration(self):
        """Registry integrity checks run before processing untrusted inputs."""
        malformed = ToolDefinition(
            "bad-schema", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "offline",
            (ToolParameter("value", ParamKind.NUMBER), ToolParameter("value", ParamKind.NUMBER)),
        )
        observed = []
        class SideEffectList(list):
            def __iter__(self):
                observed.append("read")
                raise AssertionError("arguments evaluated before registry validation")
        with self.assertRaisesRegex(OrchestrationError, "duplicate tool parameter"):
            validate_unambiguous_arguments(malformed, SideEffectList([("value", 5)]))
        self.assertEqual(observed, [])

    def test_malformed_registry_entry_is_rejected(self):
        """An invalid ToolParameter entry is rejected without attribute errors."""
        malformed = ToolDefinition(
            "bad-schema", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "offline",
            (None,),
        )
        with self.assertRaisesRegex(OrchestrationError, "invalid definition"):
            validate_unambiguous_arguments(malformed, ())

    def test_untrusted_definition_subclass_cannot_run_property_code(self):
        """Reject a forged subclass before its parameter property is touched."""
        touched = []
        class TrapDefinition(ToolDefinition):
            @property
            def parameters(self):
                touched.append("accessed")
                raise AssertionError("untrusted ToolDefinition property evaluated")
        fake = object.__new__(TrapDefinition)
        with self.assertRaisesRegex(OrchestrationError, "registered ToolDefinition"):
            validate_unambiguous_arguments(fake, (("value", 1.0),))
        self.assertEqual(touched, [])


if __name__ == "__main__":
    unittest.main()
