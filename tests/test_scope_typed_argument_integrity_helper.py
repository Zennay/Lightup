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


if __name__ == "__main__":
    unittest.main()
