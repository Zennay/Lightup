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


if __name__ == "__main__":
    unittest.main()
