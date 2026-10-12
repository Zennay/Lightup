"""Purely offline #1143 numeric integrity contract and real-executor RED canaries.

The three expected failures deliberately record a currently uncorrected
producer bug. They are NOT successful runtime enforcement checks.
"""
from __future__ import annotations

import math
import tempfile
import unittest
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.finite_number_review import (
    FiniteNumberRefused, FiniteNumberReview, review_finite_number,
)
from lightup.state import StateStore


class NumericIntegrityReviewTests(unittest.TestCase):
    def test_finite_integer_controls_include_arbitrary_precision(self):
        for value in (0, 1, -1, 10**500, -(10**500)):
            with self.subTest(value_type=type(value).__name__, digits=len(str(value))):
                result = review_finite_number(value)
                self.assertEqual(result, FiniteNumberReview("integer"))

    def test_finite_float_controls(self):
        for value in (0.0, -0.0, 0.5, -0.5, 1e-300, 1e300, 1.7976931348623157e308):
            with self.subTest(value=value):
                self.assertEqual(review_finite_number(value).kind, "float")

    def test_nonfinite_refusals_are_deterministic(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(nonfinite=str(value)):
                with self.assertRaisesRegex(
                    FiniteNumberRefused, "^NUMBER requires an exact finite int or float$"
                ):
                    review_finite_number(value)

    def test_reject_bool_enum_subclass_and_string(self):
        class NumericEnum(IntEnum):
            ONE = 1

        class StrangeInt(int):
            def __float__(self):
                raise AssertionError("untrusted float conversion")

        class StrangeFloat(float):
            def __repr__(self):
                raise AssertionError("untrusted repr")

        for value in (True, False, NumericEnum.ONE, StrangeInt(1), StrangeFloat(1.0),
                      "1.0", None, complex(1, 0), {}, [], b"4"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(FiniteNumberRefused):
                    review_finite_number(value)

    def test_review_can_never_serve_as_boolean_permission(self):
        for review in (review_finite_number(0), review_finite_number(1.2)):
            with self.assertRaisesRegex(TypeError, "not execution authorization"):
                bool(review)

    def test_reference_does_not_mutate_input_collections(self):
        for value in ([], {}, [float("inf")]):
            before = repr(value)
            with self.assertRaises(FiniteNumberRefused):
                review_finite_number(value)
            self.assertEqual(repr(value), before)

    def test_canonical_positive_controls_match_legacy_param_shape(self):
        definition = ToolDefinition(
            "synthetic-number", "web-baseline", InteractionKind.ANALYSIS,
            RiskLevel.ANALYSIS_ONLY, "offline number shape",
            (ToolParameter("value", ParamKind.NUMBER),),
        )
        for value in (0, -42, 0.25, 2.0):
            self.assertTrue(ParamKind.NUMBER.accepts(value))
            definition.validate_arguments({"value": value})
            self.assertIsInstance(review_finite_number(value), FiniteNumberReview)


class LegacyExecutorNumberAdmissionTests(unittest.TestCase):
    """Real dispatch with temporary local SQLite and a no-network handler."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.run_id = self.store.create_run(target="synthetic.test")
        self.calls = []
        registry = ToolRegistry()

        def handler(context, arguments):
            self.calls.append(arguments["value"])
            return ToolOutput("synthetic", "note", b"local-only")

        registry.register(
            ToolDefinition(
                "synthetic-number", "web-baseline", InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY, "offline fixture; no target I/O",
                (ToolParameter("value", ParamKind.NUMBER),),
            ),
            handler,
        )
        self.executor = ToolExecutor(registry, self.store)
        self.context = RunContext(
            run_id=self.run_id,
            client_id="synthetic-client", engagement_id="synthetic-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _call(self, number):
        return self.executor.execute(
            self.context,
            ToolCall("synthetic-number", "synthetic.test", (("value", number),)),
        )

    def _evidence_count(self):
        with self.store.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def test_finite_real_executor_control_dispatches_once(self):
        self.assertEqual(self._evidence_count(), 0)
        result = self._call(2.5)
        self.assertNotEqual(result.evidence_id, "")
        self.assertEqual(self.calls, [2.5])
        self.assertEqual(self._evidence_count(), 1)

    def _assert_nonfinite_is_denied_before_handler(self, number):
        # Expected RED until ParamKind.NUMBER owner integrates this contract.
        with self.assertRaises(OrchestrationError):
            self._call(number)
        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence_count(), 0)

    @unittest.expectedFailure
    def test_real_executor_nan_refusal_expected_red(self):
        self._assert_nonfinite_is_denied_before_handler(float("nan"))

    @unittest.expectedFailure
    def test_real_executor_posinf_refusal_expected_red(self):
        self._assert_nonfinite_is_denied_before_handler(float("inf"))

    @unittest.expectedFailure
    def test_real_executor_neginf_refusal_expected_red(self):
        self._assert_nonfinite_is_denied_before_handler(float("-inf"))


if __name__ == "__main__":
    unittest.main()
