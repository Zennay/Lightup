"""W2: bounded multi-NUMBER structural review; entirely offline and non-authorizing.

The opt-in helper is NOT wired to installed tool execution. These tests
must not be interpreted as real-target authorization or deployed enforcement.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor, ToolOutput,
    ToolParameter, ToolRegistry, ParamKind,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.finite_number_review import (
    FiniteNumberBatchReview, FiniteNumberRefused, FiniteNumberReview,
    MAX_OFFLINE_NUMBER_BATCH, review_finite_number, review_finite_number_batch,
)
from lightup.state import StateStore


class FiniteNumberBatchW2Tests(unittest.TestCase):
    def test_empty_batch_is_structural_only(self):
        result = review_finite_number_batch(())
        self.assertEqual(result.items, ())
        with self.assertRaisesRegex(TypeError, "not execution authorization"):
            bool(result)

    def test_mixed_finite_tuple_preserves_identity_and_kind(self):
        huge = 10**500
        values = (0, 1.25, -0.0, huge, -huge, 1e-300)
        result = review_finite_number_batch(values)
        self.assertIsInstance(result, FiniteNumberBatchReview)
        self.assertEqual(tuple(item.kind for item in result.items),
                         ("integer", "float", "float", "integer", "integer", "float"))
        self.assertEqual(values[3], huge)
        self.assertEqual(values[4], -huge)
        for item in result.items:
            self.assertIsInstance(item, FiniteNumberReview)
            with self.assertRaises(TypeError):
                bool(item)
        with self.assertRaises(TypeError):
            bool(result)

    def test_limit_edge_64_accepted_65_denied(self):
        max_len = MAX_OFFLINE_NUMBER_BATCH
        self.assertEqual(len(review_finite_number_batch((1,) * max_len).items), max_len)
        with self.assertRaisesRegex(FiniteNumberRefused, "bounded exact tuple"):
            review_finite_number_batch((1,) * (max_len + 1))

    def test_late_nan_refuses_entire_batch(self):
        values = (2.0,) * (MAX_OFFLINE_NUMBER_BATCH - 1) + (float("nan"),)
        before = tuple(id(v) for v in values)
        with self.assertRaisesRegex(FiniteNumberRefused,
                                    "^NUMBER requires an exact finite int or float$"):
            review_finite_number_batch(values)
        self.assertEqual(tuple(id(v) for v in values), before)

    def test_nonfinite_at_first_middle_last_positions(self):
        for invalid in (float("nan"), float("inf"), float("-inf")):
            for position in (0, 1, 2):
                items = [3.0, -12, 4.0]
                items[position] = invalid
                with self.subTest(value_type="nonfinite", position=position):
                    with self.assertRaises(FiniteNumberRefused):
                        review_finite_number_batch(tuple(items))

    def test_non_tuple_iterable_must_not_run_custom_iterator(self):
        class TrapIterable:
            def __iter__(self):
                raise AssertionError("unsafe user iteration reached")
            def __repr__(self):
                raise AssertionError("unsafe representation reached")

        class TrapTuple(tuple):
            def __iter__(self):
                raise AssertionError("tuple-subclass iterator reached")

        for invalid in ([], {}, TrapIterable(), TrapTuple((1, 2)), "123", None):
            with self.subTest(invalid_type=type(invalid).__name__):
                with self.assertRaisesRegex(FiniteNumberRefused, "bounded exact tuple"):
                    review_finite_number_batch(invalid)

    def test_malicious_numeric_object_methods_are_not_called(self):
        class TrapNumeric:
            def __float__(self):
                raise AssertionError("custom numeric coercion reached")
            def __int__(self):
                raise AssertionError("custom integer coercion reached")
            def __repr__(self):
                raise AssertionError("untrusted value rendered")

        with self.assertRaisesRegex(
            FiniteNumberRefused, "^NUMBER requires an exact finite int or float$"
        ) as raised:
            review_finite_number_batch((1.0, 2, TrapNumeric()))
        self.assertNotIn("TrapNumeric", str(raised.exception))

    def test_bad_subclasses_denied_without_coercion(self):
        class FloatSubclass(float):
            def __float__(self):
                raise AssertionError("float conversion called")

        class IntSubclass(int):
            def __int__(self):
                raise AssertionError("int conversion called")

        for value in (FloatSubclass(1.0), IntSubclass(1), True):
            with self.assertRaises(FiniteNumberRefused):
                review_finite_number_batch((0, value))

    def test_atomic_review_is_frozen_but_cannot_grant_permission(self):
        result = review_finite_number_batch((0, 1.0))
        with self.assertRaises(FrozenInstanceError):
            result.items = ()  # type: ignore[misc]
        with self.assertRaises(TypeError):
            bool(result)
        # An input that passed batch review cannot become a grant token.
        self.assertEqual(review_finite_number(1.0).kind, "float")

    def test_structurally_valid_numeric_input_does_not_bypass_target_grant(self):
        # Genuine ToolExecutor and disposable local ledger; target I/O is forbidden.
        self.assertEqual(review_finite_number_batch((1.0,)).items[0].kind, "float")
        with tempfile.TemporaryDirectory() as temporary:
            store = StateStore(Path(temporary) / "evidence.sqlite3")
            run_id = store.create_run(target="synthetic.invalid")
            handler_calls: list[object] = []

            def forbidden_handler(context, arguments):
                handler_calls.append(arguments["value"])
                return ToolOutput("should not run", "note", b"not-emitted")

            registry = ToolRegistry()
            registry.register(
                ToolDefinition(
                    "synthetic-target-number", "network-services",
                    InteractionKind.TARGET_ACTIVE, RiskLevel.STANDARD,
                    "offline-only probe stub",
                    (ToolParameter("value", ParamKind.NUMBER),),
                ),
                forbidden_handler,
            )
            executor = ToolExecutor(registry, store)
            context = RunContext(
                run_id=run_id, client_id="synthetic", engagement_id="synthetic",
                mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
                approved_risk=RiskLevel.STANDARD, authorization=None,
                is_lab=False, created_at=datetime.now(timezone.utc),
            )
            with self.assertRaises(ToolDenied):
                executor.execute(
                    context,
                    ToolCall("synthetic-target-number", "synthetic.invalid",
                             (("value", 1.0),)),
                )
            self.assertEqual(handler_calls, [])
            with store.connect() as con:
                self.assertEqual(con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
