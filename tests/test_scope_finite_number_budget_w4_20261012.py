"""W4 post-decoding NUMBER magnitude budgets; synthetic lab-only #1143.

The reference is never installed as a production parser/execution grant.
A bit-length check cannot bound upstream JSON parsing or object allocation.
"""
from __future__ import annotations

import unittest

from lightup.finite_number_review import (
    FiniteNumberRefused,
    FiniteNumberBatchReview,
    MAX_OFFLINE_INTEGER_BITS,
    review_bounded_finite_number,
    review_finite_number,
    review_finite_number_batch,
)


class NumericBitBudgetW4Tests(unittest.TestCase):
    def test_exact_default_bit_boundary_and_negative_control(self):
        limit = MAX_OFFLINE_INTEGER_BITS
        for value in (0, -1, (1 << (limit - 1)), -(1 << (limit - 1))):
            with self.subTest(value_type=type(value).__name__, length=value.bit_length()):
                self.assertEqual(review_bounded_finite_number(value).kind, "integer")
        for value in (1 << limit, -(1 << limit)):
            with self.assertRaisesRegex(
                FiniteNumberRefused, "^NUMBER integer exceeds offline bit budget$"
            ):
                review_bounded_finite_number(value)

    def test_caller_can_request_stricter_bit_budget_only(self):
        self.assertEqual(review_bounded_finite_number(7, max_integer_bits=3).kind,
                         "integer")
        for value in (8, -8):
            with self.assertRaises(FiniteNumberRefused):
                review_bounded_finite_number(value, max_integer_bits=3)

    def test_bad_budget_type_range_never_coerced(self):
        class IntSub(int):
            def __index__(self):
                raise AssertionError("budget index conversion reached")

        class TrapBudget:
            def __int__(self):
                raise AssertionError("budget int conversion reached")
            def __repr__(self):
                raise AssertionError("budget repr reached")

        for invalid in (True, False, 0, -1, 4097, 1.0, "12", IntSub(4), TrapBudget()):
            with self.subTest(budget_type=type(invalid).__name__):
                with self.assertRaisesRegex(
                    FiniteNumberRefused, "^NUMBER bit budget requires a bounded exact int$"
                ):
                    review_bounded_finite_number(1, max_integer_bits=invalid)

    def test_nonfinite_float_denied_even_with_wider_integer_budget(self):
        for invalid in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaisesRegex(FiniteNumberRefused, "exact finite"):
                review_bounded_finite_number(invalid, max_integer_bits=4096)

    def test_finite_float_is_unaffected_by_integer_magnitude_budget(self):
        # Finite float range/precision must be assessed by its consumer; the
        # integer bit budget intentionally does not assert a float range.
        for value in (1e-300, -1e308, 0.0, -0.0):
            self.assertEqual(review_bounded_finite_number(
                value, max_integer_bits=1
            ).kind, "float")

    def test_batch_refuses_oversize_integer_at_last_element_atomically(self):
        too_large = 1 << MAX_OFFLINE_INTEGER_BITS
        values = (1,) * 63 + (too_large,)
        with self.assertRaisesRegex(FiniteNumberRefused, "integer exceeds offline bit budget"):
            review_finite_number_batch(values)
        self.assertEqual(len(values), 64)
        self.assertEqual(values[-1], too_large)

    def test_batch_accepts_stricter_bound_and_denies_single_outlier(self):
        result = review_finite_number_batch((0, 1, 2, 3.0), max_integer_bits=2)
        self.assertIsInstance(result, FiniteNumberBatchReview)
        self.assertEqual(len(result.items), 4)
        with self.assertRaisesRegex(FiniteNumberRefused, "integer exceeds offline bit budget"):
            review_finite_number_batch((1, 4), max_integer_bits=2)
        with self.assertRaisesRegex(FiniteNumberRefused, "bit budget requires"):
            review_finite_number_batch((), max_integer_bits=False)

    def test_unbounded_scalar_review_remains_shape_only(self):
        # This legacy opt-in method is not a resource-safe serialization gate.
        huge = 1 << (MAX_OFFLINE_INTEGER_BITS + 100)
        self.assertEqual(review_finite_number(huge).kind, "integer")
        with self.assertRaises(FiniteNumberRefused):
            review_bounded_finite_number(huge)

    def test_custom_numeric_no_coercion_even_on_small_budget(self):
        class DangerousInt(int):
            def bit_length(self):
                raise AssertionError("subclass bit_length reached")
            def __repr__(self):
                raise AssertionError("subclass repr reached")

        with self.assertRaises(FiniteNumberRefused):
            review_bounded_finite_number(DangerousInt(1), max_integer_bits=1)


if __name__ == "__main__":
    unittest.main()
