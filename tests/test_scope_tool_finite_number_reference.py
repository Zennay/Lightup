"""Offline acceptance reference: numeric tool arguments must be finite.

This deliberately does not dispatch tools or activate real targets.
Production enforcement belongs to the ToolRegistry source owner.
"""
import math
import unittest
from enum import IntEnum


def accepts_canonical_finite_number(value: object) -> bool:
    """Exact primitives only; bool, subclasses and non-finite floats denied."""
    return (type(value) is int or type(value) is float) and (
        type(value) is int or math.isfinite(value)
    )


class NumberEnum(IntEnum):
    ONE = 1


class DerivedInt(int):
    pass


class DerivedFloat(float):
    pass


class FiniteNumberReferenceTests(unittest.TestCase):
    def test_canonical_finite_values(self):
        for value in (0, -1, 4, 0.0, -1.25, 3.5, 1e300, -1e300):
            with self.subTest(value=value):
                self.assertTrue(accepts_canonical_finite_number(value))

    def test_nonfinite_float_denied(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(value)):
                self.assertFalse(accepts_canonical_finite_number(value))

    def test_bool_enum_and_subclasses_denied(self):
        for value in (True, False, NumberEnum.ONE, DerivedInt(3), DerivedFloat(1.5)):
            with self.subTest(value=repr(value)):
                self.assertFalse(accepts_canonical_finite_number(value))

    def test_nonnumeric_values_denied(self):
        for value in (None, "1", b"1", [], {}, complex(1, 0)):
            with self.subTest(value=repr(value)):
                self.assertFalse(accepts_canonical_finite_number(value))

    def test_no_coercion_or_user_methods(self):
        class Hostile:
            def __float__(self):
                raise AssertionError("untrusted coercion called")
            def __int__(self):
                raise AssertionError("untrusted coercion called")
        self.assertFalse(accepts_canonical_finite_number(Hostile()))


if __name__ == "__main__":
    unittest.main()
