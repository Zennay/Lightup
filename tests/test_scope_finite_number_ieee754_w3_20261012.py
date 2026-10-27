"""W3 deterministic IEEE-754 and JSON boundary acceptance for #1143.

LAB ONLY: evidence of an opt-in structural reviewer, not a production parser,
grant, target permission, or an installed tool-execution boundary.
"""
from __future__ import annotations

import json
import math
import struct
import unittest

from lightup.finite_number_review import (
    FiniteNumberRefused, review_finite_number, review_finite_number_batch,
)


def binary64(bits: int) -> float:
    return struct.unpack(">d", struct.pack(">Q", bits))[0]


class NumberIeee754W3Tests(unittest.TestCase):
    def test_ieee754_signed_zero_and_subnormal_boundaries_are_finite(self):
        for bits in (
            0x0000000000000000,  # +0
            0x8000000000000000,  # -0
            0x0000000000000001,  # smallest +subnormal
            0x8000000000000001,  # smallest -subnormal
            0x000fffffffffffff,  # largest +subnormal
            0x0010000000000000,  # smallest positive normal
            0x7fefffffffffffff,  # max positive finite
            0xffefffffffffffff,  # max negative finite
        ):
            with self.subTest(binary64_bits=hex(bits)):
                value = binary64(bits)
                self.assertEqual(review_finite_number(value).kind, "float")
                self.assertEqual(struct.unpack(">Q", struct.pack(">d", value))[0], bits)

    def test_ieee754_infinity_nan_payloads_are_denied(self):
        for bits in (
            0x7ff0000000000000,  # +infinity
            0xfff0000000000000,  # -infinity
            0x7ff8000000000000,  # quiet NaN
            0x7ff8000000000001,  # distinct quiet payload
            0xfff8000000000001,  # negative NaN payload
        ):
            with self.subTest(binary64_bits=hex(bits)):
                value = binary64(bits)
                with self.assertRaisesRegex(
                    FiniteNumberRefused, "^NUMBER requires an exact finite int or float$"
                ):
                    review_finite_number(value)
                with self.assertRaises(FiniteNumberRefused):
                    review_finite_number_batch((1, value))

    def test_nextafter_edges_are_handled_without_quantization(self):
        finite = (
            math.nextafter(0.0, 1.0),
            math.nextafter(0.0, -1.0),
            math.nextafter(math.inf, 0.0),
            math.nextafter(-math.inf, 0.0),
        )
        for value in finite:
            with self.subTest(value=value):
                self.assertEqual(review_finite_number(value).kind, "float")
                self.assertEqual(len(review_finite_number_batch((value,)).items), 1)

    def test_finite_results_can_use_strict_json_serialization(self):
        # Serialization is an independent consumer contract; success here is
        # only a small positive control and not a universal byte-size bound.
        for value in (0, -(10**500), 0.0, -0.0, 0.5, 1e300):
            with self.subTest(value_type=type(value).__name__):
                review_finite_number(value)
                encoded = json.dumps({"value": value}, allow_nan=False)
                decoded = json.loads(encoded)["value"]
                self.assertEqual(decoded, value)

    def test_nonfinite_values_fail_before_strict_json_serialization(self):
        for value in (binary64(0x7ff8000000000000), float("inf"), -float("inf")):
            with self.assertRaises(FiniteNumberRefused):
                review_finite_number(value)
            with self.assertRaises(ValueError):
                json.dumps({"value": value}, allow_nan=False)

    def test_boolean_and_numeric_subclasses_are_never_canonical_float(self):
        class SpecialFloat(float):
            def __float__(self):
                raise AssertionError("subclass coercion must not occur")
        for value in (False, True, SpecialFloat(0.0), SpecialFloat(float("inf"))):
            with self.assertRaises(FiniteNumberRefused):
                review_finite_number(value)


if __name__ == "__main__":
    unittest.main()
