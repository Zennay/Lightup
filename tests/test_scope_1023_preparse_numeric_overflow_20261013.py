"""#1023 W11: numeric exponent overflow must deny BEFORE json.loads.

All fixtures are synthetic offline JSON byte buffers. The optional shape
predicate cannot authorize grants, clients, target scans or tool dispatch.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin


class NumericPreparseFiniteness(unittest.TestCase):
    def assert_no_full_parser(self, raw: bytes, **bounds) -> None:
        with patch.object(json, "loads", side_effect=AssertionError("JSON tree allocated")) as parser:
            self.assertFalse(bounded_envelope_shape_optin(raw, **bounds))
        parser.assert_not_called()

    def test_float_overflow_before_full_json_parser_at_root_member(self):
        for raw in (
            b'{"risk":1e999}', b'{"risk":-1e999}',
            b'{"risk":1E+9999}', b'{"risk":-9.9E999}',
        ):
            with self.subTest(raw=raw):
                self.assert_no_full_parser(raw)

    def test_float_overflow_before_full_parser_when_nested(self):
        for raw in (
            b'{"items":[1e999]}',
            b'{"items":[{"amount":1e999}]}',
            b'{"outer":{"middle":{"ratio":-1e999}}}',
            b'{"values":[1.25,2,1e999,3]}',
        ):
            with self.subTest(raw=raw):
                self.assert_no_full_parser(raw)

    def test_boundary_between_finite_and_overflow_floats(self):
        self.assertTrue(bounded_envelope_shape_optin(b'{"value":1e308}'))
        self.assertTrue(bounded_envelope_shape_optin(b'{"value":-1.7976931348623157e308}'))
        self.assert_no_full_parser(b'{"value":1e309}')
        self.assert_no_full_parser(b'{"value":1.7976931348623159e308}')

    def test_nonfinite_constants_are_grammar_denied_before_parse(self):
        for raw in (
            b'{"value":NaN}', b'{"value":Infinity}',
            b'{"value":-Infinity}', b'{"value":[NaN]}',
        ):
            with self.subTest(raw=raw):
                self.assert_no_full_parser(raw)

    def test_finite_decimal_and_exponent_samples_stay_eligible(self):
        for raw in (
            b'{"v":0.1}', b'{"v":-0.1}', b'{"v":-0}',
            b'{"v":-0.0}', b'{"v":1.5E+1}', b'{"v":-1.25e-6}',
            b'{"v":1e-308}', b'{"v":[1e308,1.23,0.1,0]}',
            b'{"v":{"ratio":2.5e10}}',
        ):
            with self.subTest(raw=raw):
                self.assertTrue(bounded_envelope_shape_optin(raw))

    def test_integer_literals_do_not_turn_into_floats(self):
        for raw in (
            b'{"count":12345678901234567890123456789}',
            b'{"count":-12345678901234567890123456789}',
            b'{"count":0}', b'{"count":-0}',
        ):
            with self.subTest(raw=raw):
                self.assertTrue(bounded_envelope_shape_optin(raw))

    def test_malformed_exponents_deny_before_full_parser(self):
        for raw in (
            b'{"v":1e}', b'{"v":1E+}', b'{"v":1e-}',
            b'{"v":0x10}', b'{"v":1.e5}', b'{"v":+1e10}',
            b'{"v":1e10e10}',
        ):
            with self.subTest(raw=raw):
                self.assert_no_full_parser(raw)

    def test_early_byte_budget_still_wins_over_numeric_parse(self):
        raw = b'{"amount":1e999}'
        self.assert_no_full_parser(raw, max_bytes=len(raw)-1)
        self.assert_no_full_parser(raw, max_nodes=1)

    def test_float_overflow_in_non_authority_claim_denies(self):
        self.assert_no_full_parser(
            b'{"approved":true,"tenant":"forged","risk":1e999}')
        # A finite numeric risk is only shape-eligible, not approved.
        self.assertTrue(bounded_envelope_shape_optin(
            b'{"approved":true,"tenant":"forged","risk":5}'))

    def test_malformed_overflow_suffix_cannot_bypass_scanner(self):
        for raw in (
            b'{"v":1e9999tail}', b'{"v":1e9999 1}',
            b'{"v":[1e9999,]}', b'{"v":-1e9999,}',
        ):
            with self.subTest(raw=raw):
                self.assert_no_full_parser(raw)


if __name__ == "__main__":
    unittest.main()
