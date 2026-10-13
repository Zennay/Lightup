"""#1023 opt-in JSON envelope Unicode scalar-value safety regressions.

No grant, issuer or endpoint logic; tests are offline byte arrays only.
Escaped isolated UTF-16 surrogates are not Unicode scalar values, even though
the standard Python JSON decoder may accept them. Reject during preparse
rather than treating their shape as a plausible authorization envelope.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin


class UnicodeScalarPreparseTests(unittest.TestCase):
    def test_isolated_high_surrogate_value_rejected_before_decoder(self):
        samples = (
            b'{"name":"\\uD800"}', b'{"name":"\\udbff"}',
            b'{"nested":{"name":"\\uD834a"}}',
            b'{"list":["\\uD800"]}', b'{"value":"prefix\\uDBFFsuffix"}',
        )
        for raw in samples:
            with self.subTest(raw=raw), patch.object(
                json, "loads", side_effect=AssertionError("should preparse deny")
            ) as decoder:
                self.assertFalse(bounded_envelope_shape_optin(raw))
                decoder.assert_not_called()

    def test_isolated_low_surrogate_value_rejected_before_decoder(self):
        samples = (
            b'{"name":"\\uDC00"}', b'{"name":"\\udfff"}',
            b'{"nested":["\\uDC01"]}', b'{"name":"\\udf00\\uD800"}',
        )
        for raw in samples:
            with self.subTest(raw=raw), patch.object(
                json, "loads", side_effect=AssertionError("should preparse deny")
            ) as decoder:
                self.assertFalse(bounded_envelope_shape_optin(raw))
                decoder.assert_not_called()

    def test_isolated_surrogate_object_key_rejected_before_decoder(self):
        samples = (
            b'{"\\ud800":1}', b'{"nested":{"\\uDC00":1}}',
            b'{"items":[{"prefix\\udfff":true}]}',
        )
        for raw in samples:
            with self.subTest(raw=raw), patch.object(
                json, "loads", side_effect=AssertionError("should preparse deny")
            ) as decoder:
                self.assertFalse(bounded_envelope_shape_optin(raw))
                decoder.assert_not_called()

    def test_high_surrogate_followed_by_non_low_is_rejected(self):
        samples = (
            b'{"s":"\\ud800\\u0041"}',
            b'{"s":"\\ud800\\ud800"}',
            b'{"s":"\\ud800\\\\uDC00"}',
            b'{"s":"\\ud800\\udbff\\udc00"}',
        )
        for raw in samples:
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope_shape_optin(raw))

    def test_well_paired_escaped_utf16_is_shape_eligible(self):
        samples = (
            b'{"s":"\\ud83d\\ude00"}',
            b'{"\\ud83d\\ude00":"emoji"}',
            b'{"nested":{"s":["\\uD800\\uDC00","\\uDBFF\\uDFFF"]}}',
            b'{"s":"prefix\\ud83d\\ude00suffix"}',
        )
        for raw in samples:
            with self.subTest(raw=raw):
                self.assertTrue(bounded_envelope_shape_optin(raw))

    def test_regular_escaped_bmp_and_literal_emoji_still_allowed(self):
        samples = (
            b'{"s":"\\u0000\\u007f\\uD7FF\\uE000\\uFFFF"}',
            '{"s":"☃é💡"}'.encode("utf-8"),
            b'{"s":"\\\\uD800"}',  # literal backslash-u text
            b'{"s":"\\u0061","\\u0062":"ok"}',
        )
        for raw in samples:
            with self.subTest(raw=raw):
                self.assertTrue(bounded_envelope_shape_optin(raw))

    def test_exact_size_budget_remains_predecode_even_for_surrogates(self):
        raw = b'{"s":"\\ud800"}'
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(raw, max_bytes=len(raw)-1))
        decoder.assert_not_called()

    def test_whole_valid_surrogate_pair_obeys_node_and_depth_budget(self):
        raw = b'{"s":["\\ud83d\\ude00"]}'
        self.assertTrue(bounded_envelope_shape_optin(
            raw, max_nodes=3, max_depth=3))
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(
                raw, max_nodes=2, max_depth=3))
            self.assertFalse(bounded_envelope_shape_optin(
                raw, max_nodes=3, max_depth=2))
        decoder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
