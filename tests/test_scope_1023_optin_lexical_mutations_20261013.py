"""#1023 W8: deterministic lexical/framing mutation and budget-order acceptance.

Synthetic local byte buffers only. Never issues grants or calls networking,
ToolExecutor, WSGI, a real client, target, or production endpoints.
"""
from __future__ import annotations

import json
import random
import unittest
from unittest.mock import patch

from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin


class LexicalMutationAcceptance(unittest.TestCase):
    def _assert_preparse_deny(self, raw: bytes, **kwargs):
        with patch.object(
            json, "loads", side_effect=AssertionError("full JSON parser reached")
        ) as parser:
            self.assertFalse(bounded_envelope_shape_optin(raw, **kwargs))
        parser.assert_not_called()

    def test_bad_object_separator_matrix_fails_before_parser(self):
        rejected = (
            b'{"a" 1}', b'{"a";1}', b'{"a"=1}', b'{"a":}',
            b'{"a":1,}', b'{"a":1,, "b":2}', b'{,"a":1}',
            b'{"a":1 "b":2}', b'{"a":1;"b":2}', b'{"a",1}',
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_bad_array_separator_matrix_fails_before_parser(self):
        rejected = (
            b'{"a":[,1]}', b'{"a":[1,]}', b'{"a":[1,,2]}',
            b'{"a":[1;2]}', b'{"a":[1 2]}', b'{"a":[1:2]}',
            b'{"a":[1,,]}', b'{"a":[{,}]}', b'{"a":[,]}',
            b'{"a":[true false]}',
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_invalid_primitive_terminators_fail_before_parser(self):
        rejected = (
            b'{"v":01}', b'{"v":00}', b'{"v":+1}',
            b'{"v":--1}', b'{"v":1.}', b'{"v":1e}',
            b'{"v":1e+}', b'{"v":1e-}', b'{"v":.1}',
            b'{"v":TRUE}', b'{"v":False}', b'{"v":nul}',
            b'{"v":NaN}', b'{"v":Infinity}', b'{"v":-Infinity}',
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_invalid_string_escapes_fail_before_parser(self):
        rejected = (
            b'{"v":"\\q"}', b'{"v":"\\z"}',
            b'{"v":"\\u000"}', b'{"v":"\\u000q"}',
            b'{"v":"\\u12XX"}', b'{"v":"\\uD800"}',
            b'{"\\uDC00":false}', b'{"v":"abc\\',
            b'{"v":"abc\n"}',
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_trailing_document_framing_fails_before_parser(self):
        rejected = (
            b'{}{}', b'{} true', b'{} 0', b'{}[]',
            b'{} trailing', b'{}\x00', b'{}\xef\xbb\xbf',
            b' \t{} \n:', b' \r\n{}\r\n{}',
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_root_must_be_object_before_parser(self):
        for raw in (b'[]', b'[{}]', b'null', b'true', b'false', b'1', b'""'):
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_object_value_nested_budget_precedes_parser(self):
        raw = b'{"root":{"a":[true,false,null,0],"b":{}}}'
        # 1 root + 1 object + 1 array + 4 scalars + 1 object = 8
        self.assertTrue(bounded_envelope_shape_optin(raw, max_depth=4, max_nodes=8))
        self._assert_preparse_deny(raw, max_depth=3, max_nodes=8)
        self._assert_preparse_deny(raw, max_depth=4, max_nodes=7)

    def test_deterministic_random_prefix_truncations_are_preparse_denied(self):
        rng = random.Random(1023)
        documents = (
            b'{"tenant":"lab","scope":{"capabilities":["read","report"]}}',
            b'{"nested":[{"ok":true},{"ok":false}],"count":12}',
            '{"unicode":"☃é💡","escape":"\\\\\\\"","null":null}'.encode("utf-8"),
        )
        for raw in documents:
            self.assertTrue(bounded_envelope_shape_optin(raw))
            cutpoints = sorted(rng.sample(range(1, len(raw)), min(12, len(raw)-1)))
            for position in cutpoints:
                prefix = raw[:position]
                with self.subTest(raw=raw[:30], position=position):
                    self._assert_preparse_deny(prefix)

    def test_invalid_utf8_boundaries_rejected_before_parser(self):
        for raw in (
            b'{"value":"\xc0\xaf"}', b'{"value":"\xed\xa0\x80"}',
            b'{"value":"\xf4\x90\x80\x80"}', b'{"value":"\xff"}',
            b'{"value":"\xe2\x82"}', b'{"value":"\x80"}',
        ):
            with self.subTest(raw=raw):
                self._assert_preparse_deny(raw)

    def test_valid_raw_unicode_and_escaped_pair_have_same_shape(self):
        literal = '{"note":"😀☃é","active":false}'.encode()
        escaped = b'{"note":"\\ud83d\\ude00\\u2603\\u00e9","active":false}'
        self.assertEqual(json.loads(literal), json.loads(escaped))
        self.assertTrue(bounded_envelope_shape_optin(literal))
        self.assertTrue(bounded_envelope_shape_optin(escaped))
        for max_nodes in (1, 2):
            self._assert_preparse_deny(literal, max_nodes=max_nodes)
            self._assert_preparse_deny(escaped, max_nodes=max_nodes)

    def test_invalid_budget_type_rejected_prior_to_decoder(self):
        invalid = (None, True, False, -2, 0, 0.0, float("nan"), "4", b"4")
        for field in ("max_bytes", "max_depth", "max_nodes"):
            for value in invalid:
                with self.subTest(field=field, value=repr(value)):
                    self._assert_preparse_deny(b'{}', **{field:value})

    def test_one_byte_overrun_and_exact_ceiling(self):
        payload = '{"value":"é💡☃"}'.encode("utf-8")
        self.assertTrue(bounded_envelope_shape_optin(payload, max_bytes=len(payload)))
        self._assert_preparse_deny(payload, max_bytes=len(payload)-1)
        self._assert_preparse_deny(payload, max_bytes=1)


if __name__ == "__main__":
    unittest.main()
