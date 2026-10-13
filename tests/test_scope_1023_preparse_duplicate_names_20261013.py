"""#1023 W10: reject duplicate decoded JSON object names BEFORE full-tree parsing.

Only exercises the isolated, uninstalled, non-authorizing shape helper.
It must never turn a syntactically accepted document into a trusted issuer,
current grant, consent, valid tenant, or permission to execute a tool.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin


class DuplicateKeyEarlyDenial(unittest.TestCase):
    def assert_rejected_without_full_decoder(self, raw: bytes, **budgets) -> None:
        with patch.object(json, "loads", side_effect=AssertionError("full JSON tree allocated")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(raw, **budgets))
        decoder.assert_not_called()

    def test_root_literal_duplicate_refused_before_full_decoder(self):
        self.assert_rejected_without_full_decoder(
            b'{"tenant":"alice","tenant":"bob","approved":true}')

    def test_escaped_key_alias_refused_before_full_decoder(self):
        variants = (
            b'{"tenant":1,"\\u0074enant":2}',
            b'{"\\u0074enant":1,"tenant":2}',
            b'{"a":false,"\\u0061":true}',
            b'{"\\u0061":0,"\\u0061":1}',
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self.assert_rejected_without_full_decoder(raw)

    def test_escaped_and_literal_emoji_names_collide_before_full_decoder(self):
        variants = (
            '{"😀":1,"\\ud83d\\ude00":2}'.encode(),
            b'{"\\ud83d\\ude00":1,"\\uD83D\\uDE00":2}',
            '{"\\ud83d\\ude00":1,"😀":2}'.encode(),
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self.assert_rejected_without_full_decoder(raw)

    def test_nested_objects_refuse_colliding_names_before_full_decoder(self):
        variants = (
            b'{"outer":{"tenant":1,"\\u0074enant":2}}',
            b'{"items":[{"id":1,"id":2}]}',
            b'{"a":{"b":{"approved":true,"approved":false}}}',
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self.assert_rejected_without_full_decoder(raw)

    def test_escaped_slash_quote_and_backslash_are_canonical_names(self):
        variants = (
            b'{"a/b":1,"a\\/b":2}',
            b'{"a\\"b":1,"a\\u0022b":2}',
            b'{"\\\\":1,"\\u005c":2}',
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self.assert_rejected_without_full_decoder(raw)

    def test_empty_name_alias_collision_before_full_decoder(self):
        self.assert_rejected_without_full_decoder(b'{"":0,"\\u0000":1,"":2}')

    def test_sibling_object_names_are_independent(self):
        doc = b'{"left":{"tenant":"alpha"},"right":{"tenant":"beta"}}'
        self.assertTrue(bounded_envelope_shape_optin(doc))
        self.assertTrue(bounded_envelope_shape_optin(
            b'{"items":[{"id":1},{"id":2},{"id":3}]}'))

    def test_duplicate_key_is_not_a_node_and_limits_still_apply(self):
        doc = b'{"id":1,"id":2}'
        self.assert_rejected_without_full_decoder(doc, max_nodes=3, max_depth=2)
        self.assert_rejected_without_full_decoder(doc, max_nodes=2, max_depth=2)
        self.assertTrue(bounded_envelope_shape_optin(
            b'{"id":1,"other":2}', max_nodes=3, max_depth=2))

    def test_byte_budget_terminates_before_key_decode(self):
        doc = b'{"tenant":1,"tenant":2}'
        with patch.object(json.decoder, "scanstring", side_effect=AssertionError("key decoded")) as scanner:
            self.assertFalse(bounded_envelope_shape_optin(doc, max_bytes=len(doc)-1))
        scanner.assert_not_called()

    def test_missing_or_invalid_escape_denied_without_full_decoder(self):
        for doc in (b'{"id":1,"\\uxxyz":2}',
                    b'{"id":1,"\\uD800":2}',
                    b'{"id":1,"\\":2}'):
            with self.subTest(doc=doc):
                self.assert_rejected_without_full_decoder(doc)

    def test_scanner_key_decode_failure_fails_closed(self):
        doc = b'{"tenant":"synthetic"}'
        with patch.object(json.decoder, "scanstring", side_effect=ValueError("invalid name")):
            with patch.object(json, "loads", side_effect=AssertionError("full decoder reached")) as decoder:
                self.assertFalse(bounded_envelope_shape_optin(doc))
            decoder.assert_not_called()

    def test_semantic_approval_value_can_never_authorize(self):
        forged = b'{"issuer":"claimed","tenant":"other","approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(forged))
        # True here still means syntactically well-formed; there is no
        # issuer, grant lookup, consent or network-active path in this helper.
        self.assertIs(type(bounded_envelope_shape_optin(forged)), bool)


if __name__ == "__main__":
    unittest.main()
