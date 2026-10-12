"""Uninstalled #1023 lexical preparse admission regression, no authorization."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin
from test_scope_envelope_resource_bounds_reference_20261008 import bounded_envelope


class OptinPreparseNoTreeAllocation(unittest.TestCase):
    def test_depth_denied_before_json_loads(self):
        raw = b'{"outer":{"middle":{"inner":0}}}'
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as parser:
            self.assertFalse(bounded_envelope_shape_optin(raw, max_depth=2))
        parser.assert_not_called()

    def test_nodes_denied_before_json_loads(self):
        raw = b'{"items":[0,1,2,3,4]}'
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as parser:
            self.assertFalse(bounded_envelope_shape_optin(raw, max_nodes=6))
        parser.assert_not_called()

    def test_node_limit_inclusive_and_keys_not_counted(self):
        raw = b'{"items":[0,1,2,3,4]}'
        self.assertTrue(bounded_envelope_shape_optin(raw, max_nodes=7, max_depth=3))
        self.assertFalse(bounded_envelope_shape_optin(raw, max_nodes=6, max_depth=3))
        self.assertTrue(bounded_envelope_shape_optin(b'{"a":2}', max_nodes=2))
        self.assertFalse(bounded_envelope_shape_optin(b'{"a":2}', max_nodes=1))

    def test_depth_limit_inclusive_nested_array(self):
        raw = b'{"items":[null,{"inner":false}]}'
        self.assertTrue(bounded_envelope_shape_optin(raw, max_depth=4))
        self.assertFalse(bounded_envelope_shape_optin(raw, max_depth=3))

    def test_minimal_root_limits(self):
        self.assertTrue(bounded_envelope_shape_optin(b'{}', max_nodes=1, max_depth=1))
        self.assertFalse(bounded_envelope_shape_optin(b'{}', max_nodes=1, max_depth=0))
        self.assertFalse(bounded_envelope_shape_optin(b'[]', max_nodes=1, max_depth=1))
        self.assertFalse(bounded_envelope_shape_optin(b'null', max_nodes=1, max_depth=1))

    def test_early_size_and_configuration_before_json_loads(self):
        raw = b'{"items":[null]}'
        variants = [
            {"max_bytes":len(raw)-1}, {"max_depth":0}, {"max_nodes":False},
            {"max_bytes":"100"}, {"max_depth":True}, {"max_nodes":-1},
            {"max_depth":0.5}, {"max_nodes":None}
        ]
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as parser:
            for limits in variants:
                with self.subTest(limits=limits):
                    self.assertFalse(bounded_envelope_shape_optin(raw, **limits))
        parser.assert_not_called()

    def test_wrong_raw_type_refused_without_json_loads(self):
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as parser:
            for raw in ("{}", bytearray(b'{}'), memoryview(b'{}'), None, {}, 1):
                with self.subTest(type=type(raw).__name__):
                    self.assertFalse(bounded_envelope_shape_optin(raw))
        parser.assert_not_called()

    def test_bad_utf8_and_control_char_rejected_before_json_loads(self):
        for raw in (b'{"x":"\xff"}', b'{"x":"\x00"}', b'{"x":"\x1f"}'):
            with self.subTest(raw=raw):
                with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as parser:
                    self.assertFalse(bounded_envelope_shape_optin(raw))
                parser.assert_not_called()

    def test_long_nested_input_denied_without_decoder(self):
        raw = b'{"a":' * 220 + b'0' + b'}' * 220
        with patch.object(json, "loads", side_effect=AssertionError("decoder reached")) as parser:
            self.assertFalse(bounded_envelope_shape_optin(raw, max_depth=16))
        parser.assert_not_called()

    def test_dangling_commas_and_broken_json_denied(self):
        docs = (
            b'{"x":}', b'{"x":1,}', b'{"x":1,, "y":2}',
            b'{"x":[,1]}', b'{"x":[1,]}',
            b'{"x":true,}', b'{"x":1} trailing', b'{"x": 01}',
            b'{"x":1.}', b'{"x":+1}', b'{"x":1e}', b'{"x":-}',
            b'{"x":null}{}', b'{"x":"bad\\q"}',
            b'{"x":"\\uAAZ1"}', b'{"x":"open}',
            b'{"x":false} garbage',
        )
        for raw in docs:
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope_shape_optin(raw))

    def test_escaped_quotes_punctuation_and_legal_numbers(self):
        docs = (
            b'{"a\\\"b":"c,}:[]","n":-1.23e+4}',
            b'{"\\u0061":"x","items":[-0,0,0.2,1E-2]}',
            b' { "x" : [ ] , "obj" : {} } ',
            b'{"unicode":"\xe2\x98\x83","ok":true}',
        )
        for raw in docs:
            with self.subTest(raw=raw):
                self.assertTrue(bounded_envelope_shape_optin(raw))

    def test_escaped_and_nested_duplicate_keys_denied(self):
        for raw in (
            b'{"a":1,"\\u0061":2}',
            b'{"nested":{"x":1,"x":2}}',
            b'{"items":[{"z":0,"z":1}]}',
        ):
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope_shape_optin(raw))

    def test_nonfinite_denied(self):
        for raw in (
            b'{"v":NaN}', b'{"v":Infinity}', b'{"v":-Infinity}',
            b'{"v":1e999}', b'{"v":-1e999}',
        ):
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope_shape_optin(raw))

    def test_boundary_and_bom(self):
        raw = b'{"ok":true}'
        self.assertTrue(bounded_envelope_shape_optin(raw, max_bytes=len(raw)))
        self.assertFalse(bounded_envelope_shape_optin(raw, max_bytes=len(raw)-1))
        self.assertFalse(bounded_envelope_shape_optin(bytes.fromhex("efbbbf")+raw))

    def test_valid_samples_match_parent_reference_predicate(self):
        samples = (
            {"tenant":"lab.invalid", "enabled":False},
            {"a":1, "b":[1,2,3], "c":{"d":True}},
            {"text":"[] {} , : \\" and more", "numeric":-0.125},
            {"n":[{"x":2},None,{},[]]},
            {"unicode":"☃", "value":" \\u0000 "},
        )
        for value in samples:
            raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
            for depth, nodes in ((1,1),(2,3),(3,7),(8,128)):
                with self.subTest(value=value, depth=depth, nodes=nodes):
                    self.assertEqual(bounded_envelope_shape_optin(
                        raw, max_depth=depth, max_nodes=nodes),
                        bounded_envelope(raw, max_depth=depth, max_nodes=nodes))

    def test_error_path_does_not_mutate_caller_bytes(self):
        raw = b'{"a":[1,2,3]}'
        snapshot = raw[:]
        self.assertFalse(bounded_envelope_shape_optin(raw, max_nodes=2))
        self.assertEqual(raw, snapshot)

    def test_shape_only_never_confers_authorization(self):
        forged = b'{"issuer":"forged","tenant":"other","approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(forged))
        self.assertNotIn("authorization", bounded_envelope_shape_optin.__name__)


if __name__ == "__main__":
    unittest.main()
