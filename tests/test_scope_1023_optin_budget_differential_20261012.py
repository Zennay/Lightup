"""#1023 deterministic shape scanner differential + allocation-order stress controls.

All fixtures in-memory; no network, grants, clients, execution or deployment.
"""
from __future__ import annotations

import json
import random
import unittest
from unittest.mock import patch

from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin
from test_scope_envelope_resource_bounds_reference_20261008 import bounded_envelope


def _tree(rng: random.Random, remaining: int):
    atoms = [None, True, False, 0, -1, 123, -0.125,
             "☃", "\\", '"', "[],:{}", "\n", "é💡", " \t "]
    if remaining <= 0 or rng.randrange(5) == 0:
        return rng.choice(atoms)
    if rng.randrange(2):
        return [_tree(rng, remaining - 1) for _ in range(rng.randrange(5))]
    keys = ['a', 'outer', '☃', 'q"quote', "\\slash", 'num', '']
    rng.shuffle(keys)
    return {key: _tree(rng, remaining - 1) for key in keys[:rng.randrange(5)]}


class OptinPreparseDifferential(unittest.TestCase):
    def test_deterministic_json_tree_parity_500_combinations(self):
        rng = random.Random(1023)
        for index in range(100):
            root = {f"item{index}": _tree(rng, 3)}
            raw = json.dumps(root, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
            for depth, nodes in ((1, 1), (2, 3), (3, 8), (4, 16), (8, 128)):
                with self.subTest(index=index, depth=depth, nodes=nodes):
                    expected = bounded_envelope(raw, max_depth=depth, max_nodes=nodes)
                    actual = bounded_envelope_shape_optin(
                        raw, max_depth=depth, max_nodes=nodes)
                    self.assertEqual(actual, expected)

    def test_many_flat_members_budget_before_json_parse(self):
        raw = json.dumps({"items": list(range(160))},
                         separators=(",", ":")).encode("ascii")
        with patch.object(json, "loads", side_effect=AssertionError("tree allocated")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(
                raw, max_bytes=8192, max_depth=8, max_nodes=100))
        decoder.assert_not_called()
        self.assertTrue(bounded_envelope_shape_optin(
            raw, max_bytes=8192, max_depth=8, max_nodes=162))

    def test_very_deep_preparse_is_iterative(self):
        raw = b'{"x":' * 1300 + b'null' + b'}' * 1300
        with patch.object(json, "loads", side_effect=AssertionError("tree allocated")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(
                raw, max_bytes=10000, max_depth=64, max_nodes=3000))
        decoder.assert_not_called()

    def test_multibyte_raw_byte_boundaries_precede_decode_and_parse(self):
        raw = '{"value":"☃é💡"}'.encode("utf-8")
        self.assertTrue(bounded_envelope_shape_optin(raw, max_bytes=len(raw)))
        with patch.object(json, "loads", side_effect=AssertionError("tree allocated")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(raw, max_bytes=len(raw)-1))
        decoder.assert_not_called()

    def test_punctuation_inside_escaped_object_names_is_not_structure(self):
        raw = json.dumps({'[]"\\{},:': {'a': [1, True]}},
                         ensure_ascii=False, separators=(",", ":")).encode()
        self.assertTrue(bounded_envelope_shape_optin(
            raw, max_depth=4, max_nodes=5))
        self.assertFalse(bounded_envelope_shape_optin(
            raw, max_depth=3, max_nodes=5))
        self.assertFalse(bounded_envelope_shape_optin(
            raw, max_depth=4, max_nodes=4))

    def test_preparse_denial_never_reads_or_modifies_grant_state(self):
        payload = b'{"issuer":"forged","tenant":"other","approved":true}'
        before = payload[:]
        self.assertTrue(bounded_envelope_shape_optin(payload))
        self.assertEqual(payload, before)
        with patch.object(json, "loads", side_effect=AssertionError("tree allocated")) as decoder:
            self.assertFalse(bounded_envelope_shape_optin(payload, max_nodes=1))
        decoder.assert_not_called()
        self.assertEqual(payload, before)


if __name__ == "__main__":
    unittest.main()
