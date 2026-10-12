"""#1023 negative preparse resource-order canaries, synthetic and uninstalled.

Run on the immutable #1012 reference parent. Two deliberately expected RED
tests document that max_depth/max_nodes are currently enforced *after*
json.loads has allocated a parsed tree. Green size/type/encoding controls
prevent mistakenly treating these two gaps as total resource-safety proof.

No real grant, HTTP request, target, network I/O or executor use.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from test_scope_envelope_resource_bounds_reference_20261008 import bounded_envelope


class EnvelopePreparseResourceGap(unittest.TestCase):
    @unittest.expectedFailure
    def test_depth_exceeded_should_not_enter_json_parser(self):
        """RED: depth ceiling must precede allocation if used as a preparse bound."""
        raw = b'{"outer":{"middle":{"inner":0}}}'
        with patch.object(json, "loads", side_effect=AssertionError("JSON parsed before depth gate")) as parser:
            self.assertFalse(bounded_envelope(raw, max_depth=2))
        parser.assert_not_called()

    @unittest.expectedFailure
    def test_node_limit_exceeded_should_not_enter_json_parser(self):
        """RED: full parse currently happens before traversal counts nodes."""
        raw = b'{"items":[0,1,2,3,4]}'
        with patch.object(json, "loads", side_effect=AssertionError("JSON parsed before node gate")) as parser:
            self.assertFalse(bounded_envelope(raw, max_nodes=2))
        parser.assert_not_called()

    def test_byte_ceiling_still_denies_before_parser(self):
        raw = b'{"scope":{"assets":["lab.invalid"]}}'
        with patch.object(json, "loads", side_effect=AssertionError("decoder called")) as parser:
            self.assertFalse(bounded_envelope(raw, max_bytes=len(raw) - 1))
        parser.assert_not_called()

    def test_bad_integer_budget_denied_before_parser(self):
        for bad in (True, False, -1, 0, 0.25, "2", None):
            with self.subTest(bad=bad):
                with patch.object(json, "loads", side_effect=AssertionError("decoder called")) as parser:
                    self.assertFalse(bounded_envelope(b'{}', max_nodes=bad))
                parser.assert_not_called()

    def test_utf8_decode_failure_does_not_enter_json_parser(self):
        raw = b'{"x":"\xff"}'
        with patch.object(json, "loads", side_effect=AssertionError("decoder called")) as parser:
            self.assertFalse(bounded_envelope(raw))
        parser.assert_not_called()

    def test_depth_denial_without_parser_spy_is_shape_only(self):
        raw = b'{"outer":{"middle":{"inner":0}}}'
        self.assertFalse(bounded_envelope(raw, max_depth=2))
        self.assertTrue(bounded_envelope(raw, max_depth=4))

    def test_node_denial_without_parser_spy_is_shape_only(self):
        raw = b'{"items":[0,1,2,3,4]}'
        self.assertFalse(bounded_envelope(raw, max_nodes=2))
        self.assertTrue(bounded_envelope(raw, max_nodes=7))

    def test_budget_non_authority_even_for_positive_shape(self):
        # Valid JSON is not a trusted issuer, tenant, consent or current grant.
        forged = b'{"trusted":true,"approved":true,"grant":"forged"}'
        self.assertIs(bounded_envelope(forged), True)


if __name__ == "__main__":
    unittest.main()
