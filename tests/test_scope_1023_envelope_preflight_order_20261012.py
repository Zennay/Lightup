"""Offline integration-order acceptance for #1023 (reference gate only).

Run against the #1012 exact-head parent using:
  python -m unittest discover -s tests -p 'test_scope_1023_envelope_preflight_order_20261012.py' -v

NO production parsing, authorization, target activity, network or executor dispatch.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from test_scope_envelope_resource_bounds_reference_20261008 import bounded_envelope


class EnvelopePreflightOrderAcceptance(unittest.TestCase):
    """The imported shape predicate is NOT an authorization check."""

    def assert_refused_before_parse(self, body: object, **budgets: object) -> None:
        # Poisoning json.loads makes the absence of parser invocation observable.
        with patch.object(json, "loads", side_effect=AssertionError("parsed rejected input")) as parser:
            self.assertFalse(bounded_envelope(body, **budgets))
        parser.assert_not_called()

    def test_oversize_bytes_are_denied_before_json_parse(self) -> None:
        self.assert_refused_before_parse(b'{"a":"' + b"x" * 80 + b'"}', max_bytes=32)

    def test_bad_budget_is_denied_before_json_parse(self) -> None:
        for key in ("max_bytes", "max_depth", "max_nodes"):
            for bad in (True, False, 0, -1, 1.25, None, "8"):
                with self.subTest(budget=key, value=bad):
                    self.assert_refused_before_parse(b'{"safe":true}', **{key: bad})

    def test_typed_bytes_gate_runs_before_json_parse(self) -> None:
        class SpoofBytes(bytes):
            pass
        for body in (SpoofBytes(b"{}"), bytearray(b"{}"), memoryview(b"{}"), "{}", None):
            with self.subTest(body_type=type(body).__name__):
                self.assert_refused_before_parse(body)

    def test_boundary_bytes_parse_at_exact_limit(self) -> None:
        raw = b'{"scope":{"assets":["local.test"]}}'
        with patch.object(json, "loads", wraps=json.loads) as parser:
            self.assertTrue(bounded_envelope(raw, max_bytes=len(raw)))
            self.assertFalse(bounded_envelope(raw, max_bytes=len(raw) - 1))
            self.assertEqual(parser.call_count, 1)

    def test_invalid_utf8_within_budget_is_rejected(self) -> None:
        self.assertFalse(bounded_envelope(b'{"a":"\xff"}', max_bytes=100))

    def test_escaped_duplicate_key_after_decoding_denied(self) -> None:
        self.assertFalse(bounded_envelope(b'{"scope":1,"sc\\u006fpe":2}'))

    def test_exponent_overflow_within_budget_denied(self) -> None:
        self.assertFalse(bounded_envelope(b'{"max_risk":1e999}'))

    def test_trailing_document_denied(self) -> None:
        self.assertFalse(bounded_envelope(b'{"scope":{}} {"scope":{}}'))

    def test_max_node_count_is_inclusive(self) -> None:
        raw = b'{"scope":{"assets":["local.test"]}}'
        # root dict -> nested dict -> list -> scalar = four nodes.
        self.assertTrue(bounded_envelope(raw, max_nodes=4, max_depth=4))
        self.assertFalse(bounded_envelope(raw, max_nodes=3, max_depth=4))
        self.assertFalse(bounded_envelope(raw, max_nodes=4, max_depth=3))

    def test_shape_success_has_no_authorization_result(self) -> None:
        # A well-formed request can be malicious, revoked or cross-tenant;
        # syntactic eligibility cannot be interpreted as any authorization.
        raw = b'{"issuer":"UNVERIFIED","tenant":"OTHER","risk":5,"approved":true}'
        self.assertTrue(bounded_envelope(raw))
        self.assertIs(type(bounded_envelope(raw)), bool)

    def test_mutable_source_buffer_denied_without_rewrite(self) -> None:
        raw = bytearray(b'{"scope":{}}')
        before = bytes(raw)
        self.assertFalse(bounded_envelope(raw))
        self.assertEqual(bytes(raw), before)

    def test_invalid_document_does_not_raise_or_leak_bytes(self) -> None:
        payloads = [b'', b'{', b'{"a":NaN}', b'{"a":[1,2,}', b'\xef\xbb\xbf{}']
        for payload in payloads:
            with self.subTest(length=len(payload)):
                self.assertIs(bounded_envelope(payload), False)


if __name__ == "__main__":
    unittest.main()
