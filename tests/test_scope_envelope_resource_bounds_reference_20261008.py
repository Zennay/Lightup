"""Offline reference limits for untrusted authorization envelopes.

This is not the production authorization parser or a grant issuer.
"""
import json
import math
import unittest


def bounded_envelope(raw: object, *, max_bytes: int = 4096, max_depth: int = 8,
                     max_nodes: int = 128) -> bool:
    """Reject excessive shape before downstream use; never grant authority."""
    if (type(raw) is not bytes
            or any(type(limit) is not int or limit < 1 for limit in
                   (max_bytes, max_depth, max_nodes))
            or len(raw) > max_bytes):
        return False
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return False
    if type(value) is not dict:
        return False
    stack = [(value, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > max_nodes or depth > max_depth:
            return False
        if type(node) is dict:
            for key, child in node.items():
                if type(key) is not str:
                    return False
                stack.append((child, depth + 1))
        elif type(node) is list:
            stack.extend((child, depth + 1) for child in node)
        elif type(node) is float:
            if not math.isfinite(node):
                return False
        elif type(node) not in (str, int, bool, type(None)):
            return False
    return True


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class EnvelopeBoundsReferenceTests(unittest.TestCase):
    def test_bounded_object_is_shape_eligible_not_authorized(self):
        self.assertTrue(bounded_envelope(b'{"tenant":"example","active":false}'))

    def test_outer_non_object_denied(self):
        for raw in (b'[]', b'"value"', b'null', b'false'):
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope(raw))

    def test_max_byte_boundary(self):
        raw = b'{"id":"x"}'
        self.assertTrue(bounded_envelope(raw, max_bytes=len(raw)))
        self.assertFalse(bounded_envelope(raw, max_bytes=len(raw)-1))

    def test_excessively_nested(self):
        raw = b'{"a":' * 12 + b'0' + b'}' * 12
        self.assertFalse(bounded_envelope(raw))

    def test_excessive_nodes(self):
        self.assertFalse(bounded_envelope(json.dumps({"items": list(range(30))}).encode(),
                                          max_nodes=20))

    def test_duplicate_property_denied(self):
        self.assertFalse(bounded_envelope(b'{"active":false,"active":true}'))

    def test_invalid_utf8_denied(self):
        self.assertFalse(bounded_envelope(b'{"x":"\\xff"}'.replace(b'\\xff', bytes([255]))))

    def test_non_finite_number_denied(self):
        self.assertFalse(bounded_envelope(b'{"risk":NaN}'))

    def test_nonfinite_exponent_overflow_denied(self):
        # Python JSON accepts exponent overflow as inf without parse_constant.
        for raw in (b'{"risk":1e999}', b'{"risk":-1e999}',
                    b'{"nested":[1e999]}'):
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope(raw))

    def test_finite_decimal_allowed_as_shape_only(self):
        self.assertTrue(bounded_envelope(b'{"risk":1.25}'))

    def test_wrong_input_type_denied(self):
        for raw in ('{}', bytearray(b'{}'), memoryview(b'{}'), None):
            with self.subTest(t=type(raw).__name__):
                self.assertFalse(bounded_envelope(raw))

    def test_invalid_budget_configuration_fails_closed(self):
        for name in ("max_bytes", "max_depth", "max_nodes"):
            for invalid in (0, -1, True, False, 1.5, "100", None):
                with self.subTest(name=name, invalid=invalid):
                    self.assertFalse(bounded_envelope(b'{}', **{name: invalid}))

    def test_exact_root_node_and_depth_boundaries(self):
        self.assertTrue(bounded_envelope(b'{}', max_nodes=1, max_depth=1))
        self.assertFalse(bounded_envelope(b'{"a":1}', max_nodes=1))
        self.assertFalse(bounded_envelope(b'{"a":1}', max_depth=1))
        self.assertTrue(bounded_envelope(b'{"a":1}', max_nodes=2, max_depth=2))

    def test_deeply_nested_input_never_raises(self):
        raw = b'{"a":' * 300 + b'null' + b'}' * 300
        self.assertFalse(bounded_envelope(raw, max_bytes=10000))

    def test_duplicate_keys_nested_or_escaped_denied(self):
        for raw in (
            b'{"outer":{"x":1,"x":2}}',
            b'{"a":1,"\\\\u0061":2}',
            b'{"entries":[{"x":1,"x":2}]}',
        ):
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope(raw))

    def test_noncanonical_document_boundaries_denied(self):
        for raw in (
            b'', b'   ', b'{}{}', b'{} true',
            bytes([0xef, 0xbb, 0xbf]) + b'{}',
            b'{"ok":true} trailing',
        ):
            with self.subTest(raw=raw):
                self.assertFalse(bounded_envelope(raw))

    def test_max_nodes_inclusive_for_nested_containers(self):
        document = b'{"items":[true,null]}'
        self.assertTrue(bounded_envelope(document, max_nodes=4, max_depth=3))
        self.assertFalse(bounded_envelope(document, max_nodes=3, max_depth=3))
        self.assertFalse(bounded_envelope(document, max_nodes=4, max_depth=2))

    def test_no_mutation_of_caller_buffer(self):
        raw = b'{"nested":{"active":false}}'
        snapshot = raw[:]
        bounded_envelope(raw)
        self.assertEqual(raw, snapshot)


if __name__ == "__main__":
    unittest.main()
