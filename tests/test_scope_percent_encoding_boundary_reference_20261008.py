"""Offline canonical percent-encoding boundary reference; NOT production authorization.

No network operations, URL resolution, grants, or target dispatch are performed.
"""
import string
import unittest
from urllib.parse import unquote

_HEX = frozenset(string.hexdigits)


def canonical_scope_segment(value):
    """Accept exact ASCII scope segments, refusing percent-encoded aliases.

    This intentionally restrictive *reference* grammar is a proposed owner
    decision, not a substitute for the actual policy's resource grammar.
    """
    if type(value) is not str or not value or len(value) > 128:
        return False
    return all(ch in string.ascii_letters + string.digits + "-._~" for ch in value)


def percent_alias(value):
    if type(value) is not str:
        return False
    return "%" in value or unquote(value) != value


class PercentEncodingBoundaryReferenceTests(unittest.TestCase):
    def test_literal_safe_scope_segment(self):
        for value in ("asset-1", "TENANT_5", "a.b", "~"):
            with self.subTest(value=value):
                self.assertTrue(canonical_scope_segment(value))

    def test_reject_single_encoded_aliases(self):
        for value in ("%61sset", "asset%2d1", "%7E", "%2e", "%2F", "%5c"):
            with self.subTest(value=value):
                self.assertFalse(canonical_scope_segment(value))
                self.assertTrue(percent_alias(value))

    def test_reject_double_encoded_aliases(self):
        for value in ("%2561sset", "%252f", "%255c", "%252e%252e"):
            with self.subTest(value=value):
                self.assertFalse(canonical_scope_segment(value))

    def test_reject_ambiguous_or_malformed_escape_sequences(self):
        for value in ("asset%", "%", "%GG", "%2", "%u0061", "a%00b"):
            with self.subTest(value=value):
                self.assertFalse(canonical_scope_segment(value))

    def test_reject_separator_and_unicode_variants(self):
        for value in ("a/b", "a\\b", "a:b", "a b", "é", "a\u200bb", "../x"):
            with self.subTest(value=value):
                self.assertFalse(canonical_scope_segment(value))

    def test_reject_wrong_types(self):
        class StringSubclass(str):
            pass
        for value in (None, b"asset", 1, True, StringSubclass("asset")):
            with self.subTest(value=repr(value)):
                self.assertFalse(canonical_scope_segment(value))

    def test_reject_empty_and_oversized_segments(self):
        self.assertFalse(canonical_scope_segment(""))
        self.assertFalse(canonical_scope_segment("a" * 129))
        self.assertTrue(canonical_scope_segment("a" * 128))

    def test_no_implicit_decoding_or_casefolding(self):
        self.assertNotEqual("ASSET", "asset")
        self.assertNotEqual("%61sset", "asset")
        self.assertFalse(canonical_scope_segment("%61sset"))


if __name__ == "__main__":
    unittest.main()
