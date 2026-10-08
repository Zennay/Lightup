"""Offline reference acceptance tests for untrusted authorization identifier syntax.

These tests intentionally do not exercise a production authorization grant.
"""
import re
import unittest

IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z", re.ASCII)

def reference_identifier(value):
    # No implicit coercion, whitespace repair, case folding or Unicode normalization.
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None

class IdentifierBoundaryContract(unittest.TestCase):
    def test_canonical_ascii_identifiers(self):
        for value in ("a", "tenant-1", "asset_23", "0", "a" * 64):
            with self.subTest(value=value):
                self.assertTrue(reference_identifier(value))

    def test_noncanonical_or_ambiguous_identifiers_deny(self):
        for value in ("", " ", " tenant", "tenant ", "Tenant", "a.b", "a/b",
                      "a\\b", "a:b", "a@b", "_abc", "-abc", "abc_", "abc-",
                      "a" * 65, "a\n", "a\x00", "a\t", "a\r", "a\u200b",
                      "a\u00e9", "a\u0430", "a\uff41", "a\u212a"):
            with self.subTest(value=repr(value)):
                self.assertFalse(reference_identifier(value))

    def test_wrong_types_deny_even_when_stringifiable(self):
        class LooksValid:
            def __str__(self):
                return "tenant-1"
        class StringSubclass(str):
            pass
        for value in (None, True, False, 1, 0, b"tenant-1", ["tenant-1"],
                      {"id": "tenant-1"}, LooksValid(), StringSubclass("tenant-1")):
            with self.subTest(type=type(value).__name__):
                self.assertFalse(reference_identifier(value))

    def test_identity_does_not_silently_canonicalize(self):
        for value in ("Tenant", "tenant ", "t\u0435nant", "Ｔenant"):
            self.assertFalse(reference_identifier(value))
            self.assertNotEqual(value, "tenant")

if __name__ == "__main__":
    unittest.main()
