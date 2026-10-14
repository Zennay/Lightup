"""Offline reference: capability identifiers must never gain authority by case folding.

This module does NOT exercise production approval, grant issuance or dispatch.
"""
import unittest
import unicodedata


def _eligible(granted, requested):
    """Reference-only exact lexical membership, not an authorization engine."""
    if type(granted) is not tuple or any(type(x) is not str for x in granted):
        return False
    if type(requested) is not str or not requested or len(requested) > 128:
        return False
    if any(not x or len(x) > 128 for x in granted):
        return False
    return requested in granted


class CapabilityCaseBoundaryReference(unittest.TestCase):
    def test_exact_positive_control(self):
        self.assertTrue(_eligible(("web-baseline",), "web-baseline"))

    def test_ascii_case_never_widens(self):
        self.assertFalse(_eligible(("web-baseline",), "WEB-BASELINE"))
        self.assertFalse(_eligible(("Web-Baseline",), "web-baseline"))

    def test_unicode_casefold_alias_never_widens(self):
        self.assertFalse(_eligible(("strasse",), "straße"))
        self.assertFalse(_eligible(("K",), "K"))

    def test_normalization_alias_never_widens(self):
        canonical = unicodedata.normalize("NFC", "cafe\u0301")
        self.assertFalse(_eligible((canonical,), "cafe\u0301"))

    def test_whitespace_variants_are_not_authority(self):
        for requested in (" web-baseline", "web-baseline ", "web-baseline\n"):
            with self.subTest(requested=repr(requested)):
                self.assertFalse(_eligible(("web-baseline",), requested))

    def test_non_string_and_mutable_collection_rejected(self):
        for granted, requested in ((["web-baseline"], "web-baseline"),
                                   (("web-baseline",), 1),
                                   ((1,), "web-baseline"),
                                   (("web-baseline",), True)):
            with self.subTest(granted=repr(granted), requested=repr(requested)):
                self.assertFalse(_eligible(granted, requested))

    def test_overlength_fails_closed(self):
        self.assertFalse(_eligible(("x" * 129,), "x" * 129))
        self.assertFalse(_eligible(("web-baseline",), "x" * 129))

    def test_immutable_reference_does_not_change_grant(self):
        granted = ("web-baseline",)
        self.assertFalse(_eligible(granted, "WEB-BASELINE"))
        self.assertEqual(granted, ("web-baseline",))


if __name__ == "__main__":
    unittest.main()
