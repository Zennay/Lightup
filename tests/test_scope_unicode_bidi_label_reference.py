"""Offline display-label ambiguity reference; NOT a production permission gate."""
import unittest
import unicodedata

BIDI_CONTROLS = frozenset(chr(x) for x in (
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
    0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
))
MAX_LABEL = 128

def safe_display_label(value):
    """Reference-only untrusted label validator, with conservative denial."""
    if type(value) is not str or not value or len(value) > MAX_LABEL:
        return None
    if unicodedata.normalize("NFC", value) != value:
        return None
    for char in value:
        category = unicodedata.category(char)
        if char in BIDI_CONTROLS or category.startswith("C") or category in {"Zl", "Zp"}:
            return None
    return value


class UnicodeDisplayLabelBoundaryTests(unittest.TestCase):
    def test_basic_ascii_label(self):
        self.assertEqual(safe_display_label("tenant-01 / read-only"), "tenant-01 / read-only")

    def test_right_to_left_override_denied(self):
        self.assertIsNone(safe_display_label("tenant-01\u202eNIMDA"))

    def test_isolate_and_pop_denied(self):
        for char in ("\u2066", "\u2067", "\u2068", "\u2069"):
            with self.subTest(char=ord(char)):
                self.assertIsNone(safe_display_label("safe" + char + "owner"))

    def test_left_right_marks_denied(self):
        for char in ("\u200e", "\u200f", "\u061c"):
            with self.subTest(char=ord(char)):
                self.assertIsNone(safe_display_label("a" + char + "b"))

    def test_line_and_paragraph_separators_denied(self):
        for char in ("\u2028", "\u2029", "\n", "\r", "\t", "\x00"):
            with self.subTest(char=ord(char)):
                self.assertIsNone(safe_display_label("tenant" + char + "allow"))

    def test_nfc_canonical_only(self):
        self.assertIsNone(safe_display_label("Cafe\u0301"))
        self.assertEqual(safe_display_label("Caf\u00e9"), "Caf\u00e9")

    def test_reject_boolean_number_and_subclass(self):
        class Label(str):
            pass
        for item in (True, 7, None, b"tenant", Label("tenant")):
            with self.subTest(item=repr(item)):
                self.assertIsNone(safe_display_label(item))

    def test_empty_and_oversized_denied(self):
        self.assertIsNone(safe_display_label(""))
        self.assertIsNone(safe_display_label("x" * (MAX_LABEL + 1)))
        self.assertEqual(safe_display_label("x" * MAX_LABEL), "x" * MAX_LABEL)

    def test_input_remains_unchanged(self):
        value = "safe\u202eevil"
        before = value
        self.assertIsNone(safe_display_label(value))
        self.assertEqual(value, before)

    def test_visible_unicode_not_implicitly_authority(self):
        self.assertEqual(safe_display_label("client-\u03b1"), "client-\u03b1")


if __name__ == "__main__":
    unittest.main()
