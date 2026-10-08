"""Offline reference for safe human-facing remediation attachment display names.

Not production evidence storage, authorization, or path handling.
"""
import re
import unittest
import unicodedata


def safe_attachment_label(value):
    """Return a constrained display label; fail closed on ambiguous input."""
    if type(value) is not str or not 1 <= len(value) <= 120:
        raise ValueError("invalid attachment label")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("noncanonical Unicode")
    if value in {".", ".."} or value.startswith((".", " ", "-")):
        raise ValueError("ambiguous name")
    if value.endswith((" ", ".")):
        raise ValueError("ambiguous suffix")
    if "/" in value or "\\\\" in value or ":" in value or "%" in value:
        raise ValueError("path or encoding token")
    if any(unicodedata.category(char)[0] == "C" for char in value):
        raise ValueError("control or format character")
    if any(char in "<>\\"|?*" for char in value):
        raise ValueError("filesystem metacharacter")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]*", value, flags=re.ASCII):
        raise ValueError("nonportable label")
    stem = value.split(".")[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)[1-9]", stem):
        raise ValueError("reserved platform name")
    return value


class AttachmentNameReferenceTests(unittest.TestCase):
    def test_positive(self):
        for name in ("evidence-001.json", "retest screenshot 2.png", "finding_42.txt"):
            with self.subTest(name=name):
                self.assertEqual(safe_attachment_label(name), name)

    def test_traversal_and_separators(self):
        for name in ("../x", "sub/file", r"sub\\file", "..", ".", "C:secret"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_attachment_label(name)

    def test_encoded_path_ambiguity(self):
        for name in ("%2e%2e", "evidence%2fsecret", "a%5cb"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_attachment_label(name)

    def test_control_and_format(self):
        for name in ("evidence\n.txt", "a\x00b", "a\u202eb", "a\u200db"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_attachment_label(name)

    def test_unicode_normalization(self):
        for name in ("cafe\u0301.txt", "\uff0e\uff0e", "\u0131.txt"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_attachment_label(name)

    def test_windows_reserved(self):
        for name in ("CON", "nul.txt", "COM1.log", "LPT9.csv"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_attachment_label(name)

    def test_ambiguous_suffix_and_prefix(self):
        for name in (" file", "-file", ".hidden", "file.", "file "):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_attachment_label(name)

    def test_type_bounds_and_no_coercion(self):
        for value in (None, 1, b"file", True, "", "a" * 121):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    safe_attachment_label(value)

    def test_immutability(self):
        value = "retest-artifact.json"
        before = value
        self.assertEqual(safe_attachment_label(value), before)
        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
