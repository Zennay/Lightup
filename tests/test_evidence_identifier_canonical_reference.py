"""Offline reference contract for unambiguous evidence identifiers.

This intentionally does not implement production authorization, persistence, or
retest dispatch. Only exact ASCII canonical identifiers are accepted.
"""
import re
import unittest

_PATTERN = re.compile(r"ev-[0-9a-f]{64}", re.ASCII)


def canonical_evidence_id(value):
    if type(value) is not str:
        raise ValueError("noncanonical evidence identifier")
    if len(value) != 67 or _PATTERN.fullmatch(value) is None:
        raise ValueError("noncanonical evidence identifier")
    return value


class EvidenceIdentifierReferenceTests(unittest.TestCase):
    def test_canonical_lowercase_hash(self):
        value = "ev-" + "a0" * 32
        self.assertEqual(canonical_evidence_id(value), value)

    def test_case_alias_rejected(self):
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            canonical_evidence_id("EV-" + "a0" * 32)
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            canonical_evidence_id("ev-" + "A0" * 32)

    def test_unicode_confusables_rejected(self):
        for value in ("еv-" + "a0" * 32, "ev-" + "ａ0" * 32,
                      "ev-" + "a0" * 31 + "а0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_evidence_id(value)

    def test_whitespace_and_control_rejected(self):
        base = "ev-" + "a0" * 32
        for value in (" " + base, base + "\n", base + "\x00", base + "\u2028"):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                canonical_evidence_id(value)

    def test_truncated_and_oversized_rejected(self):
        for value in ("ev-" + "a0" * 31, "ev-" + "a0" * 33, "ev-"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_evidence_id(value)

    def test_type_confusion_rejected(self):
        class StrAlias(str):
            pass
        for value in (None, 42, b"ev-" + b"a0" * 32,
                      StrAlias("ev-" + "a0" * 32)):
            with self.subTest(type=type(value)), self.assertRaises(ValueError):
                canonical_evidence_id(value)

    def test_no_normalization_or_mutation(self):
        alias = "ev-" + "A0" * 32
        with self.assertRaises(ValueError):
            canonical_evidence_id(alias)
        self.assertEqual(alias, "ev-" + "A0" * 32)


if __name__ == "__main__":
    unittest.main()
