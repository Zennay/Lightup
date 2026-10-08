"""Offline normalization-collision diagnostics only; NEVER grant authority from these transforms.

These regressions demonstrate why identity verification must compare verified
issuer-owned opaque identifiers instead of normalized display labels.
"""
import json
import unicodedata
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_confusable_identity_cases.json"


class NormalizationCollisionDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {
            case["id"]: case
            for case in json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
        }

    def test_nfc_can_collapse_distinct_input_spellings(self):
        case = self.cases["combining_accent"]
        self.assertNotEqual(case["trusted"], case["supplied"])
        self.assertEqual(
            unicodedata.normalize("NFC", case["trusted"]),
            unicodedata.normalize("NFC", case["supplied"]),
        )

    def test_nfkc_can_collapse_fullwidth_identity(self):
        case = self.cases["fullwidth_t"]
        self.assertNotEqual(case["trusted"], case["supplied"])
        self.assertEqual(
            unicodedata.normalize("NFKC", case["trusted"]),
            unicodedata.normalize("NFKC", case["supplied"]),
        )

    def test_casefold_can_collapse_distinct_identity(self):
        case = self.cases["casefold"]
        self.assertNotEqual(case["trusted"], case["supplied"])
        self.assertEqual(case["trusted"].casefold(), case["supplied"].casefold())

    def test_trimming_can_collapse_distinct_identity(self):
        case = self.cases["trailing_space"]
        self.assertNotEqual(case["trusted"], case["supplied"])
        self.assertEqual(case["trusted"].strip(), case["supplied"].strip())

    def test_invisible_character_requires_explicit_handling(self):
        case = self.cases["zero_width"]
        self.assertNotEqual(case["trusted"], case["supplied"])
        self.assertIn("\\u200b", case["supplied"].encode("unicode_escape").decode("ascii"))
        self.assertEqual(
            case["trusted"],
            case["supplied"].replace("\u200b", ""),
        )

    def test_reference_exact_comparison_never_normalizes(self):
        for case in self.cases.values():
            with self.subTest(case=case["id"]):
                exact_match = (
                    type(case["trusted"]) is str
                    and type(case["supplied"]) is str
                    and case["trusted"] == case["supplied"]
                )
                self.assertIs(exact_match, case["expected_identity_match"])

    def test_lookup_does_not_accept_casefold_or_nfkc_alias(self):
        trusted_issuer_ids = {"tenant-a": "issuer-controlled-grant"}
        for key in ("fullwidth_t", "casefold", "zero_width", "cyrillic_a"):
            with self.subTest(case=key):
                untrusted = self.cases[key]["supplied"]
                self.assertNotIn(untrusted, trusted_issuer_ids)


if __name__ == "__main__":
    unittest.main()
