"""Offline schema/identity-reference assertions; not a production gate."""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_confusable_identity_cases.json"
EXPECTED = {"ascii_exact_control", "cyrillic_a", "fullwidth_t", "zero_width",
            "casefold", "combining_accent", "trailing_space", "greek_omicron"}


class ConfusableIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_contract_metadata(self):
        self.assertEqual(self.fixture["schema_version"], 1)
        self.assertEqual(self.fixture["classification"], "offline_contract_only")
        self.assertEqual(self.fixture["default_active_dispatch"], "deny")

    def test_complete_nonduplicated_cases(self):
        ids = [case["id"] for case in self.fixture["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), EXPECTED)

    def test_immutable_byte_exact_reference_comparison(self):
        for row in self.fixture["cases"]:
            with self.subTest(case=row["id"]):
                self.assertIs(type(row["trusted"]), str)
                self.assertIs(type(row["supplied"]), str)
                self.assertIs(type(row["expected_identity_match"]), bool)
                self.assertEqual(row["trusted"] == row["supplied"], row["expected_identity_match"])

    def test_no_implicit_confusable_authorization(self):
        for row in self.fixture["cases"]:
            if row["id"] != "ascii_exact_control":
                with self.subTest(case=row["id"]):
                    self.assertFalse(row["expected_identity_match"])


if __name__ == "__main__":
    unittest.main()
