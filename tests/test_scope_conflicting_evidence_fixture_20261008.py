"""Fixture-lock for synthetic-only authorization evidence reference cases."""
import json
from pathlib import Path
import unittest

from test_scope_conflicting_evidence_reference_20261008 import reference_admit

FIXTURE = Path(__file__).with_name("fixtures") / "scope_conflicting_evidence_20261008.json"


class ConflictingEvidenceFixtureTests(unittest.TestCase):
    def test_fixture_is_immutable_contract_and_all_cases_match(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(type(data["base"]), dict)
        ids = [case["id"] for case in data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 12)
        self.assertTrue(any(case["admitted"] is True for case in data["cases"]))
        self.assertTrue(any(case["admitted"] is False for case in data["cases"]))
        for case in data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIs(type(case["admitted"]), bool)
                value = dict(data["base"])
                for key in case.get("drop", []):
                    value.pop(key)
                value.update(case["patch"])
                before = dict(value)
                self.assertIs(reference_admit(value), case["admitted"])
                self.assertEqual(value, before, "reference decision must not modify its input")


if __name__ == "__main__":
    unittest.main()
