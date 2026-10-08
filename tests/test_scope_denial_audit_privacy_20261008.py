"""Offline *contract fixture* checks, not production authorization tests."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "scope_denial_audit_privacy_20261008.json"
CONTRACT = ROOT / "docs" / "scope-denial-audit-privacy-20261008.md"


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class DenialAuditPrivacyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
        cls.contract = CONTRACT.read_text(encoding="utf-8")

    def test_explicitly_non_authorizing(self):
        self.assertIs(self.data["release_authorizing"], False)
        self.assertEqual(self.data["scope"], "offline-denial-audit-privacy")

    def test_unique_eight_cases(self):
        cases = self.data["cases"]
        self.assertEqual(len(cases), 8)
        self.assertEqual({c["id"] for c in cases}, {f"AUD-{n:02d}" for n in range(1, 9)})

    def test_every_case_denies_without_sensitive_disclosure(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["expected_decision"], "DENY")
                self.assertIs(case["raw_sensitive_data_emitted"], False)
                self.assertIn(case["id"], self.contract)

    def test_bounded_schema_and_forbidden_inputs(self):
        required = set(self.data["required_event_fields"])
        forbidden = set(self.data["forbidden_event_fields"])
        self.assertEqual(len(required), len(self.data["required_event_fields"]))
        self.assertEqual(len(forbidden), len(self.data["forbidden_event_fields"]))
        self.assertFalse(required & forbidden)
        self.assertTrue({"tenant_correlation_id", "reason_code", "policy_version"} <= required)
        self.assertTrue({"authorization", "cookie", "access_token", "url", "target"} <= forbidden)

    def test_contract_contains_non_runtime_caveat(self):
        self.assertIn("not evidence of runtime enforcement", self.contract)
        self.assertIn("No real-target interaction is authorized", self.contract)


if __name__ == "__main__":
    unittest.main()
