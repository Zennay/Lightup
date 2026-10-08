"""Adversarial JSON fixture shape tests; never claims runtime protection."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_scope_denial_audit_fixture_20261008 import validate


class DenialAuditFixtureAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good = json.loads((ROOT / "tests" / "fixtures" / "scope_denial_audit_privacy_20261008.json").read_text())

    def bad(self, mutate):
        obj = copy.deepcopy(self.good)
        mutate(obj)
        with self.assertRaises(ValueError):
            validate(json.dumps(obj))

    def test_positive_fixture(self):
        self.assertTrue(validate(json.dumps(self.good)))

    def test_duplicate_json_key_rejected(self):
        raw = json.dumps(self.good)
        with self.assertRaises(ValueError):
            validate(raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1))

    def test_boolean_schema_version_rejected(self):
        self.bad(lambda d: d.update(schema_version=True))

    def test_release_authorization_never_true(self):
        self.bad(lambda d: d.update(release_authorizing=True))

    def test_extra_top_level_field_rejected(self):
        self.bad(lambda d: d.update(secret="surprise"))

    def test_duplicate_case_id_rejected(self):
        self.bad(lambda d: d["cases"][1].update(id="AUD-01"))

    def test_mismatched_case_condition_rejected(self):
        self.bad(lambda d: d["cases"][0].update(condition="revoked_grant"))

    def test_allow_decision_rejected(self):
        self.bad(lambda d: d["cases"][0].update(expected_decision="ALLOW"))

    def test_sensitive_emission_rejected(self):
        self.bad(lambda d: d["cases"][0].update(raw_sensitive_data_emitted=True))

    def test_extra_case_field_rejected(self):
        self.bad(lambda d: d["cases"][0].update(raw_url="https://example.invalid/?token=secret"))

    def test_missing_forbidden_field_rejected(self):
        self.bad(lambda d: d["forbidden_event_fields"].remove("access_token"))

    def test_duplicate_required_field_rejected(self):
        self.bad(lambda d: d["required_event_fields"].append("event_id"))


if __name__ == "__main__":
    unittest.main()
