"""Mutation-resistant schema checks for non-executable scope-review fixture.

These checks validate review-data integrity only; they do not prove production gates.
"""
import copy
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "docs/fixtures/scope-authorization-offline-review-v1.json"
SAFE_DEFAULTS = {"mode": "ANALYSIS_ONLY", "network_access": False, "active_execution": False, "external_targets": False}
ALLOWED_MEMBERSHIP = {"explicit", "absent", "excluded"}
ALLOWED_GRANTS = {
    "missing", "expired", "future", "otherwise-valid", "revoked",
    "foreign-tenant", "widened-after-issuance", "valid-no-operator-approval", "none",
}
EXPECTED_IDS = {
    "absent-grant", "expired-grant", "not-yet-valid", "undeclared-asset",
    "excluded-asset", "revoked-grant", "different-tenant",
    "changed-asset-snapshot", "missing-admin-approval", "analysis-only",
}

def review_schema_valid(document):
    if type(document) is not dict or set(document) != {"schema_version", "purpose", "defaults", "cases"}:
        return False
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        return False
    if type(document["purpose"]) is not str or not document["purpose"]:
        return False
    defaults = document["defaults"]
    if type(defaults) is not dict or defaults != SAFE_DEFAULTS:
        return False
    if any(type(defaults[k]) is not type(v) for k, v in SAFE_DEFAULTS.items()):
        return False
    cases = document["cases"]
    if type(cases) is not list or len(cases) != len(EXPECTED_IDS):
        return False
    by_id = {}
    for case in cases:
        if type(case) is not dict or set(case) != {"id", "asset", "membership", "grant", "expected", "reason"}:
            return False
        if any(type(case[k]) is not str or not case[k] for k in case):
            return False
        if case["id"] in by_id or case["membership"] not in ALLOWED_MEMBERSHIP or case["grant"] not in ALLOWED_GRANTS:
            return False
        if not case["asset"].endswith(".example.invalid"):
            return False
        by_id[case["id"]] = case
    if set(by_id) != EXPECTED_IDS:
        return False
    return all(
        case["expected"] == ("ALLOW_ANALYSIS_ONLY" if name == "analysis-only" else "DENY")
        for name, case in by_id.items()
    )

class ReviewSchemaMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_checked_in_fixture(self):
        self.assertTrue(review_schema_valid(self.fixture))

    def test_privilege_widening_mutations_fail(self):
        for key, value in (
            ("network_access", True),
            ("active_execution", True),
            ("external_targets", True),
            ("mode", "ACTIVE"),
            ("network_access", 0),
        ):
            mutated = copy.deepcopy(self.fixture)
            mutated["defaults"][key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(review_schema_valid(mutated))

    def test_cases_cannot_be_added_removed_or_flipped(self):
        for mutation in ("extra_case", "drop_case", "allow_execution", "duplicate_case"):
            mutated = copy.deepcopy(self.fixture)
            if mutation == "extra_case":
                case = dict(mutated["cases"][0], id="new-case")
                mutated["cases"].append(case)
            elif mutation == "drop_case":
                mutated["cases"].pop()
            elif mutation == "allow_execution":
                mutated["cases"][0]["expected"] = "ALLOW_ACTIVE"
            else:
                mutated["cases"][-1] = dict(mutated["cases"][0])
            with self.subTest(mutation=mutation):
                self.assertFalse(review_schema_valid(mutated))

if __name__ == "__main__":
    unittest.main()
