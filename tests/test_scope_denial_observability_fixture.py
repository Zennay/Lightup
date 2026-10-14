"""Offline integrity checks for proposed denial observability acceptance cases.

These checks validate a non-authoritative fixture only. They do not exercise
production authorization, storage, networking, or any target-capable adapter.
"""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_denial_observability_cases.json"
REQUIRED = {
    "foreign_tenant", "revoked_grant", "expired_grant", "future_grant",
    "narrowed_grant", "invalid_capability", "invalid_risk",
    "mandatory_audit_failure", "secret_exception", "replayed_denial",
    "denial_flood", "authorized_request",
}
KEYS = {"id", "boundary", "decision", "external", "dispatch", "raw_input_logged"}


class DenialObservabilityFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_is_explicitly_non_authoritative(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertIs(self.data["authoritative"], False)

    def test_cases_are_unique_and_complete(self):
        ids = [case["id"] for case in self.data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), REQUIRED)

    def test_schema_has_no_unbounded_input_fields(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(set(case), KEYS)
                self.assertIn(case["boundary"], {"tenant", "grant", "capability", "risk", "audit", "telemetry"})

    def test_no_case_grants_dispatch(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIs(case["dispatch"], False)
                self.assertIs(case["raw_input_logged"], False)

    def test_denied_cases_have_generic_external_response(self):
        for case in self.data["cases"]:
            if case["decision"] == "deny":
                with self.subTest(case=case["id"]):
                    self.assertEqual(case["external"], "generic")

    def test_decisions_and_external_channels_are_closed_vocabularies(self):
        allowed_decisions = {"deny", "bounded", "no_authority_change", "cannot_grant"}
        allowed_externals = {"generic", "none"}
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIs(type(case["id"]), str)
                self.assertIs(type(case["boundary"]), str)
                self.assertIs(type(case["decision"]), str)
                self.assertIs(type(case["external"]), str)
                self.assertIn(case["decision"], allowed_decisions)
                self.assertIn(case["external"], allowed_externals)
                self.assertIs(type(case["dispatch"]), bool)
                self.assertIs(type(case["raw_input_logged"]), bool)

    def test_denial_outcome_cannot_masquerade_as_non_denial(self):
        exceptional = {"denial_flood": "bounded",
                       "replayed_denial": "no_authority_change",
                       "authorized_request": "cannot_grant"}
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["decision"], exceptional.get(case["id"], "deny"))

    def test_replay_and_authorized_cases_cannot_derive_authority(self):
        by_id = {case["id"]: case for case in self.data["cases"]}
        self.assertEqual(by_id["replayed_denial"]["decision"], "no_authority_change")
        self.assertEqual(by_id["authorized_request"]["decision"], "cannot_grant")


if __name__ == "__main__":
    unittest.main()
