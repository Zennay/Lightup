"""Offline contract checks for scope-authorization incident containment.

No network, target, database, executor or authorization grant access.
"""
import json
from pathlib import Path
import unittest

FIXTURE = Path(__file__).resolve().parents[1] / "docs" / "fixtures" / "scope-authorization-incident-tabletop.json"
EXPECTED_IDS = {
    "revoked-before-dispatch",
    "narrowed-after-approval",
    "expired-during-run",
    "resolver-audit-outage",
    "cross-tenant-stale-run",
    "cancellation-ack-only",
}
REQUIRED_FIELDS = {
    "incident_id", "observed_at_utc", "tenant_id", "engagement_id",
    "run_id", "grant_id", "expected_version", "observed_version",
    "revoked_or_narrowed_dimensions", "queued_child_ids",
    "inflight_child_ids", "stop_requested_at", "stop_acknowledged_at",
    "terminal_state_by_child", "audit_receipt_refs", "reviewer_id",
    "review_at_utc", "closure_decision",
}


class IncidentTabletopFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_version_and_offline_non_authority(self):
        self.assertIs(type(self.data.get("schema_version")), int)
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["purpose"], "offline_tabletop_only")
        self.assertIs(self.data["non_authority"], True)

    def test_default_is_open(self):
        self.assertEqual(self.data["default_containment"], "open")

    def test_closure_fields_are_complete_and_distinct(self):
        fields = self.data["required_closure_fields"]
        self.assertIs(type(fields), list)
        self.assertTrue(all(type(item) is str and item for item in fields))
        self.assertEqual(len(fields), len(set(fields)))
        self.assertEqual(set(fields), REQUIRED_FIELDS)

    def test_scenarios_have_stable_unique_ids(self):
        scenarios = self.data["scenarios"]
        self.assertIs(type(scenarios), list)
        self.assertEqual({s["id"] for s in scenarios}, EXPECTED_IDS)
        self.assertEqual(len(scenarios), len(EXPECTED_IDS))

    def test_expectations_are_nonempty_unique_typed_strings(self):
        for scenario in self.data["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(set(scenario), {"id", "expected"})
                self.assertIs(type(scenario["id"]), str)
                expectations = scenario["expected"]
                self.assertIs(type(expectations), list)
                self.assertTrue(expectations)
                self.assertTrue(all(type(v) is str and v for v in expectations))
                self.assertEqual(len(expectations), len(set(expectations)))

    def test_cancellation_ack_never_implies_closure(self):
        scenarios = {s["id"]: set(s["expected"]) for s in self.data["scenarios"]}
        self.assertIn("closure_denied", scenarios["cancellation-ack-only"])
        self.assertIn("terminal_state_unproven", scenarios["cancellation-ack-only"])
        self.assertIn("child_terminal_state_verified", scenarios["expired-during-run"])

    def test_revocation_denies_dispatch_and_retry(self):
        scenarios = {s["id"]: set(s["expected"]) for s in self.data["scenarios"]}
        self.assertGreaterEqual(
            scenarios["revoked-before-dispatch"],
            {"dispatch_denied", "retry_denied"},
        )

    def test_narrowing_cannot_resume_implicitly(self):
        scenarios = {s["id"]: set(s["expected"]) for s in self.data["scenarios"]}
        self.assertGreaterEqual(
            scenarios["narrowed-after-approval"],
            {"excluded_authority_denied", "resumption_requires_review"},
        )

    def test_expiry_denies_continuation_and_retry(self):
        scenarios = {s["id"]: set(s["expected"]) for s in self.data["scenarios"]}
        self.assertGreaterEqual(
            scenarios["expired-during-run"],
            {"next_step_denied", "retry_denied", "child_terminal_state_verified"},
        )

    def test_fixture_has_no_unreviewed_keys(self):
        self.assertEqual(
            set(self.data),
            {"schema_version", "purpose", "default_containment",
             "required_closure_fields", "scenarios", "non_authority"},
        )

    def test_outage_and_cross_tenant_fail_closed(self):
        scenarios = {s["id"]: set(s["expected"]) for s in self.data["scenarios"]}
        self.assertGreaterEqual(
            scenarios["resolver-audit-outage"], {"dispatch_denied", "closure_denied"}
        )
        self.assertGreaterEqual(
            scenarios["cross-tenant-stale-run"],
            {"foreign_grant_denied", "foreign_receipt_denied"},
        )


if __name__ == "__main__":
    unittest.main()
