"""Offline reference checks for tenant-bound authorization replay.

These tests exercise a deliberately pure reference predicate, NOT production
authorization, issuance, async cancellation, or executor behavior.
"""
import json
from pathlib import Path
import unittest

FIXTURE = Path(__file__).parent / "fixtures" / "scope_tenant_replay_reference.json"


def eligible(case):
    """Conservative *reference* expectation; not an authority issuer."""
    return (
        type(case["run_tenant"]) is str
        and bool(case["run_tenant"])
        and type(case["grant_tenant"]) is str
        and case["run_tenant"] == case["grant_tenant"]
        and type(case["snapshot_revision"]) is int
        and type(case["live_revision"]) is int
        and case["snapshot_revision"] == case["live_revision"]
        and case["grant_active"] is True
    )


class TenantReplayReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.cases = cls.data["cases"]

    def test_schema_and_unique_ids(self):
        self.assertEqual(self.data["schema_version"], 1)
        ids = [case["id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 6)

    def test_fixture_expected_decisions(self):
        for case in self.cases:
            with self.subTest(case=case["id"]):
                self.assertIs(type(case["expect_eligible"]), bool)
                self.assertEqual(eligible(case), case["expect_eligible"])

    def test_foreign_tenant_never_eligible(self):
        for case in self.cases:
            if case["grant_tenant"] != case["run_tenant"]:
                with self.subTest(case=case["id"]):
                    self.assertFalse(eligible(case))

    def test_type_confusion_fails_closed(self):
        base = next(c for c in self.cases if c["id"] == "same_tenant_same_revision")
        for key, value in [
            ("run_tenant", None), ("run_tenant", ""), ("grant_tenant", 0),
            ("snapshot_revision", True), ("live_revision", 7.0),
            ("grant_active", 1), ("grant_active", "true"),
        ]:
            with self.subTest(field=key, value=value):
                self.assertFalse(eligible({**base, key: value}))

    def test_revision_and_revocation_fail_closed(self):
        base = next(c for c in self.cases if c["id"] == "same_tenant_same_revision")
        for change in [
            {"live_revision": 6}, {"live_revision": 8},
            {"grant_active": False}, {"grant_tenant": "tenant-b"},
        ]:
            with self.subTest(change=change):
                self.assertFalse(eligible({**base, **change}))


if __name__ == "__main__":
    unittest.main()
