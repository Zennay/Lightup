"""Reference-only approval envelope boundary checks (not production proof)."""
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from test_scope_human_approval_reference_model import (
    ApprovalEnvelope, Candidate, reference_decision
)

NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


class ApprovalEnvelopeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = ApprovalEnvelope(
            tenant="tenant-a", revision="r1", reviewer="reviewer",
            issuer_lineage="trusted-grant-1", assets=frozenset({"lab.test"}),
            capabilities=frozenset({"header-check"}), max_risk=2,
            valid_from=NOW - timedelta(hours=1),
            valid_until=NOW + timedelta(hours=1), active=True
        )
        self.candidate = Candidate("tenant-a", "r1", "lab.test", "header-check", 1, "active")

    def test_narrow_exact_case_is_only_conditionally_eligible(self):
        self.assertTrue(reference_decision(self.candidate, self.grant, NOW))

    def test_changes_denied(self):
        variants = [
            replace(self.candidate, tenant="tenant-b"),
            replace(self.candidate, revision="r2"),
            replace(self.candidate, asset="other.test"),
            replace(self.candidate, capability="network-scan"),
            replace(self.candidate, risk=3),
            replace(self.candidate, mode="analysis"),
            replace(self.candidate, risk=True),
            replace(self.candidate, risk=-1),
            replace(self.candidate, mode=1),
            replace(self.candidate, mode="ACTIVE"),
        ]
        for candidate in variants:
            with self.subTest(candidate=candidate):
                self.assertFalse(reference_decision(candidate, self.grant, NOW))

    def test_revocation_and_missing_provenance_denied(self):
        variants = [
            None, replace(self.grant, active=False),
            replace(self.grant, reviewer=" "),
            replace(self.grant, issuer_lineage=""),
            replace(self.grant, tenant="tenant-b"),
            replace(self.grant, assets=frozenset()),
            replace(self.grant, capabilities=frozenset()),
        ]
        for grant in variants:
            with self.subTest(grant=grant):
                self.assertFalse(reference_decision(self.candidate, grant, NOW))

    def test_interval_is_half_open_and_requires_timezone(self):
        self.assertFalse(reference_decision(self.candidate, self.grant, self.grant.valid_until))
        self.assertTrue(reference_decision(self.candidate, self.grant, self.grant.valid_from))
        self.assertFalse(reference_decision(self.candidate, self.grant, NOW.replace(tzinfo=None)))
        self.assertFalse(reference_decision(self.candidate, replace(
            self.grant, valid_from=NOW.replace(tzinfo=None)), NOW))

    def test_malformed_grants_deny(self):
        for grant in (
            replace(self.grant, max_risk=True),
            replace(self.grant, max_risk=-1),
            replace(self.grant, max_risk="2"),
            replace(self.grant, assets={"lab.test"}),
            replace(self.grant, capabilities={"header-check"}),
            replace(self.grant, valid_until=self.grant.valid_from),
        ):
            with self.subTest(grant=grant):
                self.assertFalse(reference_decision(self.candidate, grant, NOW))

if __name__ == "__main__":
    unittest.main()
