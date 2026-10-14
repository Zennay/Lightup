"""Offline reference only: a risk change cannot reuse an earlier approval.

This model is intentionally NOT wired to production authorization or dispatch.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Snapshot:
    tenant: str
    request_id: str
    revision: int
    risk: int
    approved_max_risk: int
    approved_revision: int
    active: bool


def eligible(snapshot: Snapshot, requested_risk: int, live: Snapshot) -> bool:
    """Conservative illustrative gate, not an issuance or security decision."""
    if type(snapshot) is not Snapshot or type(live) is not Snapshot:
        return False
    for item in (snapshot, live):
        if (type(item.tenant) is not str or not item.tenant
                or type(item.request_id) is not str or not item.request_id
                or type(item.revision) is not int or item.revision < 0
                or type(item.risk) is not int or not 0 <= item.risk <= 5
                or type(item.approved_max_risk) is not int
                or not 0 <= item.approved_max_risk <= 5
                or type(item.approved_revision) is not int
                or type(item.active) is not bool):
            return False
    if type(requested_risk) is not int or not 0 <= requested_risk <= 5:
        return False
    return (
        snapshot.active and live.active
        and snapshot.tenant == live.tenant
        and snapshot.request_id == live.request_id
        and snapshot.revision == live.revision
        and snapshot.approved_revision == snapshot.revision
        and live.approved_revision == live.revision
        and snapshot.risk == live.risk == requested_risk
        and requested_risk <= snapshot.approved_max_risk
        and requested_risk <= live.approved_max_risk
        and live.approved_max_risk <= snapshot.approved_max_risk
    )


class RiskChangeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.approved = Snapshot("tenant-a", "req-a", 3, 2, 2, 3, True)

    def test_unchanged_reference_is_conditionally_eligible(self):
        self.assertTrue(eligible(self.approved, 2, self.approved))

    def test_risk_escalation_denied_even_if_new_live_grant_wider(self):
        live = Snapshot("tenant-a", "req-a", 3, 3, 3, 3, True)
        self.assertFalse(eligible(self.approved, 3, live))

    def test_risk_downgrade_requires_new_approval_revision(self):
        live = Snapshot("tenant-a", "req-a", 4, 1, 2, 3, True)
        self.assertFalse(eligible(self.approved, 1, live))

    def test_revision_change_denied_even_with_same_risk(self):
        live = Snapshot("tenant-a", "req-a", 4, 2, 2, 4, True)
        self.assertFalse(eligible(self.approved, 2, live))

    def test_live_cap_narrowing_denies_previous_risk(self):
        live = Snapshot("tenant-a", "req-a", 3, 2, 1, 3, True)
        self.assertFalse(eligible(self.approved, 2, live))

    def test_tenant_and_request_identity_cannot_change(self):
        for live in (
            Snapshot("tenant-b", "req-a", 3, 2, 2, 3, True),
            Snapshot("tenant-a", "req-b", 3, 2, 2, 3, True),
        ):
            with self.subTest(live=live):
                self.assertFalse(eligible(self.approved, 2, live))

    def test_revoked_or_unapproved_denied(self):
        self.assertFalse(eligible(self.approved, 2, Snapshot("tenant-a", "req-a", 3, 2, 2, 3, False)))
        self.assertFalse(eligible(self.approved, 2, Snapshot("tenant-a", "req-a", 3, 2, 2, 2, True)))

    def test_type_confusion_rejected(self):
        for risk in (True, 2.0, "2", -1, 6):
            with self.subTest(risk=risk):
                self.assertFalse(eligible(self.approved, risk, self.approved))
        self.assertFalse(eligible(self.approved, 2, Snapshot("tenant-a", "req-a", True, 2, 2, 3, True)))
        self.assertFalse(eligible(self.approved, 2, Snapshot("tenant-a", "req-a", 3, 2, True, 3, True)))

    def test_snapshot_is_not_modified(self):
        prior = repr(self.approved)
        eligible(self.approved, 3, Snapshot("tenant-a", "req-a", 4, 3, 3, 4, True))
        self.assertEqual(repr(self.approved), prior)


if __name__ == "__main__":
    unittest.main()
