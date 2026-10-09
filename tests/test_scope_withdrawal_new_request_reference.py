"""Offline reference: withdrawal cannot be bypassed by a new request identifier.

This is NOT authorization or a production implementation. It models an
issuer-owned consent epoch that a production source owner must authenticate.
No network, target, scanner or capability is invoked.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class IssuedConsent:
    tenant: str
    asset: str
    epoch: int
    active: bool


@dataclass(frozen=True)
class RequestSnapshot:
    tenant: str
    asset: str
    consent_epoch: int
    request_id: str


def _identity(value):
    return type(value) is str and 0 < len(value) <= 128 and value.isascii() and all(
        character.isalnum() or character in "-._" for character in value
    )


def conditionally_eligible(snapshot, current):
    """Necessary consistency check only; caller must verify trusted provenance."""
    if type(snapshot) is not RequestSnapshot or type(current) is not IssuedConsent:
        return False
    if not all(_identity(x) for x in (
        snapshot.tenant, snapshot.asset, snapshot.request_id,
        current.tenant, current.asset,
    )):
        return False
    if type(current.active) is not bool or current.active is not True:
        return False
    if type(snapshot.consent_epoch) is not int or type(current.epoch) is not int:
        return False
    if not (1 <= snapshot.consent_epoch < 2**63 and 1 <= current.epoch < 2**63):
        return False
    return (
        snapshot.tenant == current.tenant
        and snapshot.asset == current.asset
        and snapshot.consent_epoch == current.epoch
    )


class WithdrawalNewRequestBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = RequestSnapshot("tenant-A", "asset-1", 7, "request-original")
        self.issuer = IssuedConsent("tenant-A", "asset-1", 7, True)

    def test_matching_fixture_is_only_conditionally_eligible(self):
        self.assertTrue(conditionally_eligible(self.snapshot, self.issuer))

    def test_withdrawal_dominates_renamed_request(self):
        renamed = RequestSnapshot("tenant-A", "asset-1", 7, "request-new")
        self.assertFalse(conditionally_eligible(renamed, IssuedConsent("tenant-A", "asset-1", 7, False)))

    def test_reissued_consent_does_not_resurrect_old_snapshot(self):
        self.assertFalse(conditionally_eligible(self.snapshot, IssuedConsent("tenant-A", "asset-1", 8, True)))

    def test_new_epoch_new_request_requires_matching_epoch(self):
        new = RequestSnapshot("tenant-A", "asset-1", 8, "request-new")
        self.assertTrue(conditionally_eligible(new, IssuedConsent("tenant-A", "asset-1", 8, True)))
        self.assertFalse(conditionally_eligible(new, self.issuer))

    def test_request_id_never_overrides_tenant_or_asset(self):
        self.assertFalse(conditionally_eligible(
            RequestSnapshot("tenant-B", "asset-1", 7, "request-new"), self.issuer))
        self.assertFalse(conditionally_eligible(
            RequestSnapshot("tenant-A", "asset-2", 7, "request-new"), self.issuer))

    def test_truthy_active_flag_denied(self):
        for active in (1, "yes", [], None):
            with self.subTest(active=active):
                self.assertFalse(conditionally_eligible(
                    self.snapshot, IssuedConsent("tenant-A", "asset-1", 7, active)))

    def test_revision_type_confusion_denied(self):
        for epoch in (True, 7.0, "7", None, -1, 0, 2**63):
            with self.subTest(epoch=epoch):
                self.assertFalse(conditionally_eligible(
                    RequestSnapshot("tenant-A", "asset-1", epoch, "request-new"), self.issuer))
                self.assertFalse(conditionally_eligible(
                    self.snapshot, IssuedConsent("tenant-A", "asset-1", epoch, True)))

    def test_ambiguous_identifiers_denied(self):
        for value in ("", "asset/1", " asset-1", "asset-1\\n", "á", "x" * 129):
            with self.subTest(value=value):
                self.assertFalse(conditionally_eligible(
                    RequestSnapshot("tenant-A", value, 7, "request-new"), self.issuer))

    def test_duck_types_and_subclasses_denied(self):
        class ForgedSnapshot(RequestSnapshot):
            pass
        class ForgedConsent(IssuedConsent):
            pass
        self.assertFalse(conditionally_eligible(ForgedSnapshot("tenant-A", "asset-1", 7, "new"), self.issuer))
        self.assertFalse(conditionally_eligible(self.snapshot, ForgedConsent("tenant-A", "asset-1", 7, True)))

    def test_new_request_does_not_reset_epoch_with_same_identifier(self):
        # The old identifier can be recycled; it must not restore a stale epoch.
        recycled = RequestSnapshot("tenant-A", "asset-1", 7, "request-original")
        self.assertFalse(conditionally_eligible(
            recycled, IssuedConsent("tenant-A", "asset-1", 8, True)))

    def test_current_issuer_identity_must_be_canonical(self):
        for value in (" tenant-A", "tenant-A\\n", "tenant/A", "é", "x" * 129, 7):
            with self.subTest(value=value):
                self.assertFalse(conditionally_eligible(
                    self.snapshot, IssuedConsent(value, "asset-1", 7, True)))

    def test_request_identity_must_be_canonical(self):
        for value in ("", " request-new", "request/new", "request-new\\n", "é", 2):
            with self.subTest(value=value):
                self.assertFalse(conditionally_eligible(
                    RequestSnapshot("tenant-A", "asset-1", 7, value), self.issuer))

    def test_inputs_remain_unchanged(self):
        before = (repr(self.snapshot), repr(self.issuer))
        conditionally_eligible(self.snapshot, self.issuer)
        self.assertEqual(before, (repr(self.snapshot), repr(self.issuer)))


if __name__ == "__main__":
    unittest.main()
