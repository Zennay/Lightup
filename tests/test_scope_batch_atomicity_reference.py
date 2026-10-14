"""Offline reference: batches must not partially grant active authority.

This is a standalone specification model, NOT the production authorization path.
No network, target calls, storage, or real capability execution.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class ProposedGrant:
    tenant: str
    asset: str
    capability: str
    approved: bool


def reference_batch(current_tenant, proposed, existing=()):
    """Return a fresh immutable set of grants or deny the whole operation."""
    if type(current_tenant) is not str or not current_tenant or len(current_tenant) > 128:
        return None
    if type(proposed) is not tuple or type(existing) is not tuple:
        return None
    if len(proposed) == 0 or len(proposed) > 128:
        return None
    result = []
    seen = set()
    for grant in proposed:
        if type(grant) is not ProposedGrant:
            return None
        if (type(grant.tenant) is not str or grant.tenant != current_tenant
                or type(grant.asset) is not str or not grant.asset
                or type(grant.capability) is not str or not grant.capability
                or type(grant.approved) is not bool or not grant.approved):
            return None
        identity = (grant.tenant, grant.asset, grant.capability)
        if identity in seen or identity in existing:
            return None
        seen.add(identity)
        result.append(identity)
    return tuple(result)


class ScopeBatchAtomicityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.ok = ProposedGrant("tenant-a", "example.invalid", "passive", True)

    def test_one_valid_grant(self):
        self.assertEqual(reference_batch("tenant-a", (self.ok,)),
                         (("tenant-a", "example.invalid", "passive"),))

    def test_late_denial_rolls_back_earlier_grant(self):
        denied = ProposedGrant("tenant-a", "other.invalid", "active", False)
        self.assertIsNone(reference_batch("tenant-a", (self.ok, denied)))

    def test_cross_tenant_late_entry_denies_entire_batch(self):
        foreign = ProposedGrant("tenant-b", "other.invalid", "passive", True)
        self.assertIsNone(reference_batch("tenant-a", (self.ok, foreign)))

    def test_duplicate_denies_entire_batch(self):
        self.assertIsNone(reference_batch("tenant-a", (self.ok, self.ok)))

    def test_existing_identity_denies_entire_batch(self):
        key = ("tenant-a", "example.invalid", "passive")
        self.assertIsNone(reference_batch("tenant-a", (self.ok,), (key,)))

    def test_non_boolean_approval_fails_closed(self):
        spoof = ProposedGrant("tenant-a", "example.invalid", "passive", 1)
        self.assertIsNone(reference_batch("tenant-a", (spoof,)))

    def test_duck_typed_grant_fails_closed(self):
        class Duck:
            tenant, asset, capability, approved = "tenant-a", "example.invalid", "passive", True
        self.assertIsNone(reference_batch("tenant-a", (Duck(),)))

    def test_mutable_batch_fails_closed(self):
        self.assertIsNone(reference_batch("tenant-a", [self.ok]))

    def test_oversized_batch_fails_closed(self):
        self.assertIsNone(reference_batch("tenant-a", (self.ok,) * 129))

    def test_inputs_remain_unchanged(self):
        data = (self.ok, ProposedGrant("tenant-a", "other.invalid", "active", False))
        before = repr(data)
        self.assertIsNone(reference_batch("tenant-a", data))
        self.assertEqual(repr(data), before)


if __name__ == "__main__":
    unittest.main()
