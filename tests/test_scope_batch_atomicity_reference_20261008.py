"""Offline reference contract: a batch cannot inherit partial scope approval.

This file intentionally contains no LightUp production imports or target I/O.
It does NOT prove production executor behaviour; integration belongs to its owner.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    tenant: str
    engagement: str
    asset: str
    capability: str
    risk: int


@dataclass(frozen=True)
class Grant:
    tenant: str
    engagement: str
    assets: tuple[str, ...]
    capabilities: tuple[str, ...]
    max_risk: int
    active: bool


def reference_batch_eligible(items: object, grant: object) -> bool:
    """Pure *eligibility* predicate, not permission to dispatch."""
    if type(items) is not tuple or not items or type(grant) is not Grant:
        return False
    if (type(grant.tenant) is not str or type(grant.engagement) is not str
            or type(grant.assets) is not tuple
            or type(grant.capabilities) is not tuple
            or type(grant.max_risk) is not int or type(grant.active) is not bool
            or not grant.active or grant.max_risk < 0):
        return False
    if any(type(v) is not str for v in grant.assets + grant.capabilities):
        return False
    for item in items:
        if type(item) is not Item:
            return False
        if (type(item.tenant) is not str or type(item.engagement) is not str
                or type(item.asset) is not str or type(item.capability) is not str
                or type(item.risk) is not int or item.risk < 0):
            return False
        if not (item.tenant == grant.tenant and item.engagement == grant.engagement
                and item.asset in grant.assets
                and item.capability in grant.capabilities
                and item.risk <= grant.max_risk):
            return False
    return True


class BatchAtomicityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-a", "eng-1", ("asset-a",), ("read",), 2, True)
        self.good = Item("tenant-a", "eng-1", "asset-a", "read", 1)

    def test_single_authorized_item_eligible_only(self):
        self.assertTrue(reference_batch_eligible((self.good,), self.grant))

    def test_mixed_out_of_scope_asset_denies_whole_batch(self):
        bad = Item("tenant-a", "eng-1", "asset-b", "read", 1)
        self.assertFalse(reference_batch_eligible((self.good, bad), self.grant))
        self.assertFalse(reference_batch_eligible((bad, self.good), self.grant))

    def test_cross_tenant_or_engagement_denies_whole_batch(self):
        for bad in (Item("tenant-b", "eng-1", "asset-a", "read", 1),
                    Item("tenant-a", "eng-2", "asset-a", "read", 1)):
            with self.subTest(bad=bad):
                self.assertFalse(reference_batch_eligible((self.good, bad), self.grant))

    def test_capability_and_risk_escalation_deny_whole_batch(self):
        for bad in (Item("tenant-a", "eng-1", "asset-a", "write", 1),
                    Item("tenant-a", "eng-1", "asset-a", "read", 3)):
            with self.subTest(bad=bad):
                self.assertFalse(reference_batch_eligible((self.good, bad), self.grant))

    def test_empty_or_mutable_batch_not_eligible(self):
        self.assertFalse(reference_batch_eligible((), self.grant))
        self.assertFalse(reference_batch_eligible([self.good], self.grant))

    def test_untrusted_item_type_and_risk_denied(self):
        self.assertFalse(reference_batch_eligible((self.good, object()), self.grant))
        self.assertFalse(reference_batch_eligible(
            (Item("tenant-a", "eng-1", "asset-a", "read", True),), self.grant))

    def test_inactive_or_malformed_grant_denied(self):
        self.assertFalse(reference_batch_eligible((self.good,),
            Grant("tenant-a", "eng-1", ("asset-a",), ("read",), 2, False)))
        self.assertFalse(reference_batch_eligible((self.good,),
            Grant("tenant-a", "eng-1", ["asset-a"], ("read",), 2, True)))
        self.assertFalse(reference_batch_eligible((self.good,),
            Grant("tenant-a", "eng-1", ("asset-a",), ("read",), True, True)))

    def test_input_objects_remain_unchanged(self):
        items = (self.good, Item("tenant-a", "eng-1", "asset-b", "read", 1))
        before_items, before_grant = repr(items), repr(self.grant)
        self.assertFalse(reference_batch_eligible(items, self.grant))
        self.assertEqual(repr(items), before_items)
        self.assertEqual(repr(self.grant), before_grant)


if __name__ == "__main__":
    unittest.main()
