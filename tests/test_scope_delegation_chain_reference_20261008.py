"""Offline delegation-chain rejection reference; NOT a production authorization gate."""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    grant_id: str
    tenant: str
    parent_id: str | None
    capabilities: frozenset[str]
    assets: frozenset[str]
    risk: int
    active: bool


def conditionally_eligible(grants, leaf_id, tenant, asset, capability, risk):
    """Demonstrate narrowing only; trusted issuance/live revocation are NOT proven."""
    if type(leaf_id) is not str or type(tenant) is not str:
        return False
    if type(asset) is not str or type(capability) is not str or type(risk) is not int:
        return False
    if risk < 0 or len(grants) > 32:
        return False
    seen = set()
    current = leaf_id
    child = None
    for _ in range(33):
        if type(current) is not str or not current or current in seen:
            return False
        seen.add(current)
        grant = grants.get(current)
        if type(grant) is not Grant or grant.grant_id != current:
            return False
        if type(grant.tenant) is not str or grant.tenant != tenant or grant.active is not True:
            return False
        if type(grant.capabilities) is not frozenset or type(grant.assets) is not frozenset:
            return False
        if any(type(x) is not str for x in grant.capabilities | grant.assets):
            return False
        if type(grant.risk) is not int or grant.risk < 0:
            return False
        if asset not in grant.assets or capability not in grant.capabilities or risk > grant.risk:
            return False
        if child is not None:
            if not child.assets <= grant.assets or not child.capabilities <= grant.capabilities:
                return False
            if child.risk > grant.risk:
                return False
        if grant.parent_id is None:
            return True
        if type(grant.parent_id) is not str:
            return False
        child, current = grant, grant.parent_id
    return False


class DelegationChainReferenceTests(unittest.TestCase):
    def setUp(self):
        self.root = Grant("root", "tenant-a", None, frozenset({"read", "scan"}), frozenset({"lab-a", "lab-b"}), 3, True)
        self.child = Grant("child", "tenant-a", "root", frozenset({"read"}), frozenset({"lab-a"}), 1, True)
        self.grants = {"root": self.root, "child": self.child}

    def eligible(self, grants=None, **overrides):
        values = dict(leaf_id="child", tenant="tenant-a", asset="lab-a", capability="read", risk=1)
        values.update(overrides)
        return conditionally_eligible(self.grants if grants is None else grants, **values)

    def test_unchanged_narrowing_is_conditionally_eligible(self):
        self.assertTrue(self.eligible())

    def test_cycle_and_missing_ancestor_fail_closed(self):
        self.assertFalse(self.eligible({"root": self.root, "child": Grant("child", "tenant-a", "child", self.child.capabilities, self.child.assets, 1, True)}))
        self.assertFalse(self.eligible({"child": self.child}))

    def test_cross_tenant_parent_denied(self):
        foreign = Grant("root", "tenant-b", None, self.root.capabilities, self.root.assets, 3, True)
        self.assertFalse(self.eligible({"root": foreign, "child": self.child}))

    def test_parent_revocation_denied(self):
        revoked = Grant("root", "tenant-a", None, self.root.capabilities, self.root.assets, 3, False)
        self.assertFalse(self.eligible({"root": revoked, "child": self.child}))

    def test_child_cannot_widen_parent_assets_or_capabilities(self):
        wide_asset = Grant("child", "tenant-a", "root", self.child.capabilities, frozenset({"lab-a", "lab-c"}), 1, True)
        wide_cap = Grant("child", "tenant-a", "root", frozenset({"read", "write"}), self.child.assets, 1, True)
        for candidate in (wide_asset, wide_cap):
            with self.subTest(candidate=candidate):
                self.assertFalse(self.eligible({"root": self.root, "child": candidate}))

    def test_child_cannot_widen_parent_risk(self):
        wide = Grant("child", "tenant-a", "root", self.child.capabilities, self.child.assets, 4, True)
        self.assertFalse(self.eligible({"root": self.root, "child": wide}))

    def test_unapproved_asset_capability_and_risk_denied(self):
        for kwargs in ({"asset": "lab-b"}, {"capability": "scan"}, {"risk": 2}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.eligible(**kwargs))

    def test_invalid_types_and_aliases_denied(self):
        for kwargs in ({"risk": True}, {"tenant": 1}, {"asset": b"lab-a"}, {"leaf_id": 7}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.eligible(**kwargs))
        malformed = Grant("child", "tenant-a", "root", self.child.capabilities, self.child.assets, True, True)
        self.assertFalse(self.eligible({"root": self.root, "child": malformed}))

    def test_non_exact_grant_and_forged_id_denied(self):
        @dataclass(frozen=True)
        class Impostor(Grant):
            pass
        self.assertFalse(self.eligible({"root": self.root, "child": Impostor(**vars(self.child))}))
        self.assertFalse(self.eligible({"root": self.root, "child": Grant("other", "tenant-a", "root", self.child.capabilities, self.child.assets, 1, True)}))


if __name__ == "__main__":
    unittest.main()
