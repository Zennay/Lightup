"""Offline delegation-chain reference checks; NOT a production authorizer."""
import unittest


def eligible(chain, *, tenant, asset, audience, capability, risk, now, max_depth=4):
    """Toy model only. All records are invented, local test fixtures."""
    if not isinstance(chain, tuple) or not chain or len(chain) > max_depth:
        return False
    seen = set()
    previous = None
    for record in chain:
        if type(record) is not dict or set(record) != {
            "id", "parent", "tenant", "asset", "audience", "caps",
            "risk", "start", "end", "active", "delegable"
        }:
            return False
        identifier = record["id"]
        if type(identifier) is not str or not identifier or identifier in seen:
            return False
        seen.add(identifier)
        if any(type(record[k]) is not str or record[k] == "" for k in ("tenant", "asset", "audience")):
            return False
        if (record["tenant"], record["asset"], record["audience"]) != (tenant, asset, audience):
            return False
        if type(record["active"]) is not bool or not record["active"]:
            return False
        if type(record["delegable"]) is not bool:
            return False
        if type(record["risk"]) is not int or type(risk) is not int or record["risk"] < risk:
            return False
        if type(record["start"]) is not int or type(record["end"]) is not int:
            return False
        if not record["start"] <= now < record["end"]:
            return False
        caps = record["caps"]
        if type(caps) is not frozenset or not all(type(c) is str for c in caps):
            return False
        if capability not in caps:
            return False
        if previous is None:
            if record["parent"] is not None:
                return False
        else:
            if record["parent"] != previous["id"] or not previous["delegable"]:
                return False
            if (not caps.issubset(previous["caps"]) or
                record["risk"] > previous["risk"] or
                record["start"] < previous["start"] or
                record["end"] > previous["end"]):
                return False
        previous = record
    return True


class DelegationChainReferenceTests(unittest.TestCase):
    def setUp(self):
        self.parent = dict(id="g1", parent=None, tenant="t1", asset="a1",
                           audience="worker1", caps=frozenset({"passive", "report"}),
                           risk=2, start=10, end=100, active=True, delegable=True)
        self.child = dict(self.parent, id="g2", parent="g1",
                          caps=frozenset({"passive"}), end=90, delegable=False)
        self.kw = dict(tenant="t1", asset="a1", audience="worker1",
                       capability="passive", risk=1, now=30)

    def check(self, parent=None, child=None, **kwargs):
        return eligible((self.parent if parent is None else parent,
                         self.child if child is None else child),
                        **(self.kw | kwargs))

    def test_bounded_valid_reference(self):
        self.assertTrue(self.check())

    def test_cross_tenant_child(self):
        self.assertFalse(self.check(child=self.child | {"tenant": "t2"}))

    def test_asset_or_audience_swap(self):
        for key in ("asset", "audience"):
            with self.subTest(key=key):
                self.assertFalse(self.check(child=self.child | {key: "other"}))

    def test_capability_expansion(self):
        self.assertFalse(self.check(child=self.child | {"caps": frozenset({"passive", "report", "active"})}))

    def test_risk_expansion(self):
        self.assertFalse(self.check(child=self.child | {"risk": 3}))

    def test_broader_time_window(self):
        for changes in ({"start": 9}, {"end": 101}):
            with self.subTest(changes=changes):
                self.assertFalse(self.check(child=self.child | changes))

    def test_revoked_parent(self):
        self.assertFalse(self.check(parent=self.parent | {"active": False}))

    def test_denied_delegation(self):
        self.assertFalse(self.check(parent=self.parent | {"delegable": False}))

    def test_wrong_parent_and_reused_id(self):
        self.assertFalse(self.check(child=self.child | {"parent": "unknown"}))
        self.assertFalse(self.check(child=self.child | {"id": "g1"}))

    def test_expiry_and_typed_bool(self):
        self.assertFalse(self.check(now=100))
        self.assertFalse(self.check(child=self.child | {"active": 1}))

    def test_chain_depth_limit(self):
        self.assertFalse(eligible((self.parent, self.child), max_depth=1, **self.kw))

    def test_input_not_mutated(self):
        original_parent, original_child = self.parent.copy(), self.child.copy()
        self.check()
        self.assertEqual((self.parent, self.child), (original_parent, original_child))


if __name__ == "__main__":
    unittest.main()
