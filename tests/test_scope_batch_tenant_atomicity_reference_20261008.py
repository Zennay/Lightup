"""Offline M7/ST5 reference: a mixed-authority batch must never partially authorize.

This is intentionally NOT production authorization. No target I/O or imports.
"""
import unittest


def eligible_batch(tenant, grant_revision, items):
    """Fail closed on *any* item; never return an eligible subset."""
    if type(tenant) is not str or not tenant or type(grant_revision) is not int or grant_revision < 1:
        return False
    if type(items) is not list or not items:
        return False
    seen = set()
    for item in items:
        if type(item) is not dict or set(item) != {"id", "tenant", "grant_revision", "approved"}:
            return False
        ident = item["id"]
        if type(ident) is not str or not ident or ident in seen:
            return False
        seen.add(ident)
        if (type(item["tenant"]) is not str or item["tenant"] != tenant
                or type(item["grant_revision"]) is not int
                or item["grant_revision"] != grant_revision
                or item["approved"] is not True):
            return False
    return True


class ScopeBatchAtomicityReferenceTests(unittest.TestCase):
    def item(self, ident="a", tenant="tenant-a", revision=7, approved=True):
        return {"id": ident, "tenant": tenant, "grant_revision": revision, "approved": approved}

    def test_single_inert_approved_reference(self):
        self.assertTrue(eligible_batch("tenant-a", 7, [self.item()]))

    def test_homogeneous_reference_batch(self):
        self.assertTrue(eligible_batch("tenant-a", 7, [self.item(), self.item("b")]))

    def test_cross_tenant_member_denies_entire_batch(self):
        self.assertFalse(eligible_batch("tenant-a", 7, [self.item(), self.item("b", tenant="tenant-b")]))

    def test_stale_member_denies_entire_batch(self):
        self.assertFalse(eligible_batch("tenant-a", 7, [self.item(), self.item("b", revision=6)]))

    def test_unapproved_member_denies_entire_batch(self):
        self.assertFalse(eligible_batch("tenant-a", 7, [self.item(), self.item("b", approved=False)]))

    def test_truthy_approval_is_not_authority(self):
        for value in (1, "true", [], {"approved": True}):
            with self.subTest(value=value):
                self.assertFalse(eligible_batch("tenant-a", 7, [self.item(approved=value)]))

    def test_boolean_revision_is_not_integer_revision(self):
        self.assertFalse(eligible_batch("tenant-a", True, [self.item(revision=True)]))
        self.assertFalse(eligible_batch("tenant-a", 7, [self.item(revision=True)]))

    def test_duplicate_work_item_denies_all(self):
        self.assertFalse(eligible_batch("tenant-a", 7, [self.item(), self.item()]))

    def test_empty_malformed_or_extra_field_denies_all(self):
        for items in ([], (), None, [None], [self.item(), {"id": "b"}],
                      [dict(self.item(), capability="scan")]):
            with self.subTest(items=items):
                self.assertFalse(eligible_batch("tenant-a", 7, items))

    def test_input_is_not_mutated_or_filtered(self):
        items = [self.item(), self.item("b", tenant="tenant-b")]
        before = [dict(x) for x in items]
        self.assertFalse(eligible_batch("tenant-a", 7, items))
        self.assertEqual(items, before)


if __name__ == "__main__":
    unittest.main()
