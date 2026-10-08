"""Synthetic-only fail-closed evidence selection. No authority granted."""
import unittest

from test_scope_conflicting_evidence_reference_20261008 import reference_admit


def select_unique_approval(receipts, requested):
    """Reference: reject multiple or missing receipts, never choose a winner."""
    if type(receipts) is not list or len(receipts) != 1:
        return False
    receipt = receipts[0]
    if type(requested) is not dict or type(receipt) is not dict:
        return False
    required = ("request_id", "tenant_id", "asset_id", "capability", "revision")
    if any(type(requested.get(k)) is not str or not requested.get(k) for k in required):
        return False
    if any(type(receipt.get(k)) is not str or receipt.get(k) != requested[k] for k in required):
        return False
    envelope = dict(receipt,
                    approval_request_id=receipt["request_id"],
                    approval_tenant_id=receipt["tenant_id"],
                    approval_asset_id=receipt["asset_id"],
                    approval_capability=receipt["capability"],
                    approval_revision=receipt["revision"])
    return reference_admit(envelope)


class UniqueApprovalReferenceTests(unittest.TestCase):
    def setUp(self):
        self.request = dict(request_id="r1", tenant_id="t1", asset_id="a1",
                            capability="web-baseline", revision="v1")
        self.approval = dict(self.request, approved=True, revoked=False)

    def test_single_matching_receipt_is_conditionally_eligible(self):
        self.assertTrue(select_unique_approval([self.approval], self.request))

    def test_no_receipts_denies(self):
        self.assertFalse(select_unique_approval([], self.request))

    def test_duplicate_identical_receipts_deny_instead_of_arbitrary_selection(self):
        self.assertFalse(select_unique_approval([self.approval, dict(self.approval)], self.request))

    def test_conflicting_receipts_deny_regardless_of_order(self):
        foreign = dict(self.approval, tenant_id="foreign")
        self.assertFalse(select_unique_approval([self.approval, foreign], self.request))
        self.assertFalse(select_unique_approval([foreign, self.approval], self.request))

    def test_explicit_revocation_blocks_single_receipt(self):
        self.assertFalse(select_unique_approval([dict(self.approval, revoked=True)], self.request))

    def test_mismatched_single_receipt_denies(self):
        for k in self.request:
            with self.subTest(key=k):
                self.assertFalse(select_unique_approval([dict(self.approval, **{k: "other"})], self.request))

    def test_malformed_containers_denied(self):
        for receipts in (None, {}, (), "approved", [None], [1]):
            with self.subTest(receipts=receipts):
                self.assertFalse(select_unique_approval(receipts, self.request))

    def test_does_not_mutate_caller_owned_receipts_or_request(self):
        receipts = [dict(self.approval)]
        request = dict(self.request)
        self.assertTrue(select_unique_approval(receipts, request))
        self.assertEqual(receipts, [self.approval])
        self.assertEqual(request, self.request)


if __name__ == "__main__":
    unittest.main()
