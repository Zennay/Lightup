"""Offline test: polymorphic equality must not forge approval identity."""
import unittest

from test_scope_conflicting_evidence_reference_20261008 import reference_admit
from test_scope_unique_approval_reference_20261008 import select_unique_approval


class ForgedEquality:
    def __init__(self):
        self.comparisons = 0

    def __eq__(self, other):
        self.comparisons += 1
        return True


class IdentityComparisonGuardTests(unittest.TestCase):
    def setUp(self):
        self.req = dict(request_id="r", tenant_id="t", asset_id="a",
                        capability="web-baseline", revision="1")
        self.receipt = dict(self.req, approved=True, revoked=False)

    def test_forged_request_identity_cannot_be_compared(self):
        for key in self.req:
            with self.subTest(key=key):
                impostor = ForgedEquality()
                request = dict(self.req, **{key: impostor})
                self.assertFalse(select_unique_approval([self.receipt], request))
                self.assertEqual(impostor.comparisons, 0)

    def test_forged_receipt_identity_cannot_be_compared(self):
        for key in self.req:
            with self.subTest(key=key):
                impostor = ForgedEquality()
                receipt = dict(self.receipt, **{key: impostor})
                self.assertFalse(select_unique_approval([receipt], self.req))
                self.assertEqual(impostor.comparisons, 0)

    def test_forged_pairwise_approval_identity_cannot_be_compared(self):
        for key in ("approval_request_id", "approval_tenant_id", "approval_asset_id",
                    "approval_capability", "approval_revision"):
            with self.subTest(key=key):
                impostor = ForgedEquality()
                envelope = dict(self.receipt,
                    approval_request_id="r", approval_tenant_id="t",
                    approval_asset_id="a", approval_capability="web-baseline",
                    approval_revision="1")
                envelope[key] = impostor
                self.assertFalse(reference_admit(envelope))
                self.assertEqual(impostor.comparisons, 0)


if __name__ == "__main__":
    unittest.main()
