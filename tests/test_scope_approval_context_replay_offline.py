"""Offline reference: an approval receipt cannot be replayed into another run.

This is a *non-production* contract fixture. It performs no network I/O,
issues no grants and does not substitute for the trusted ToolExecutor gate.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class ApprovalReceipt:
    tenant: str
    engagement: str
    asset: str
    capability: str
    run_id: str
    operator_id: str
    approved_risk: int
    revision: int
    approved: bool


def admission(receipt: object, request: object, *, revoked: object) -> bool:
    """Fail closed unless every authorization-relevant dimension is exact."""
    if type(receipt) is not ApprovalReceipt or type(request) is not ApprovalReceipt:
        return False
    if type(revoked) is not bool or revoked:
        return False
    if type(receipt.approved) is not bool or receipt.approved is not True:
        return False
    if type(request.approved) is not bool or request.approved is not True:
        return False
    if type(receipt.approved_risk) is not int or type(request.approved_risk) is not int:
        return False
    if not 0 <= receipt.approved_risk <= 5 or not 0 <= request.approved_risk <= 5:
        return False
    if type(receipt.revision) is not int or type(request.revision) is not int:
        return False
    if receipt.revision <= 0 or request.revision <= 0:
        return False
    for name in ("tenant", "engagement", "asset", "capability", "run_id", "operator_id"):
        stored = getattr(receipt, name)
        asked = getattr(request, name)
        if type(stored) is not str or type(asked) is not str or not stored or stored != asked:
            return False
    return (receipt.revision == request.revision
            and request.approved_risk <= receipt.approved_risk)


class ApprovalContextReplayContract(unittest.TestCase):
    def setUp(self):
        self.receipt = ApprovalReceipt("tenant-a", "engagement-a", "asset-a",
                                       "http-baseline", "run-a", "operator-a",
                                       2, 7, True)

    def test_identical_binding_allows_only_with_explicit_non_revocation(self):
        self.assertTrue(admission(self.receipt, self.receipt, revoked=False))
        for invalid in (None, 0, "", [], True):
            self.assertFalse(admission(self.receipt, self.receipt, revoked=invalid))

    def test_context_dimension_replay_is_denied(self):
        from dataclasses import replace
        for field in ("tenant", "engagement", "asset", "capability",
                      "run_id", "operator_id"):
            with self.subTest(field=field):
                replay = replace(self.receipt, **{field: getattr(self.receipt, field) + "-other"})
                self.assertFalse(admission(self.receipt, replay, revoked=False))
                self.assertFalse(admission(replay, self.receipt, revoked=False))

    def test_risk_and_revision_boundaries(self):
        from dataclasses import replace
        self.assertTrue(admission(self.receipt,
                                  replace(self.receipt, approved_risk=1), revoked=False))
        for update in ({"approved_risk": 3}, {"approved_risk": True},
                       {"revision": 8}, {"revision": True},
                       {"approved": False}):
            with self.subTest(update=update):
                self.assertFalse(admission(self.receipt, replace(self.receipt, **update),
                                           revoked=False))


if __name__ == "__main__":
    unittest.main()
