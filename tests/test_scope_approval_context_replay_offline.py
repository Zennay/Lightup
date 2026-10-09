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


    def test_corrupt_stored_context_does_not_become_authority_on_exact_match(self):
        from dataclasses import replace
        for field in ("tenant", "engagement", "asset", "capability",
                      "run_id", "operator_id"):
            for invalid in ("", None, 0, ["forged"], True):
                with self.subTest(field=field, invalid=repr(invalid)):
                    corrupt = replace(self.receipt, **{field: invalid})
                    self.assertFalse(admission(corrupt, corrupt, revoked=False))

    def test_noncanonical_receipt_and_request_types_are_denied(self):
        from dataclasses import replace
        class ForgedReceipt(ApprovalReceipt):
            pass

        class ForgedString(str):
            pass

        self.assertFalse(admission(ForgedReceipt(**vars(self.receipt)),
                                   self.receipt, revoked=False))
        self.assertFalse(admission(self.receipt,
                                   ForgedReceipt(**vars(self.receipt)), revoked=False))
        for field in ("tenant", "engagement", "asset", "capability",
                      "run_id", "operator_id"):
            with self.subTest(field=field):
                forged = replace(self.receipt, **{
                    field: ForgedString(getattr(self.receipt, field))
                })
                self.assertFalse(admission(forged, forged, revoked=False))


    def test_stored_receipt_revision_risk_and_approval_are_authoritative(self):
        from dataclasses import replace
        mutations = (
            {"revision": 0}, {"revision": -1}, {"revision": True},
            {"revision": "7"}, {"approved_risk": -1}, {"approved_risk": 6},
            {"approved_risk": 2.0}, {"approved": 1}, {"approved": None},
            {"approved": False},
        )
        for update in mutations:
            with self.subTest(update=update):
                modified = replace(self.receipt, **update)
                self.assertFalse(admission(modified, modified, revoked=False))

    def test_pairwise_role_swaps_never_transfer_authority(self):
        from dataclasses import replace
        from itertools import combinations
        fields = ("tenant", "engagement", "asset", "capability",
                  "run_id", "operator_id")
        for left, right in combinations(fields, 2):
            with self.subTest(left=left, right=right):
                moved = replace(self.receipt, **{
                    left: getattr(self.receipt, right),
                    right: getattr(self.receipt, left),
                })
                self.assertFalse(admission(self.receipt, moved, revoked=False))
                self.assertFalse(admission(moved, self.receipt, revoked=False))


    def test_risk_ceiling_exhaustive_bounded_matrix(self):
        from dataclasses import replace
        for ceiling in range(6):
            stored = replace(self.receipt, approved_risk=ceiling)
            for requested in range(6):
                with self.subTest(ceiling=ceiling, requested=requested):
                    request = replace(stored, approved_risk=requested)
                    self.assertEqual(
                        admission(stored, request, revoked=False),
                        requested <= ceiling,
                    )
                    self.assertFalse(admission(stored, request, revoked=True))

    def test_revision_isolation_across_successive_receipts(self):
        from dataclasses import replace
        for old_revision in range(1, 5):
            for latest_revision in range(1, 5):
                with self.subTest(old=old_revision, latest=latest_revision):
                    stored = replace(self.receipt, revision=latest_revision)
                    request = replace(self.receipt, revision=old_revision)
                    self.assertEqual(
                        admission(stored, request, revoked=False),
                        old_revision == latest_revision,
                    )


    def test_lookalike_request_identity_never_reuses_approval(self):
        from dataclasses import replace
        fields = ("tenant", "engagement", "asset", "capability",
                  "run_id", "operator_id")
        for field in fields:
            original = getattr(self.receipt, field)
            for candidate in (original.upper(), original + " ", " " + original,
                              original + chr(0x200B), original + chr(0x0301)):
                if candidate == original:
                    continue
                with self.subTest(field=field, candidate=repr(candidate)):
                    request = replace(self.receipt, **{field: candidate})
                    self.assertFalse(admission(self.receipt, request, revoked=False))


if __name__ == "__main__":
    unittest.main()
