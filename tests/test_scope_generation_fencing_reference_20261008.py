"""Offline reference tests: revocation/reissue fencing, NOT production authorization."""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Lease:
    tenant: str
    engagement: str
    grant: str
    generation: int


class ReferenceFence:
    """Illustrative in-memory generation fence. Not a durable authority store."""

    def __init__(self):
        self.current = {}

    @staticmethod
    def _valid(lease):
        return (
            type(lease) is Lease
            and all(type(getattr(lease, field)) is str
                    and bool(getattr(lease, field))
                    for field in ("tenant", "engagement", "grant"))
            and type(lease.generation) is int
            and lease.generation > 0
        )

    def issue(self, lease):
        if not self._valid(lease):
            return False
        key = (lease.tenant, lease.engagement, lease.grant)
        previous = self.current.get(key, 0)
        if lease.generation <= previous:
            return False
        self.current[key] = lease.generation
        return True

    def authorize(self, lease):
        if not self._valid(lease):
            return False
        key = (lease.tenant, lease.engagement, lease.grant)
        return self.current.get(key) == lease.generation

    def revoke(self, lease):
        if not self.authorize(lease):
            return False
        key = (lease.tenant, lease.engagement, lease.grant)
        self.current[key] += 1
        return True


class FencingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.fence = ReferenceFence()
        self.first = Lease("tenant-a", "engagement-a", "grant-a", 1)

    def test_unissued_lease_denied(self):
        self.assertFalse(self.fence.authorize(self.first))

    def test_current_generation_reference_eligible(self):
        self.assertTrue(self.fence.issue(self.first))
        self.assertTrue(self.fence.authorize(self.first))

    def test_revoke_blocks_old_generation(self):
        self.assertTrue(self.fence.issue(self.first))
        self.assertTrue(self.fence.revoke(self.first))
        self.assertFalse(self.fence.authorize(self.first))

    def test_reissue_requires_generation_above_tombstone(self):
        self.fence.issue(self.first)
        self.fence.revoke(self.first)
        self.assertFalse(self.fence.issue(self.first))
        self.assertFalse(self.fence.issue(Lease("tenant-a", "engagement-a", "grant-a", 2)))
        self.assertTrue(self.fence.issue(Lease("tenant-a", "engagement-a", "grant-a", 3)))
        self.assertFalse(self.fence.authorize(self.first))

    def test_cross_tenant_generation_is_isolated(self):
        self.fence.issue(self.first)
        self.assertFalse(self.fence.authorize(Lease("tenant-b", "engagement-a", "grant-a", 1)))
        self.assertFalse(self.fence.authorize(Lease("tenant-a", "engagement-b", "grant-a", 1)))

    def test_cross_grant_generation_is_isolated(self):
        self.fence.issue(self.first)
        self.assertFalse(self.fence.authorize(Lease("tenant-a", "engagement-a", "grant-b", 1)))

    def test_types_are_exact_not_truthy(self):
        for generation in (True, 1.0, "1", None, 0, -1):
            self.assertFalse(self.fence.issue(Lease("tenant-a", "engagement-a", "grant-a", generation)))
        for lease in ({"tenant": "tenant-a"}, Lease("", "engagement-a", "grant-a", 1)):
            self.assertFalse(self.fence.authorize(lease))

    def test_stale_issuer_cannot_roll_back_generation(self):
        self.assertTrue(self.fence.issue(Lease("tenant-a", "engagement-a", "grant-a", 10)))
        self.assertFalse(self.fence.issue(self.first))
        self.assertTrue(self.fence.authorize(Lease("tenant-a", "engagement-a", "grant-a", 10)))

    def test_double_revoke_does_not_advance_fence(self):
        self.fence.issue(self.first)
        self.assertTrue(self.fence.revoke(self.first))
        self.assertFalse(self.fence.revoke(self.first))
        self.assertEqual(self.fence.current[("tenant-a", "engagement-a", "grant-a")], 2)


if __name__ == "__main__":
    unittest.main()
