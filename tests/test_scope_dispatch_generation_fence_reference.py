"""Offline reference for generation-fenced authorization dispatch (no target I/O)."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class DispatchLease:
    tenant: str
    request: str
    generation: int
    active: bool


def may_dispatch(snapshot: DispatchLease, live: DispatchLease) -> bool:
    """Reference-only predicate; does not authorize production operations."""
    if type(snapshot) is not DispatchLease or type(live) is not DispatchLease:
        return False
    for lease in (snapshot, live):
        if (type(lease.tenant) is not str or not lease.tenant
                or type(lease.request) is not str or not lease.request
                or type(lease.generation) is not int or lease.generation < 1
                or type(lease.active) is not bool):
            return False
    return (snapshot.active is True and live.active is True
            and snapshot.tenant == live.tenant
            and snapshot.request == live.request
            and snapshot.generation == live.generation)


class GenerationFenceTests(unittest.TestCase):
    def setUp(self):
        self.issued = DispatchLease("tenant-a", "request-a", 7, True)

    def test_same_generation_is_only_conditionally_eligible(self):
        self.assertTrue(may_dispatch(self.issued, self.issued))

    def test_cancellation_denies(self):
        self.assertFalse(may_dispatch(self.issued, DispatchLease("tenant-a", "request-a", 7, False)))

    def test_restart_with_new_generation_denies_stale_worker(self):
        self.assertFalse(may_dispatch(self.issued, DispatchLease("tenant-a", "request-a", 8, True)))

    def test_rollback_to_old_generation_denies_new_worker(self):
        self.assertFalse(may_dispatch(DispatchLease("tenant-a", "request-a", 8, True), self.issued))

    def test_cross_tenant_and_request_replay_denied(self):
        for live in (DispatchLease("tenant-b", "request-a", 7, True),
                     DispatchLease("tenant-a", "request-b", 7, True)):
            with self.subTest(live=live):
                self.assertFalse(may_dispatch(self.issued, live))

    def test_wrong_generation_types_denied(self):
        for value in (True, 7.0, "7", None, 0, -1):
            with self.subTest(value=value):
                self.assertFalse(may_dispatch(self.issued, DispatchLease("tenant-a", "request-a", value, True)))

    def test_truthy_active_denied(self):
        self.assertFalse(may_dispatch(self.issued, DispatchLease("tenant-a", "request-a", 7, 1)))

    def test_subclasses_not_trusted(self):
        class Forged(DispatchLease):
            pass
        self.assertFalse(may_dispatch(self.issued, Forged("tenant-a", "request-a", 7, True)))

    def test_reference_does_not_mutate_inputs(self):
        before = repr(self.issued)
        may_dispatch(self.issued, DispatchLease("tenant-a", "request-a", 8, True))
        self.assertEqual(repr(self.issued), before)


if __name__ == "__main__":
    unittest.main()
