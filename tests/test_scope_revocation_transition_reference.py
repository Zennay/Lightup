"""Additional isolated reference checks for revocation state transitions.

No production imports, network access, targets, or capability execution. These
cases specify expected dispatch-denial semantics only.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Snapshot:
    tenant: str
    target: str
    generation: int


@dataclass(frozen=True)
class Live:
    tenant: str
    target: str
    generation: int
    active: bool


def eligible(snapshot: Snapshot, live: Live | None) -> bool:
    return (
        type(snapshot) is Snapshot
        and type(live) is Live
        and type(snapshot.tenant) is str
        and type(snapshot.target) is str
        and type(snapshot.generation) is int
        and type(live.tenant) is str
        and type(live.target) is str
        and type(live.generation) is int
        and type(live.active) is bool
        and bool(snapshot.tenant)
        and bool(snapshot.target)
        and live.active
        and snapshot.tenant == live.tenant
        and snapshot.target == live.target
        and snapshot.generation == live.generation
    )


class DispatchTransitionReferenceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = Snapshot("customer-a", "local-lab", 17)
        self.live = Live("customer-a", "local-lab", 17, True)

    def test_revocation_is_monotonic_for_original_snapshot(self):
        states = [
            self.live,
            Live("customer-a", "local-lab", 17, False),
            Live("customer-a", "local-lab", 18, True),
            Live("customer-a", "local-lab", 18, False),
        ]
        self.assertEqual(
            [eligible(self.snapshot, state) for state in states],
            [True, False, False, False],
        )

    def test_new_approval_requires_new_snapshot(self):
        reapproved = Live("customer-a", "local-lab", 18, True)
        self.assertFalse(eligible(self.snapshot, reapproved))
        self.assertTrue(eligible(Snapshot("customer-a", "local-lab", 18), reapproved))

    def test_revocation_of_one_tenant_does_not_revoke_another(self):
        other = Snapshot("customer-b", "local-lab", 3)
        other_live = Live("customer-b", "local-lab", 3, True)
        self.assertTrue(eligible(other, other_live))
        self.assertFalse(eligible(self.snapshot, Live("customer-a", "local-lab", 17, False)))
        self.assertTrue(eligible(other, other_live))

    def test_no_snapshot_mutation_when_live_state_changes(self):
        previous = self.snapshot
        self.assertFalse(eligible(self.snapshot, Live("customer-a", "local-lab", 17, False)))
        self.assertEqual(self.snapshot, previous)

    def test_live_identity_and_generation_type_confusion_fail_closed(self):
        class SubclassStr(str):
            pass

        class SubclassInt(int):
            pass

        forged = [
            Live(SubclassStr("customer-a"), "local-lab", 17, True),
            Live("customer-a", SubclassStr("local-lab"), 17, True),
            Live("customer-a", "local-lab", SubclassInt(17), True),
            Live("customer-a", "local-lab", True, True),
            Live("customer-a", "local-lab", 17, 1),
        ]
        for state in forged:
            with self.subTest(state=state):
                self.assertFalse(eligible(self.snapshot, state))

    def test_snapshot_type_confusion_fail_closed(self):
        for snapshot in [
            Snapshot("customer-a", "local-lab", True),
            Snapshot("customer-a", "local-lab", 17.0),
            Snapshot("", "local-lab", 17),
            Snapshot("customer-a", "", 17),
        ]:
            with self.subTest(snapshot=snapshot):
                self.assertFalse(eligible(snapshot, self.live))

    def test_disappearance_of_grant_at_final_barrier_denies(self):
        self.assertFalse(eligible(self.snapshot, None))


if __name__ == "__main__":
    unittest.main()
