"""Offline temporal authorization ordering specification; not an executor integration test.

Every event is synthetic. The reference oracle intentionally denies execution if
revocation was observed before the final dispatch boundary, regardless of queued
approval or retry attempts.
"""
from dataclasses import dataclass, replace
import itertools
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    target: str
    revision: int
    active: bool


@dataclass(frozen=True)
class Pending:
    tenant: str
    target: str
    observed_revision: int


def queue(grant: Grant) -> Pending:
    if not grant.active:
        raise PermissionError("inactive")
    return Pending(grant.tenant, grant.target, grant.revision)


def dispatch(pending: Pending, live: Grant | None) -> bool:
    return (
        type(live) is Grant
        and live.active is True
        and type(live.revision) is int
        and type(pending.observed_revision) is int
        and live.revision == pending.observed_revision
        and live.tenant == pending.tenant
        and live.target == pending.target
    )


class RevocationOrderingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.initial = Grant("tenant-a", "lab-a", 7, True)
        self.pending = queue(self.initial)

    def test_revocation_before_dispatch_denies_even_after_queue(self):
        self.assertFalse(dispatch(self.pending, replace(self.initial, active=False)))

    def test_reapproval_same_identity_new_revision_invalidates_snapshot(self):
        self.assertFalse(dispatch(self.pending, replace(self.initial, revision=8)))

    def test_tenant_or_target_rebinding_denies(self):
        for replacement in (
            replace(self.initial, tenant="tenant-b"),
            replace(self.initial, target="lab-b"),
        ):
            with self.subTest(replacement=replacement):
                self.assertFalse(dispatch(self.pending, replacement))

    def test_missing_live_grant_denies(self):
        self.assertFalse(dispatch(self.pending, None))

    def test_exact_current_live_grant_only_is_conditionally_eligible(self):
        self.assertTrue(dispatch(self.pending, self.initial))

    def test_bool_revision_cannot_impersonate_integer_revision(self):
        grant = Grant("tenant-a", "lab-a", True, True)
        pending = Pending("tenant-a", "lab-a", 1)
        self.assertFalse(dispatch(pending, grant))

    def test_truthy_active_cannot_impersonate_boolean(self):
        for value in (1, "yes", [1]):
            with self.subTest(value=value):
                self.assertFalse(dispatch(self.pending, replace(self.initial, active=value)))

    def test_all_unique_event_orders_recheck_live_grant(self):
        # The final dispatch barrier must use live state, not its queue snapshot.
        for events in itertools.permutations(("queue", "revoke", "dispatch")):
            if events.index("queue") > events.index("dispatch"):
                continue
            live = self.initial
            pending = None
            outcomes = []
            for event in events:
                if event == "queue":
                    pending = queue(live) if live.active else None
                elif event == "revoke":
                    live = replace(live, active=False)
                elif pending is not None:
                    outcomes.append(dispatch(pending, live))
            if events.index("revoke") < events.index("dispatch"):
                self.assertNotIn(True, outcomes, events)

    def test_stale_queued_retry_never_regains_authority(self):
        revoked = replace(self.initial, active=False)
        for _ in range(3):
            self.assertFalse(dispatch(self.pending, revoked))


if __name__ == "__main__":
    unittest.main()
