"""Offline reference contracts for concurrent scope authorization leases.

This is NOT the production lease manager, and cannot authorize target execution.
"""
import unittest
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Lease:
    tenant: str
    run: str
    asset: str
    capability: str
    revision: int
    expires_at: int
    active: bool = True


def admit(existing, candidate, now):
    """Return (admitted, unchanged state) or (admitted, new state).

    Deliberately pure and deterministic. Production needs durable atomic compare
    and swap, issuer-owned revision provenance and clock validation.
    """
    if type(now) is not int or now < 0 or type(candidate) is not Lease:
        return False, existing
    if any(type(x) is not str or not x.strip() for x in
           (candidate.tenant, candidate.run, candidate.asset, candidate.capability)):
        return False, existing
    if type(candidate.revision) is not int or candidate.revision < 1:
        return False, existing
    if type(candidate.expires_at) is not int or candidate.expires_at <= now:
        return False, existing
    if candidate.active is not True:
        return False, existing
    if any(type(item) is not Lease for item in existing):
        return False, existing
    key = (candidate.tenant, candidate.asset, candidate.capability)
    for item in existing:
        if (item.tenant, item.asset, item.capability) != key:
            continue
        if item.active is True and type(item.expires_at) is int and item.expires_at > now:
            return False, existing
    return True, (*existing, candidate)


class LeaseReferenceTests(unittest.TestCase):
    def setUp(self):
        self.first = Lease("tenant-a", "run-1", "asset-a", "http-check", 1, 100)

    def test_first_lease_admitted(self):
        accepted, state = admit((), self.first, 50)
        self.assertTrue(accepted)
        self.assertEqual(state, (self.first,))

    def test_same_key_different_run_denied(self):
        accepted, state = admit((self.first,), replace(self.first, run="run-2"), 50)
        self.assertFalse(accepted)
        self.assertEqual(state, (self.first,))

    def test_same_run_replay_denied(self):
        self.assertFalse(admit((self.first,), self.first, 50)[0])

    def test_other_capability_is_independent(self):
        self.assertTrue(admit((self.first,), replace(self.first, capability="tls"), 50)[0])

    def test_other_tenant_is_independent(self):
        self.assertTrue(admit((self.first,), replace(self.first, tenant="tenant-b"), 50)[0])

    def test_other_asset_is_independent(self):
        self.assertTrue(admit((self.first,), replace(self.first, asset="asset-b"), 50)[0])

    def test_expired_lease_does_not_block_new_lease(self):
        self.assertTrue(admit((self.first,), replace(self.first, run="run-2"), 100)[0])

    def test_inactive_lease_does_not_block_new_lease(self):
        self.assertTrue(admit((replace(self.first, active=False),),
                              replace(self.first, run="run-2"), 50)[0])

    def test_new_expired_or_invalid_candidate_denied(self):
        for candidate in (replace(self.first, expires_at=50),
                          replace(self.first, revision=0),
                          replace(self.first, revision=True),
                          replace(self.first, active=1),
                          replace(self.first, tenant=" ")):
            with self.subTest(candidate=candidate):
                self.assertFalse(admit((), candidate, 50)[0])

    def test_untrusted_clock_denied(self):
        for clock in (None, True, -1, "50", 50.0):
            with self.subTest(clock=clock):
                self.assertFalse(admit((), self.first, clock)[0])

    def test_malformed_existing_state_denies(self):
        self.assertFalse(admit((object(),), self.first, 50)[0])

    def test_denial_does_not_mutate_input(self):
        existing = (self.first,)
        rejected, new_state = admit(existing, replace(self.first, run="run-2"), 50)
        self.assertFalse(rejected)
        self.assertIs(new_state, existing)


if __name__ == "__main__":
    unittest.main()
