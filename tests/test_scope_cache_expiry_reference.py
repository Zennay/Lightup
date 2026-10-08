"""Offline reference tests for authorization-cache expiry boundaries.

This model is intentionally NOT wired to production and grants no authority.
"""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class Decision:
    tenant: str
    grant_revision: int
    permitted: bool
    evaluated_at: int
    expires_at: int


def reuse_decision(decision, *, now, tenant, revision, live_grant_active):
    """Fail-closed reference: cached allow is never sufficient authority."""
    if type(decision) is not Decision:
        return False
    if type(now) is not int or type(revision) is not int:
        return False
    if type(tenant) is not str or type(live_grant_active) is not bool:
        return False
    if type(decision.tenant) is not str:
        return False
    if type(decision.grant_revision) is not int:
        return False
    if type(decision.permitted) is not bool:
        return False
    if type(decision.evaluated_at) is not int or type(decision.expires_at) is not int:
        return False
    return (
        decision.permitted is True
        and live_grant_active is True
        and tenant == decision.tenant
        and revision == decision.grant_revision
        and decision.evaluated_at <= now < decision.expires_at
    )


class CacheExpiryReferenceTests(unittest.TestCase):
    def setUp(self):
        self.decision = Decision("tenant-a", 7, True, 100, 120)

    def check(self, **changes):
        args = dict(now=110, tenant="tenant-a", revision=7, live_grant_active=True)
        args.update(changes)
        return reuse_decision(self.decision, **args)

    def test_reference_only_in_valid_window(self):
        self.assertTrue(self.check())
        self.assertFalse(self.check(now=99))
        self.assertTrue(self.check(now=100))
        self.assertTrue(self.check(now=119))
        self.assertFalse(self.check(now=120))

    def test_expired_allow_cannot_resurrect(self):
        for now in (120, 121, 1000000):
            with self.subTest(now=now):
                self.assertFalse(self.check(now=now))

    def test_revocation_denies_unexpired_allow(self):
        self.assertFalse(self.check(live_grant_active=False))

    def test_revision_change_denies_unexpired_allow(self):
        self.assertFalse(self.check(revision=8))
        self.assertFalse(self.check(revision=6))

    def test_cross_tenant_reuse_is_denied(self):
        self.assertFalse(self.check(tenant="tenant-b"))

    def test_type_confusion_is_denied(self):
        for field, value in (("now", True), ("revision", True), ("tenant", 1),
                             ("live_grant_active", 1)):
            with self.subTest(field=field):
                self.assertFalse(self.check(**{field: value}))

    def test_untrusted_cached_decision_types_are_denied(self):
        altered = dataclasses.replace(self.decision, permitted=1)
        self.assertFalse(reuse_decision(altered, now=110, tenant="tenant-a",
                                        revision=7, live_grant_active=True))

    def test_empty_or_reversed_interval_is_denied(self):
        for end in (100, 99):
            with self.subTest(end=end):
                altered = dataclasses.replace(self.decision, expires_at=end)
                self.assertFalse(reuse_decision(altered, now=100, tenant="tenant-a",
                                                revision=7, live_grant_active=True))

    def test_reference_is_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.decision.permitted = False


if __name__ == "__main__":
    unittest.main()
