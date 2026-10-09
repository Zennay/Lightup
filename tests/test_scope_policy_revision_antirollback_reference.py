"""Pure offline reference: authorization policy revision must not roll backward.

This is *not* production authorization; source-owner integration required.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class PolicySnapshot:
    tenant: str
    grant_id: str
    revision: int
    enabled: bool


def canonical_identity(value):
    """Conservative reference identity grammar; not issuer provenance."""
    return (type(value) is str and 1 <= len(value) <= 128
            and all(char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:." for char in value))


def may_continue(snapshot, current):
    """A necessary, never sufficient, condition for a queued capability."""
    if type(snapshot) is not PolicySnapshot or type(current) is not PolicySnapshot:
        return False
    if any(not canonical_identity(v) for v in (
        snapshot.tenant, snapshot.grant_id, current.tenant, current.grant_id
    )):
        return False
    if any(type(v) is not int or v < 0 for v in (
        snapshot.revision, current.revision
    )):
        return False
    if type(snapshot.enabled) is not bool or type(current.enabled) is not bool:
        return False
    return (snapshot.enabled is True and current.enabled is True
            and snapshot.tenant == current.tenant
            and snapshot.grant_id == current.grant_id
            and current.revision >= snapshot.revision)


class RevisionReferenceTests(unittest.TestCase):
    def setUp(self):
        self.saved = PolicySnapshot("tenant-a", "grant-1", 8, True)

    def test_same_revision_can_pass_necessary_check(self):
        self.assertTrue(may_continue(self.saved, self.saved))

    def test_newer_revision_can_pass_necessary_check(self):
        self.assertTrue(may_continue(self.saved, PolicySnapshot("tenant-a", "grant-1", 9, True)))

    def test_revision_rollback_denied(self):
        self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-a", "grant-1", 7, True)))

    def test_revocation_dominant_even_when_revision_newer(self):
        self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-a", "grant-1", 9, False)))

    def test_tenant_and_grant_swaps_denied(self):
        self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-b", "grant-1", 9, True)))
        self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-a", "grant-2", 9, True)))

    def test_truthy_and_negative_revisions_denied(self):
        for revision in (True, 8.0, "8", -1, None):
            with self.subTest(revision=revision):
                self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-a", "grant-1", revision, True)))

    def test_truthy_active_denied(self):
        for value in (1, "yes", None):
            with self.subTest(value=value):
                self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-a", "grant-1", 9, value)))

    def test_untrusted_subclass_denied(self):
        class Untrusted(PolicySnapshot):
            pass
        self.assertFalse(may_continue(self.saved, Untrusted("tenant-a", "grant-1", 9, True)))

    def test_malformed_identity_denied(self):
        for bad in ("", " tenant-a", "tenant-a ", "\n"):
            with self.subTest(bad=bad):
                self.assertFalse(may_continue(self.saved, PolicySnapshot(bad, "grant-1", 9, True)))

    def test_malformed_grant_identity_denied(self):
        for bad in ("grant\\n1", "grant\\u202e1", "grant/1", "g" * 129):
            with self.subTest(bad=bad):
                self.assertFalse(may_continue(self.saved, PolicySnapshot("tenant-a", bad, 9, True)))

    def test_snapshot_identity_and_revision_must_also_be_canonical(self):
        self.assertFalse(may_continue(PolicySnapshot("tenant\\na", "grant-1", 8, True),
                                      PolicySnapshot("tenant\\na", "grant-1", 9, True)))
        self.assertFalse(may_continue(PolicySnapshot("tenant-a", "grant-1", True, True),
                                      PolicySnapshot("tenant-a", "grant-1", 9, True)))

    def test_inputs_not_mutated(self):
        before = repr(self.saved)
        may_continue(self.saved, PolicySnapshot("tenant-a", "grant-1", 9, True))
        self.assertEqual(repr(self.saved), before)


if __name__ == "__main__":
    unittest.main()
