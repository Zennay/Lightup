"""Offline reference: imported authorization snapshots never become live authority.

Synthetic fixtures only. This is not production issuer verification or dispatch.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class ImportedSnapshot:
    tenant: str
    request: str
    grant: str
    revision: int
    active: bool
    export_digest: str


@dataclass(frozen=True)
class LiveDecision:
    tenant: str
    request: str
    grant: str
    revision: int
    active: bool
    issuer_verified: bool
    revoked: bool


def eligible_for_review(snapshot, live):
    """Consistency check only: never use this predicate to dispatch tools."""
    if type(snapshot) is not ImportedSnapshot or type(live) is not LiveDecision:
        return False
    for value in (snapshot.tenant, snapshot.request, snapshot.grant,
                  live.tenant, live.request, live.grant):
        if type(value) is not str or not (1 <= len(value) <= 128):
            return False
        if not value.isascii() or not all(
            c.isalnum() or c in "_-." for c in value
        ):
            return False
    if type(snapshot.export_digest) is not str or len(snapshot.export_digest) != 64:
        return False
    if any(c not in "0123456789abcdef" for c in snapshot.export_digest):
        return False
    if type(snapshot.revision) is not int or type(live.revision) is not int:
        return False
    if snapshot.revision < 1 or live.revision < 1:
        return False
    if snapshot.active is not True or live.active is not True:
        return False
    if live.issuer_verified is not True or live.revoked is not False:
        return False
    return (snapshot.tenant, snapshot.request, snapshot.grant, snapshot.revision) == (
        live.tenant, live.request, live.grant, live.revision
    )


class ImportReplayReferenceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = ImportedSnapshot("tenant1", "request1", "grant1", 3, True, "a" * 64)
        self.live = LiveDecision("tenant1", "request1", "grant1", 3, True, True, False)

    def test_conditional_reference_consistency(self):
        self.assertTrue(eligible_for_review(self.snapshot, self.live))

    def test_import_is_not_self_authenticating(self):
        self.assertFalse(eligible_for_review(self.snapshot, None))
        self.assertFalse(eligible_for_review(self.snapshot, self.snapshot))

    def test_live_revocation_and_issuer_requirement(self):
        from dataclasses import replace
        for change in ({"revoked": True}, {"issuer_verified": False},
                       {"issuer_verified": 1}, {"revoked": 0}, {"active": 1}):
            with self.subTest(change=change):
                self.assertFalse(eligible_for_review(self.snapshot, replace(self.live, **change)))

    def test_snapshot_activity_is_strict(self):
        from dataclasses import replace
        for value in (False, 1, "true", None):
            self.assertFalse(eligible_for_review(replace(self.snapshot, active=value), self.live))

    def test_identity_swaps_fail(self):
        from dataclasses import replace
        for field in ("tenant", "request", "grant"):
            self.assertFalse(eligible_for_review(replace(self.snapshot, **{field: "other"}), self.live))
            self.assertFalse(eligible_for_review(self.snapshot, replace(self.live, **{field: "other"})))

    def test_revision_replay_and_numeric_confusion_fail(self):
        from dataclasses import replace
        for value in (1, 4, 0, True, "3", 3.0):
            self.assertFalse(eligible_for_review(replace(self.snapshot, revision=value), self.live))
        for value in (2, 4, 0, True, "3", 3.0):
            self.assertFalse(eligible_for_review(self.snapshot, replace(self.live, revision=value)))

    def test_ambiguous_identifiers_fail(self):
        from dataclasses import replace
        for value in (" tenant1", "tenant1\n", "ténant1", "", "x" * 129, "tenant/1"):
            self.assertFalse(eligible_for_review(replace(self.snapshot, tenant=value), self.live))

    def test_export_digest_does_not_establish_authority(self):
        from dataclasses import replace
        for digest in ("A" * 64, "g" * 64, "a" * 63, 42, ""):
            self.assertFalse(eligible_for_review(replace(self.snapshot, export_digest=digest), self.live))
        self.assertFalse(eligible_for_review(self.snapshot, replace(self.live, issuer_verified=False)))

    def test_forged_envelopes_fail(self):
        class DerivedSnapshot(ImportedSnapshot):
            pass
        class DerivedLive(LiveDecision):
            pass
        self.assertFalse(eligible_for_review(DerivedSnapshot(**vars(self.snapshot)), self.live))
        self.assertFalse(eligible_for_review(self.snapshot, DerivedLive(**vars(self.live))))
        self.assertFalse(eligible_for_review(vars(self.snapshot), vars(self.live)))

    def test_reference_is_pure(self):
        original_snapshot, original_live = repr(self.snapshot), repr(self.live)
        eligible_for_review(self.snapshot, self.live)
        self.assertEqual(repr(self.snapshot), original_snapshot)
        self.assertEqual(repr(self.live), original_live)


if __name__ == "__main__":
    unittest.main()
