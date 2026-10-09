"""Offline reference: restoring stale authorization snapshots must not resurrect rights.

This model is deliberately not a production authorization service.
"""
from dataclasses import dataclass
import unicodedata
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    grant_id: str
    revision: int
    active: bool


def canonical_identity(value):
    """Reject ambiguous tenant/grant claims rather than silently normalizing them."""
    return (type(value) is str and 1 <= len(value) <= 128
            and value.isascii() and all(ch.isalnum() or ch in "-_." for ch in value)
            and not any(unicodedata.category(ch).startswith("C") for ch in value))


def restore_eligible(snapshot, issuer_state):
    """Admit a snapshot only if the current issuer-owned state still matches."""
    if type(snapshot) is not Grant or type(issuer_state) is not Grant:
        return False
    if not all(canonical_identity(value)
               for value in (snapshot.tenant, snapshot.grant_id,
                             issuer_state.tenant, issuer_state.grant_id)):
        return False
    if type(snapshot.revision) is not int or type(issuer_state.revision) is not int:
        return False
    if snapshot.revision < 1 or issuer_state.revision < 1:
        return False
    if type(snapshot.active) is not bool or type(issuer_state.active) is not bool:
        return False
    return (
        snapshot.tenant == issuer_state.tenant
        and snapshot.grant_id == issuer_state.grant_id
        and snapshot.revision == issuer_state.revision
        and snapshot.active is True
        and issuer_state.active is True
    )


class RestoreRollbackReferenceTests(unittest.TestCase):
    def setUp(self):
        self.current = Grant("tenant-a", "grant-a", 5, True)

    def test_exact_active_issuer_snapshot_is_only_conditionally_eligible(self):
        self.assertTrue(restore_eligible(self.current, self.current))

    def test_revoked_current_grant_denies_stale_active_backup(self):
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", 4, True),
                                          Grant("tenant-a", "grant-a", 5, False)))

    def test_same_revision_revocation_denies(self):
        self.assertFalse(restore_eligible(self.current,
                                          Grant("tenant-a", "grant-a", 5, False)))

    def test_reissued_grant_denies_old_revision(self):
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", 4, True),
                                          self.current))

    def test_cross_tenant_and_cross_grant_restore_denied(self):
        self.assertFalse(restore_eligible(Grant("tenant-b", "grant-a", 5, True),
                                          self.current))
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-b", 5, True),
                                          self.current))

    def test_future_or_forged_revision_denied(self):
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", 6, True),
                                          self.current))

    def test_boolean_revision_is_not_integer(self):
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", True, True),
                                          self.current))

    def test_truthy_active_is_not_approval(self):
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", 5, 1),
                                          self.current))
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", 5, True),
                                          Grant("tenant-a", "grant-a", 5, "yes")))

    def test_noncanonical_identity_and_invalid_revision_denied(self):
        self.assertFalse(restore_eligible(Grant(" tenant-a", "grant-a", 5, True),
                                          self.current))
        self.assertFalse(restore_eligible(Grant("tenant-a", "grant-a", 0, True),
                                          self.current))
        self.assertFalse(restore_eligible(Grant("tenant-a", "", 5, True),
                                          self.current))

    def test_control_unicode_and_overlong_identity_denied(self):
        for identity in ("tenant\nadmin", "tenant\x00admin", "tenant/admin",
                         "ténant-a", "tenant\u2028admin", "a" * 129):
            with self.subTest(identity=repr(identity)):
                self.assertFalse(restore_eligible(Grant(identity, "grant-a", 5, True),
                                                  self.current))
                self.assertFalse(restore_eligible(self.current,
                                                  Grant(identity, "grant-a", 5, True)))

    def test_polymorphic_and_untrusted_restore_envelopes_denied(self):
        class DerivedGrant(Grant):
            pass
        self.assertFalse(restore_eligible(DerivedGrant("tenant-a", "grant-a", 5, True),
                                          self.current))
        self.assertFalse(restore_eligible({"tenant": "tenant-a"}, self.current))
        self.assertFalse(restore_eligible(self.current, object()))

    def test_reference_does_not_mutate_inputs(self):
        prior = (self.current, Grant("tenant-a", "grant-a", 4, True))
        self.assertFalse(restore_eligible(prior[1], prior[0]))
        self.assertEqual(prior, (Grant("tenant-a", "grant-a", 5, True),
                                 Grant("tenant-a", "grant-a", 4, True)))


if __name__ == "__main__":
    unittest.main()
