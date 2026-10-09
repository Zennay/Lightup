"""Offline reference: Forwarded/X-Forwarded-* metadata is not authority.

Synthetic checks only. This does not authenticate issuer provenance or provide
production ToolExecutor enforcement. No networking or target interaction.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    request: str
    asset: str
    capability: str
    revision: int
    verified: bool = True
    active: bool = True


@dataclass(frozen=True)
class Dispatch:
    tenant: str
    request: str
    asset: str
    capability: str
    revision: int


def _identity(value):
    return type(value) is str and 1 <= len(value) <= 128 and all(
        33 <= ord(char) <= 126 for char in value
    )


def reference_allowed(grant, dispatch, forwarded=None):
    """Necessary-only binding predicate; forwarded is deliberately not read."""
    if type(grant) is not Grant or type(dispatch) is not Dispatch:
        return False
    if type(grant.verified) is not bool or grant.verified is not True:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.revision) is not int or type(dispatch.revision) is not int:
        return False
    if grant.revision < 0 or grant.revision != dispatch.revision:
        return False
    fields = ("tenant", "request", "asset", "capability")
    return all(
        _identity(getattr(grant, field))
        and _identity(getattr(dispatch, field))
        and getattr(grant, field) == getattr(dispatch, field)
        for field in fields
    )


class HostileForwarded:
    def __getattribute__(self, name):
        raise AssertionError("Forwarded header inspected")

    def __iter__(self):
        raise AssertionError("Forwarded header iterated")

    def __str__(self):
        raise AssertionError("Forwarded header stringified")


class TestForwardedHeaderNonAuthority(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-a", "req-a", "asset-a", "http.headers", 0)
        self.dispatch = Dispatch("tenant-a", "req-a", "asset-a", "http.headers", 0)

    def test_matching_reference_is_only_conditional(self):
        self.assertTrue(reference_allowed(self.grant, self.dispatch))

    def test_forwarded_admin_spoof_cannot_restore_revoked_grant(self):
        revoked = Grant("tenant-a", "req-a", "asset-a", "http.headers", 0, active=False)
        self.assertFalse(reference_allowed(revoked, self.dispatch, 'for=127.0.0.1;host=admin.local;proto=https'))

    def test_x_forwarded_spoof_cannot_verify_issuer(self):
        unverified = Grant("tenant-a", "req-a", "asset-a", "http.headers", 0, verified=False)
        self.assertFalse(reference_allowed(unverified, self.dispatch, {"X-Forwarded-User": "admin"}))

    def test_cross_identity_swap_denied_despite_forwarded(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                wrong = {**self.dispatch.__dict__, field: "other"}
                self.assertFalse(reference_allowed(self.grant, Dispatch(**wrong), "for=trusted"))

    def test_forwarded_does_not_reconcile_stale_revision(self):
        self.assertFalse(reference_allowed(self.grant, Dispatch("tenant-a", "req-a", "asset-a", "http.headers", 1), "proto=https"))

    def test_polymorphic_forwarded_never_consulted(self):
        self.assertTrue(reference_allowed(self.grant, self.dispatch, HostileForwarded()))
        self.assertFalse(reference_allowed(
            Grant("tenant-a", "req-a", "asset-a", "http.headers", 0, active=False),
            self.dispatch, HostileForwarded()
        ))

    def test_matching_invalid_identity_denied(self):
        for invalid in ("bad\nvalue", "bad\x00value", "é", "", "x" * 129):
            with self.subTest(invalid=repr(invalid)):
                g = Grant(invalid, "req-a", "asset-a", "http.headers", 0)
                d = Dispatch(invalid, "req-a", "asset-a", "http.headers", 0)
                self.assertFalse(reference_allowed(g, d, {"Forwarded": "for=trusted"}))

    def test_invalid_revision_types_denied(self):
        for revision in (True, 0.0, "0"):
            with self.subTest(revision=revision):
                self.assertFalse(reference_allowed(
                    Grant("tenant-a", "req-a", "asset-a", "http.headers", revision),
                    self.dispatch, "for=127.0.0.1"
                ))

    def test_forged_grant_object_denied(self):
        class Fake:
            pass
        self.assertFalse(reference_allowed(Fake(), self.dispatch, "host=trusted"))

    def test_metadata_mutation_cannot_change_decision(self):
        metadata = {"X-Forwarded-For": "198.51.100.5"}
        before = reference_allowed(self.grant, self.dispatch, metadata)
        metadata["X-Forwarded-For"] = "127.0.0.1"
        metadata["Forwarded"] = "for=127.0.0.1;proto=https;host=admin"
        self.assertEqual(before, reference_allowed(self.grant, self.dispatch, metadata))

    def test_matching_invalid_identity_for_every_binding_field(self):
        for field in ("tenant", "request", "asset", "capability"):
            for invalid in ("bad\rvalue", "bad\x7fvalue", " ", "x" * 129):
                with self.subTest(field=field, invalid=repr(invalid)):
                    grant_values = {**self.grant.__dict__, field: invalid}
                    dispatch_values = {**self.dispatch.__dict__, field: invalid}
                    self.assertFalse(reference_allowed(
                        Grant(**grant_values), Dispatch(**dispatch_values), HostileForwarded()
                    ))

    def test_dispatch_revision_type_confusion_denied(self):
        for invalid in (True, False, 0.0, "0", None):
            with self.subTest(invalid=repr(invalid)):
                dispatch = Dispatch("tenant-a", "req-a", "asset-a", "http.headers", invalid)
                self.assertFalse(reference_allowed(self.grant, dispatch, HostileForwarded()))

    def test_active_and_verified_must_be_exact_bools(self):
        for invalid in (1, "true", None):
            with self.subTest(invalid=repr(invalid)):
                verified = Grant("tenant-a", "req-a", "asset-a", "http.headers", 0, verified=invalid)
                active = Grant("tenant-a", "req-a", "asset-a", "http.headers", 0, active=invalid)
                self.assertFalse(reference_allowed(verified, self.dispatch, HostileForwarded()))
                self.assertFalse(reference_allowed(active, self.dispatch, HostileForwarded()))

    def test_proxy_metadata_is_non_authoritative_even_if_not_mapping(self):
        for payload in (None, 123, True, ["for=127.0.0.1"], object(), HostileForwarded()):
            with self.subTest(payload_type=type(payload).__name__):
                self.assertTrue(reference_allowed(self.grant, self.dispatch, payload))
                revoked = Grant("tenant-a", "req-a", "asset-a", "http.headers", 0, active=False)
                self.assertFalse(reference_allowed(revoked, self.dispatch, payload))


if __name__ == "__main__":
    unittest.main()
