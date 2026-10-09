"""Offline synthetic boundary: Sec-Fetch-Mode never supplies scope authority.

Reference-only: not a production authorization oracle. No I/O or target traffic.
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str = "tenant-a"
    request: str = "request-a"
    asset: str = "asset-a"
    capability: str = "passive-review"
    revision: int = 1
    active: bool = True
    issuer_verified: bool = True


@dataclass(frozen=True)
class Dispatch:
    tenant: str = "tenant-a"
    request: str = "request-a"
    asset: str = "asset-a"
    capability: str = "passive-review"
    revision: int = 1


def _identity(value):
    return (type(value) is str and 1 <= len(value) <= 128
            and all(0x21 <= ord(ch) <= 0x7e for ch in value))


def reference_consistent(grant, dispatch, sec_fetch_mode):
    """Necessary synthetic consistency only; never authenticates issuance."""
    if type(grant) is not Grant or type(dispatch) is not Dispatch:
        return False
    if grant.active is not True or grant.issuer_verified is not True:
        return False
    if type(grant.revision) is not int or type(dispatch.revision) is not int:
        return False
    if grant.revision < 0 or dispatch.revision != grant.revision:
        return False
    for field in ("tenant", "request", "asset", "capability"):
        left, right = getattr(grant, field), getattr(dispatch, field)
        if not _identity(left) or not _identity(right) or left != right:
            return False
    # The untrusted Sec-Fetch-Mode transport hint is never inspected.
    return True


class HostileHeader:
    def __str__(self):
        raise AssertionError("header coercion")

    def __bool__(self):
        raise AssertionError("header truthiness")

    def __eq__(self, other):
        raise AssertionError("header comparison")


class ScopeFetchModeNonAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.grant = Grant()
        self.dispatch = Dispatch()

    def test_matching_synthetic_fixture_is_hint_independent(self):
        for hint in ("navigate", "cors", "no-cors", "same-origin", "websocket", None, HostileHeader()):
            with self.subTest(hint=type(hint).__name__):
                self.assertTrue(reference_consistent(self.grant, self.dispatch, hint))

    def test_revoked_grant_not_recovered_by_transport(self):
        for hint in ("same-origin", "navigate", HostileHeader()):
            self.assertFalse(reference_consistent(replace(self.grant, active=False), self.dispatch, hint))

    def test_unverified_issuer_not_recovered_by_transport(self):
        self.assertFalse(reference_consistent(replace(self.grant, issuer_verified=False), self.dispatch, "same-origin"))

    def test_cross_binding_cannot_be_hidden_by_hint(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(reference_consistent(self.grant, replace(self.dispatch, **{field: "other"}), "same-origin"))

    def test_revisions_fail_closed(self):
        for revision in (-1, 0, 2, True, 1.0, "1"):
            with self.subTest(revision=revision):
                self.assertFalse(reference_consistent(self.grant, replace(self.dispatch, revision=revision), "navigate"))

    def test_matching_malformed_identity_fails(self):
        for value in ("", "line\nbreak", "a" * 129, 7):
            for field in ("tenant", "request", "asset", "capability"):
                with self.subTest(field=field, value=repr(value)):
                    self.assertFalse(reference_consistent(replace(self.grant, **{field: value}),
                                                          replace(self.dispatch, **{field: value}), "same-origin"))

    def test_exact_boolean_state_required(self):
        for field in ("active", "issuer_verified"):
            for value in (1, "true", None):
                with self.subTest(field=field, value=value):
                    self.assertFalse(reference_consistent(replace(self.grant, **{field: value}),
                                                          self.dispatch, "navigate"))

    def test_polymorphic_envelope_rejected(self):
        class SubGrant(Grant):
            pass
        self.assertFalse(reference_consistent(SubGrant(), self.dispatch, "same-origin"))
        self.assertFalse(reference_consistent(self.grant, object(), "same-origin"))

    def test_transport_hint_cannot_revoke_valid_synthetic_fixture(self):
        for hint in ("", "not-a-mode", "\r\n", 12, {"admin": True}, HostileHeader()):
            self.assertTrue(reference_consistent(self.grant, self.dispatch, hint))


    def test_grant_side_mismatch_denied(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(reference_consistent(replace(self.grant, **{field: "other"}),
                                                      self.dispatch, "navigate"))

    def test_grant_revision_and_flag_type_confusion_denied(self):
        for revision in (-1, 0, 2, True, 1.0, "1"):
            with self.subTest(revision=revision):
                self.assertFalse(reference_consistent(replace(self.grant, revision=revision),
                                                      self.dispatch, "cors"))

    def test_string_subclasses_not_accepted_as_identities(self):
        class SpoofedIdentity(str):
            pass

        for field in ("tenant", "request", "asset", "capability"):
            original = getattr(self.grant, field)
            with self.subTest(field=field):
                self.assertFalse(reference_consistent(
                    replace(self.grant, **{field: SpoofedIdentity(original)}),
                    self.dispatch, "same-origin"))
                self.assertFalse(reference_consistent(
                    self.grant,
                    replace(self.dispatch, **{field: SpoofedIdentity(original)}),
                    "same-origin"))

    def test_input_dataclasses_remain_unchanged(self):
        grant_before, dispatch_before = self.grant, self.dispatch
        self.assertTrue(reference_consistent(self.grant, self.dispatch, HostileHeader()))
        self.assertEqual(self.grant, grant_before)
        self.assertEqual(self.dispatch, dispatch_before)


    def test_identity_length_boundary(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                max_value = "a" * 128
                self.assertTrue(reference_consistent(
                    replace(self.grant, **{field: max_value}),
                    replace(self.dispatch, **{field: max_value}), HostileHeader()))
                too_long = "a" * 129
                self.assertFalse(reference_consistent(
                    replace(self.grant, **{field: too_long}),
                    replace(self.dispatch, **{field: too_long}), "cors"))

    def test_matching_revision_zero_is_allowed_synthetic_control(self):
        self.assertTrue(reference_consistent(
            replace(self.grant, revision=0),
            replace(self.dispatch, revision=0), "no-cors"))

    def test_missing_binding_denied_on_either_side(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(reference_consistent(
                    replace(self.grant, **{field: None}), self.dispatch, "navigate"))
                self.assertFalse(reference_consistent(
                    self.grant, replace(self.dispatch, **{field: None}), "navigate"))


if __name__ == "__main__":
    unittest.main()
