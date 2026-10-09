"""Offline reference: Content-Disposition is not authorization provenance.

Synthetic fixtures only. This never authorizes target execution.
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str = "tenant-a"
    request: str = "request-a"
    asset: str = "asset-a"
    capability: str = "read-headers"
    revision: int = 7
    active: bool = True
    issuer_verified: bool = True


@dataclass(frozen=True)
class Dispatch:
    tenant: str = "tenant-a"
    request: str = "request-a"
    asset: str = "asset-a"
    capability: str = "read-headers"
    revision: int = 7


def valid_identifier(value):
    return (
        type(value) is str
        and 0 < len(value) <= 128
        and all(ch.isascii() and (ch.isalnum() or ch in "-_.") for ch in value)
    )


def reference_consistency(grant, dispatch, content_disposition=None):
    """Necessary synthetic consistency only; never sufficient for permission."""
    if type(grant) is not Grant or type(dispatch) is not Dispatch:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.issuer_verified) is not bool or grant.issuer_verified is not True:
        return False
    if type(grant.revision) is not int or type(dispatch.revision) is not int:
        return False
    if grant.revision < 0 or grant.revision != dispatch.revision:
        return False
    for field in ("tenant", "request", "asset", "capability"):
        left, right = getattr(grant, field), getattr(dispatch, field)
        if not valid_identifier(left) or not valid_identifier(right) or left != right:
            return False
    # Do not even inspect this untrusted presentation header.
    return True


class TestContentDispositionNonAuthority(unittest.TestCase):
    def setUp(self):
        self.grant = Grant()
        self.dispatch = Dispatch()

    def test_matching_synthetic_reference(self):
        self.assertTrue(reference_consistency(self.grant, self.dispatch))

    def test_header_variations_do_not_mint_authority(self):
        for value in (
            'attachment; filename="approved.pdf"',
            "inline",
            "attachment; filename*=UTF-8''admin-approved",
            "attachment; name=grant; filename=allow",
            "attachment; filename=\"../scope.json\"",
            "\r\nX-Authorization: approved",
            None,
            42,
            {"filename": "approved"},
        ):
            with self.subTest(value=value):
                self.assertTrue(reference_consistency(self.grant, self.dispatch, value))
                self.assertFalse(reference_consistency(replace(self.grant, active=False), self.dispatch, value))

    def test_unverified_and_revoked_fail_closed(self):
        for change in ({"active": False}, {"issuer_verified": False}, {"active": 1}, {"issuer_verified": 1}):
            with self.subTest(change=change):
                self.assertFalse(reference_consistency(replace(self.grant, **change), self.dispatch, "attachment; filename=approved"))

    def test_identity_swaps_fail_even_with_approved_filename(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(reference_consistency(self.grant, replace(self.dispatch, **{field: "other"}), "attachment; filename=approved"))

    def test_grant_side_identity_swaps_fail(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(reference_consistency(replace(self.grant, **{field: "other"}), self.dispatch, "inline"))

    def test_matching_invalid_identifiers_do_not_authorize(self):
        for value in ("", "contains space", "line\nbreak", "bad\x00id", "é", "a" * 129):
            for field in ("tenant", "request", "asset", "capability"):
                with self.subTest(value=value, field=field):
                    self.assertFalse(reference_consistency(
                        replace(self.grant, **{field: value}),
                        replace(self.dispatch, **{field: value}),
                        'attachment; filename="approved"',
                    ))

    def test_stale_or_malformed_revision_denied(self):
        for value in (True, 7.0, "7", -1):
            with self.subTest(value=value):
                self.assertFalse(reference_consistency(replace(self.grant, revision=value), self.dispatch))
        self.assertFalse(reference_consistency(self.grant, replace(self.dispatch, revision=8)))

    def test_polymorphic_envelopes_denied(self):
        class ForgedGrant(Grant):
            pass
        class ForgedDispatch(Dispatch):
            pass
        self.assertFalse(reference_consistency(ForgedGrant(), self.dispatch))
        self.assertFalse(reference_consistency(self.grant, ForgedDispatch()))

    def test_hostile_header_object_is_never_evaluated(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("header string conversion")
            def __bool__(self):
                raise AssertionError("header truth check")
            def __eq__(self, _):
                raise AssertionError("header equality")
        header = Hostile()
        self.assertTrue(reference_consistency(self.grant, self.dispatch, header))
        self.assertFalse(reference_consistency(replace(self.grant, active=False), self.dispatch, header))

    def test_grant_and_dispatch_immutable(self):
        grant, dispatch = self.grant, self.dispatch
        reference_consistency(grant, dispatch, "attachment; filename=ignored")
        self.assertEqual(grant, self.grant)
        self.assertEqual(dispatch, self.dispatch)


if __name__ == "__main__":
    unittest.main()
