"""Offline reference: Fetch Metadata labels are not authorization.

Synthetic pure-stdlib model, deliberately disconnected from production gates.
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
    active: bool
    verified: bool


def reference_decision(grant, dispatch, fetch_site):
    """A browser-origin hint has zero authority, including when malformed."""
    del fetch_site
    if type(grant) is not Grant or type(dispatch) is not dict:
        return False
    if type(grant.active) is not bool or type(grant.verified) is not bool:
        return False
    if not grant.active or not grant.verified:
        return False
    if type(grant.revision) is not int or grant.revision < 0:
        return False
    if set(dispatch) != {"tenant", "request", "asset", "capability", "revision"}:
        return False
    for key in ("tenant", "request", "asset", "capability"):
        actual = getattr(grant, key)
        expected = dispatch[key]
        if type(actual) is not str or type(expected) is not str:
            return False
        if not actual or actual != expected or len(actual) > 128:
            return False
    return type(dispatch["revision"]) is int and dispatch["revision"] == grant.revision


class HostileLabel:
    def __str__(self):
        raise AssertionError("fetch hint must not be parsed")
    def __bool__(self):
        raise AssertionError("fetch hint must not be tested")
    def __getattribute__(self, name):
        raise AssertionError("fetch hint must not be inspected")


class SecFetchSiteNonAuthority(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant", "request", "asset", "web-baseline", 2, True, True)
        self.dispatch = dict(tenant="tenant", request="request", asset="asset",
                             capability="web-baseline", revision=2)

    def test_hint_values_cannot_mint_authority(self):
        for hint in ("same-origin", "same-site", "cross-site", "none", "", None, HostileLabel()):
            with self.subTest(hint=type(hint).__name__):
                self.assertTrue(reference_decision(self.grant, self.dispatch, hint))
                self.assertFalse(reference_decision(
                    Grant("tenant", "request", "asset", "web-baseline", 2, False, True),
                    self.dispatch, hint))
                self.assertFalse(reference_decision(
                    Grant("tenant", "request", "asset", "web-baseline", 2, True, False),
                    self.dispatch, hint))

    def test_cross_binding_rejection(self):
        for key in ("tenant", "request", "asset", "capability"):
            altered = dict(self.dispatch, **{key: "other"})
            for hint in ("same-origin", "none", HostileLabel()):
                with self.subTest(key=key):
                    self.assertFalse(reference_decision(self.grant, altered, hint))

    def test_revision_type_and_generation(self):
        for rev in (True, 2.0, "2", -1, 1, 3, None):
            self.assertFalse(reference_decision(
                self.grant, dict(self.dispatch, revision=rev), "same-origin"))

    def test_malformed_matching_identity_is_rejected(self):
        for value in (None, 7, "", "x" * 129):
            for key in ("tenant", "request", "asset", "capability"):
                grant = Grant(**dict(self.grant.__dict__, **{key: value}))
                dispatch = dict(self.dispatch, **{key: value})
                self.assertFalse(reference_decision(grant, dispatch, "same-origin"))

    def test_flag_type_confusion(self):
        for flag in (1, "true", object()):
            grant = Grant("tenant", "request", "asset", "web-baseline", 2, flag, True)
            self.assertFalse(reference_decision(grant, self.dispatch, "same-origin"))

    def test_polymorphic_envelope_rejected(self):
        class Map(dict):
            pass
        self.assertFalse(reference_decision(self.grant, Map(self.dispatch), "same-origin"))

    def test_no_input_mutation(self):
        before = self.dispatch.copy()
        self.assertTrue(reference_decision(self.grant, self.dispatch, HostileLabel()))
        self.assertEqual(before, self.dispatch)


    def test_grant_revision_must_be_exact_nonnegative_integer(self):
        for revision in (True, 2.0, "2", -1, None):
            grant = Grant("tenant", "request", "asset", "web-baseline",
                          revision, True, True)
            self.assertFalse(reference_decision(grant, self.dispatch, "same-origin"))
        zero = Grant("tenant", "request", "asset", "web-baseline", 0, True, True)
        self.assertTrue(reference_decision(
            zero, dict(self.dispatch, revision=0), "cross-site"))

    def test_missing_and_extra_binding_keys_fail_closed(self):
        for key in self.dispatch:
            missing = dict(self.dispatch)
            del missing[key]
            self.assertFalse(reference_decision(self.grant, missing, "none"))
        self.assertFalse(reference_decision(
            self.grant, dict(self.dispatch, injected=True), "same-origin"))

    def test_string_subclass_identity_is_not_trusted(self):
        class PretendString(str):
            pass
        for key in ("tenant", "request", "asset", "capability"):
            spoof = PretendString(self.dispatch[key])
            self.assertFalse(reference_decision(
                self.grant, dict(self.dispatch, **{key: spoof}), "same-site"))
            self.assertFalse(reference_decision(
                Grant(**dict(self.grant.__dict__, **{key: spoof})),
                self.dispatch, "same-origin"))

    def test_verified_flag_requires_exact_boolean(self):
        for flag in (1, "true", object()):
            grant = Grant("tenant", "request", "asset", "web-baseline", 2, True, flag)
            self.assertFalse(reference_decision(grant, self.dispatch, "same-origin"))


    def test_grant_subclass_is_not_trusted(self):
        class DerivedGrant(Grant):
            pass
        grant = DerivedGrant("tenant", "request", "asset", "web-baseline",
                             2, True, True)
        self.assertFalse(reference_decision(grant, self.dispatch, "same-origin"))

    def test_matching_identity_length_boundaries(self):
        for key in ("tenant", "request", "asset", "capability"):
            valid = "a" * 128
            grant = Grant(**dict(self.grant.__dict__, **{key: valid}))
            dispatch = dict(self.dispatch, **{key: valid})
            self.assertTrue(reference_decision(grant, dispatch, HostileLabel()))
            invalid = "a" * 129
            grant = Grant(**dict(self.grant.__dict__, **{key: invalid}))
            dispatch = dict(self.dispatch, **{key: invalid})
            self.assertFalse(reference_decision(grant, dispatch, HostileLabel()))

    def test_nonmatching_missing_identity_is_denied(self):
        for key in ("tenant", "request", "asset", "capability"):
            grant = Grant(**dict(self.grant.__dict__, **{key: None}))
            self.assertFalse(reference_decision(grant, self.dispatch, "same-origin"))
            dispatch = dict(self.dispatch, **{key: None})
            self.assertFalse(reference_decision(self.grant, dispatch, "same-origin"))

    def test_hostile_label_does_not_change_revision_decision(self):
        for revision in (0, 2, 3):
            grant = Grant("tenant", "request", "asset", "web-baseline",
                          revision, True, True)
            for hint in ("same-origin", "cross-site", HostileLabel()):
                self.assertEqual(
                    reference_decision(grant, self.dispatch, None),
                    reference_decision(grant, self.dispatch, hint))


    def test_metadata_object_protocols_are_never_invoked(self):
        class PoisonMetadata:
            def __iter__(self):
                raise AssertionError("transport hint iteration")
            def __len__(self):
                raise AssertionError("transport hint length")
            def __repr__(self):
                raise AssertionError("transport hint representation")
            def __eq__(self, other):
                raise AssertionError("transport hint comparison")
        hint = PoisonMetadata()
        self.assertTrue(reference_decision(self.grant, self.dispatch, hint))
        revoked = Grant("tenant", "request", "asset", "web-baseline", 2, False, True)
        self.assertFalse(reference_decision(revoked, self.dispatch, hint))

    def test_dispatch_revision_subclass_fails_closed(self):
        class PretendInt(int):
            pass
        self.assertFalse(reference_decision(
            self.grant, dict(self.dispatch, revision=PretendInt(2)), "none"))
        grant = Grant("tenant", "request", "asset", "web-baseline",
                      PretendInt(2), True, True)
        self.assertFalse(reference_decision(grant, self.dispatch, "none"))

    def test_untrusted_hint_never_changes_immutable_grant(self):
        before = dict(self.grant.__dict__)
        for hint in ("same-site", {"Sec-Fetch-Site": "same-origin"}, HostileLabel()):
            self.assertTrue(reference_decision(self.grant, self.dispatch, hint))
            self.assertEqual(dict(self.grant.__dict__), before)

if __name__ == "__main__":
    unittest.main()
