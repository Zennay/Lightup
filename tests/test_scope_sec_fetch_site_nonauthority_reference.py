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


if __name__ == "__main__":
    unittest.main()
