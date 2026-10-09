"""Offline synthetic contract: HTTP 425 Too Early cannot establish scope authorization.

No network, real targets, production executor or authorization state changes.
Passing a synthetic consistency test is NOT authenticated issuer approval.
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Scope:
    tenant: object
    request: object
    asset: object
    capability: object
    revision: object
    active: object


BASE = Scope("tenant-a", "req-a", "asset-a", "headers", 7, True)


def _identifier(value):
    return (type(value) is str and 0 < len(value) <= 128 and value.isascii()
            and all(33 <= ord(char) <= 126 for char in value))


def _revision(value):
    return type(value) is int and value > 0


def necessary_scope_consistency(grant, dispatch, response_status=None, early_data=None):
    """HTTP response / Early-Data hints intentionally have no authorization authority.

    Production must additionally validate issuer provenance, consent, revocation,
    expiry, risk ceilings and active execution enablement at dispatch time.
    """
    if type(grant) is not Scope or type(dispatch) is not Scope:
        return False
    for field in ("tenant", "request", "asset", "capability"):
        a, b = getattr(grant, field), getattr(dispatch, field)
        if not (_identifier(a) and _identifier(b) and a == b):
            return False
    return (_revision(grant.revision) and _revision(dispatch.revision)
            and grant.revision == dispatch.revision
            and type(grant.active) is bool and grant.active is True
            and type(dispatch.active) is bool and dispatch.active is True)


class TooEarlyNonauthorityTests(unittest.TestCase):
    def test_matching_fixture_is_necessary_not_permission(self):
        self.assertTrue(necessary_scope_consistency(BASE, BASE, 425, "1"))

    def test_status_variants_cannot_restore_revoked_state(self):
        for status in (425, 200, 201, 202, 204, 304, 409, 429, "425", None):
            with self.subTest(status=status):
                self.assertFalse(necessary_scope_consistency(replace(BASE, active=False), BASE, status, "1"))
                self.assertFalse(necessary_scope_consistency(BASE, replace(BASE, active=False), status, "1"))

    def test_early_data_variants_never_create_authority(self):
        for hint in ("1", "0", "true", "", None, 1, True, [], {"Early-Data": "1"}):
            with self.subTest(hint=repr(hint)):
                self.assertTrue(necessary_scope_consistency(BASE, BASE, 425, hint))
                self.assertFalse(necessary_scope_consistency(BASE, replace(BASE, active=False), 425, hint))

    def test_cross_context_denied_even_with_425(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(necessary_scope_consistency(BASE, replace(BASE, **{field: "other"}), 425, "1"))
                self.assertFalse(necessary_scope_consistency(replace(BASE, **{field: "other"}), BASE, 425, "1"))

    def test_stale_or_malformed_revisions_denied(self):
        for value in (8, 0, -1, True, 7.0, "7", None):
            with self.subTest(value=repr(value)):
                self.assertFalse(necessary_scope_consistency(BASE, replace(BASE, revision=value), 425, "1"))
                self.assertFalse(necessary_scope_consistency(replace(BASE, revision=value), BASE, 425, "1"))

    def test_matching_invalid_identifiers_denied(self):
        for field in ("tenant", "request", "asset", "capability"):
            for bad in ("", "bad space", "bad\nline", "bad\rline", "bad\x00id", "bad\x7fid", "é"):
                with self.subTest(field=field, bad=repr(bad)):
                    value = replace(BASE, **{field: bad})
                    self.assertFalse(necessary_scope_consistency(value, value, 425, "1"))

    def test_noncanonical_types_denied_even_if_equal(self):
        class StringSubclass(str):
            pass
        for field in ("tenant", "request", "asset", "capability"):
            for value in (StringSubclass(getattr(BASE, field)), 7, None, True):
                with self.subTest(field=field, value=repr(value)):
                    malformed = replace(BASE, **{field: value})
                    self.assertFalse(necessary_scope_consistency(malformed, malformed, 425, "1"))

    def test_truthy_active_values_denied(self):
        for value in (1, "true", [True], None):
            with self.subTest(value=repr(value)):
                self.assertFalse(necessary_scope_consistency(replace(BASE, active=value), BASE, 425, "1"))

    def test_polymorphic_envelopes_denied(self):
        class ScopeSubclass(Scope):
            pass
        forged = ScopeSubclass(**vars(BASE))
        self.assertFalse(necessary_scope_consistency(forged, BASE, 425, "1"))
        self.assertFalse(necessary_scope_consistency(BASE, forged, 425, "1"))

    def test_transport_objects_are_not_inspected(self):
        class Trap:
            def __bool__(self):
                raise AssertionError("Transport metadata inspected")
            def __eq__(self, other):
                raise AssertionError("Transport metadata compared")
            def __str__(self):
                raise AssertionError("Transport metadata rendered")
        denied = replace(BASE, active=False)
        self.assertTrue(necessary_scope_consistency(BASE, BASE, Trap(), Trap()))
        self.assertFalse(necessary_scope_consistency(BASE, denied, Trap(), Trap()))

    def test_immutable_inputs(self):
        before = vars(BASE).copy()
        necessary_scope_consistency(BASE, BASE, 425, "1")
        self.assertEqual(vars(BASE), before)


if __name__ == "__main__":
    unittest.main()
