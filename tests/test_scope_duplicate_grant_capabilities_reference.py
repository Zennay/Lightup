"""Offline reference: duplicate capability declarations never widen authorization.

This intentionally does NOT import or exercise a production executor.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityGrant:
    tenant: str
    grant_id: str
    capabilities: tuple[str, ...]


def validate_capability_grant(grant: object, registered: frozenset[str]) -> bool:
    """Validate canonical capability *identity*, not issuer provenance."""
    if type(grant) is not CapabilityGrant or type(registered) is not frozenset:
        return False
    if type(grant.tenant) is not str or not grant.tenant or grant.tenant.strip() != grant.tenant:
        return False
    if type(grant.grant_id) is not str or not grant.grant_id or grant.grant_id.strip() != grant.grant_id:
        return False
    if not all(value.isascii() and all(33 <= ord(c) < 127 for c in value)
               for value in (grant.tenant, grant.grant_id)):
        return False
    if type(grant.capabilities) is not tuple or not grant.capabilities:
        return False
    if not all(type(x) is str and x and x == x.strip() and x.isascii()
               and not any(ord(c) < 33 or ord(c) == 127 for c in x)
               for x in grant.capabilities):
        return False
    if len(set(grant.capabilities)) != len(grant.capabilities):
        return False
    if not all(type(x) is str for x in registered):
        return False
    return set(grant.capabilities) <= registered


class DuplicateCapabilityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.registry = frozenset({"http.headers", "tls.baseline"})
        self.base = CapabilityGrant("tenant-1", "grant-1", ("http.headers",))

    def test_canonical_positive_is_only_shape_valid(self):
        self.assertTrue(validate_capability_grant(self.base, self.registry))

    def test_duplicate_capability_denied(self):
        grant = CapabilityGrant("tenant-1", "grant-1", ("http.headers", "http.headers"))
        self.assertFalse(validate_capability_grant(grant, self.registry))

    def test_unregistered_and_wildcard_denied(self):
        for capability in ("*", "http.*", "exec.shell"):
            with self.subTest(capability=capability):
                self.assertFalse(validate_capability_grant(
                    CapabilityGrant("tenant-1", "grant-1", ("http.headers", capability)), self.registry))

    def test_case_and_space_aliases_denied(self):
        for capability in ("HTTP.HEADERS", "http.headers ", " http.headers", "http.headers\n"):
            with self.subTest(capability=capability):
                self.assertFalse(validate_capability_grant(
                    CapabilityGrant("tenant-1", "grant-1", (capability,)), self.registry))

    def test_type_confusion_denied(self):
        for values in (["http.headers"], "http.headers", ("http.headers", 1),
                       ("http.headers", True), ("http.headers", None), (), (b"http.headers",)):
            with self.subTest(values=values):
                self.assertFalse(validate_capability_grant(
                    CapabilityGrant("tenant-1", "grant-1", values), self.registry))

    def test_unicode_and_ascii_controls_denied(self):
        for capability in ("http.headérs", "http.headers\x00", "http.headers\x7f", "http.headers\t"):
            with self.subTest(capability=capability):
                self.assertFalse(validate_capability_grant(
                    CapabilityGrant("tenant-1", "grant-1", (capability,)), self.registry))

    def test_identity_controls_fail_closed(self):
        for tenant, grant_id in (("", "grant-1"), ("tenant-1", ""),
                                 (" tenant-1", "grant-1"),
                                 ("tenant-1", "grant-1\\n"),
                                 ("tenant-1\\x00", "grant-1"),
                                 (True, "grant-1"), ("tenant-1", 7)):
            with self.subTest(tenant=tenant, grant_id=grant_id):
                self.assertFalse(validate_capability_grant(
                    CapabilityGrant(tenant, grant_id, ("http.headers",)), self.registry))

    def test_no_duplicate_normalization_even_with_other_valid_values(self):
        self.assertFalse(validate_capability_grant(
            CapabilityGrant("tenant-1", "grant-1",
                            ("http.headers", "tls.baseline", "http.headers")),
            self.registry))

    def test_duplicate_reject_does_not_mutate_input(self):
        grant = CapabilityGrant("tenant-1", "grant-1", ("http.headers", "http.headers"))
        before = grant.capabilities
        self.assertFalse(validate_capability_grant(grant, self.registry))
        self.assertEqual(grant.capabilities, before)

    def test_subclass_and_noncanonical_registry_rejected(self):
        class Child(CapabilityGrant):
            pass
        self.assertFalse(validate_capability_grant(
            Child("tenant-1", "grant-1", ("http.headers",)), self.registry))
        self.assertFalse(validate_capability_grant(self.base, {"http.headers"}))


if __name__ == "__main__":
    unittest.main()
