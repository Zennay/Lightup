"""Offline reference: HTTP verb permissions never arise from host authorization.

This is deliberately NOT wired to production dispatch. No sockets or targets.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    tenant: str
    asset: str
    methods: frozenset[str]
    active: bool


def eligible(grant, tenant, asset, method):
    """Minimal fail-closed reference model, NOT an issuance/dispatch gate."""
    if type(grant) is not Grant or type(tenant) is not str or type(asset) is not str:
        return False
    if type(method) is not str or method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        return False
    if not grant.active or type(grant.active) is not bool:
        return False
    if type(grant.tenant) is not str or type(grant.asset) is not str:
        return False
    if grant.tenant != tenant or grant.asset != asset:
        return False
    if type(grant.methods) is not frozenset:
        return False
    if any(type(m) is not str or m not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
           for m in grant.methods):
        return False
    return method in grant.methods


class TestMethodCapabilityReference(unittest.TestCase):
    def setUp(self):
        self.g = Grant("tenant-a", "fixture.invalid", frozenset({"GET", "HEAD"}), True)

    def test_explicit_read_methods(self):
        self.assertTrue(eligible(self.g, "tenant-a", "fixture.invalid", "GET"))
        self.assertTrue(eligible(self.g, "tenant-a", "fixture.invalid", "HEAD"))

    def test_host_membership_never_grants_mutation(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertFalse(eligible(self.g, "tenant-a", "fixture.invalid", method))

    def test_method_is_exact_case_sensitive(self):
        for method in ("get", "Get", "GET ", " GET", "", "POST\\n", "G\u200bET"):
            with self.subTest(method=method):
                self.assertFalse(eligible(self.g, "tenant-a", "fixture.invalid", method))

    def test_unknown_and_protocol_upgrade_methods(self):
        for method in ("TRACE", "CONNECT", "OPTIONS", "PROPFIND", "PRI"):
            with self.subTest(method=method):
                self.assertFalse(eligible(self.g, "tenant-a", "fixture.invalid", method))

    def test_cross_tenant_and_asset_replay(self):
        self.assertFalse(eligible(self.g, "tenant-b", "fixture.invalid", "GET"))
        self.assertFalse(eligible(self.g, "tenant-a", "other.invalid", "GET"))

    def test_inactive_and_malformed_active(self):
        for value in (False, 0, 1, None, "true"):
            with self.subTest(value=value):
                self.assertFalse(eligible(Grant("tenant-a", "fixture.invalid", frozenset({"GET"}), value),
                                          "tenant-a", "fixture.invalid", "GET"))

    def test_malformed_methods_fail_closed(self):
        for methods in ({"GET"}, ("GET",), frozenset({"GET", "TRACE"}), frozenset({1}), None):
            with self.subTest(methods=repr(methods)):
                self.assertFalse(eligible(Grant("tenant-a", "fixture.invalid", methods, True),
                                          "tenant-a", "fixture.invalid", "GET"))

    def test_input_type_spoofing(self):
        class Str(str):
            pass
        for tenant, asset, method in ((Str("tenant-a"), "fixture.invalid", "GET"),
                                       ("tenant-a", Str("fixture.invalid"), "GET"),
                                       ("tenant-a", "fixture.invalid", Str("GET")),
                                       ("tenant-a", "fixture.invalid", True)):
            with self.subTest(value=(tenant, asset, method)):
                self.assertFalse(eligible(self.g, tenant, asset, method))

    def test_empty_permissions_never_imply_default_get(self):
        g = Grant("tenant-a", "fixture.invalid", frozenset(), True)
        self.assertFalse(eligible(g, "tenant-a", "fixture.invalid", "GET"))


if __name__ == "__main__":
    unittest.main()
