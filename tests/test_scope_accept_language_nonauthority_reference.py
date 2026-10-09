"""Offline reference: Accept-Language is presentation metadata, never a grant.

Pure stdlib test oracle; not production authorization enforcement.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    request: str
    asset: str
    capability: str
    active: bool
    issuer_verified: bool


def allowed(grant, *, tenant, request, asset, capability, accept_language):
    # No coercion: all authority-bearing identifiers must be exact strings.
    identities = (grant.tenant, grant.request, grant.asset, grant.capability,
                  tenant, request, asset, capability)
    if any(type(x) is not str or not x or x != x.strip() for x in identities):
        return False
    # Header intentionally ignored, including malformed or adversarial content.
    return (type(grant) is Grant and type(grant.active) is bool
            and type(grant.issuer_verified) is bool
            and grant.active and grant.issuer_verified
            and (tenant, request, asset, capability) ==
            (grant.tenant, grant.request, grant.asset, grant.capability))


class ScopeAcceptLanguageNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-1", "request-1", "example.invalid", "headers", True, True)
        self.context = dict(tenant="tenant-1", request="request-1",
                            asset="example.invalid", capability="headers")

    def evaluate(self, grant=None, **overrides):
        args = dict(self.context)
        args.update(overrides)
        return allowed(self.grant if grant is None else grant, **args)

    def test_matching_verified_grant_is_independent_of_header(self):
        for label in ("en-GB", "nl-NL", "admin", "*", "", None, 42,
                      {"role": "root"}, "en-GB\r\nX-Grant: approved"):
            with self.subTest(label=repr(label)):
                self.assertTrue(self.evaluate(accept_language=label))

    def test_inactive_grant_cannot_be_reactivated_by_header(self):
        grant = Grant("tenant-1", "request-1", "example.invalid", "headers", False, True)
        self.assertFalse(self.evaluate(grant, accept_language="admin,approved;q=1"))

    def test_unverified_issuer_cannot_be_repaired_by_header(self):
        grant = Grant("tenant-1", "request-1", "example.invalid", "headers", True, False)
        self.assertFalse(self.evaluate(grant, accept_language="grant-valid"))

    def test_cross_tenant_request_asset_capability_denied(self):
        for field in self.context:
            with self.subTest(field=field):
                self.assertFalse(self.evaluate(accept_language="en-GB",
                                               **{field: self.context[field] + "-other"}))

    def test_same_text_polymorphic_identity_is_rejected(self):
        class StringSubclass(str):
            pass
        for field in self.context:
            with self.subTest(field=field):
                self.assertFalse(self.evaluate(accept_language="en-GB",
                                               **{field: StringSubclass(self.context[field])}))

    def test_nonboolean_grant_flags_fail_closed(self):
        for active, verified in ((1, True), (True, 1), ("yes", True), (True, "yes")):
            grant = Grant("tenant-1", "request-1", "example.invalid", "headers",
                          active, verified)
            self.assertFalse(self.evaluate(grant, accept_language="en-GB"))

    def test_header_object_is_not_inspected_or_executed(self):
        class HostileHeader:
            def __str__(self):
                raise AssertionError("header unexpectedly converted")
            def __bool__(self):
                raise AssertionError("header unexpectedly evaluated")
        self.assertTrue(self.evaluate(accept_language=HostileHeader()))


if __name__ == "__main__":
    unittest.main()
