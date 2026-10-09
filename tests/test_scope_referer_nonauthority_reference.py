"""Offline contract: HTTP Referer is not authorization provenance.

This synthetic decision oracle is NOT production ToolExecutor enforcement.
No network, target I/O, grant issuance or active capability execution.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    tenant: str
    request: str
    asset: str
    capability: str
    approved: bool = True
    active: bool = True
    issuer_verified: bool = True


@dataclass(frozen=True)
class Call:
    tenant: str
    request: str
    asset: str
    capability: str
    referer: object = None


def permitted(grant, call):
    # Referer is deliberately never consulted.
    if type(grant) is not Grant or type(call) is not Call:
        return False
    if not all(type(getattr(grant, key)) is str and type(getattr(call, key)) is str
               for key in ("tenant", "request", "asset", "capability")):
        return False
    if not all(getattr(obj, key) and not any(ord(c) < 32 or ord(c) == 127 for c in getattr(obj, key))
               for obj in (grant, call)
               for key in ("tenant", "request", "asset", "capability")):
        return False
    if not all(getattr(grant, flag) is True for flag in
               ("approved", "active", "issuer_verified")):
        return False
    return all(getattr(grant, key) == getattr(call, key)
               for key in ("tenant", "request", "asset", "capability"))


class RefererCannotGrantAuthority(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-a", "req-1", "example.invalid", "http-baseline")
        self.call = Call("tenant-a", "req-1", "example.invalid", "http-baseline")

    def test_canonical_grant_independent_of_referer(self):
        for referer in (None, "", "https://admin.example.invalid/approved",
                        "javascript:approved", object(), {"approved": True},
                        "\r\nX-Approved: true"):
            with self.subTest(referer=repr(referer)):
                self.assertTrue(permitted(self.grant, Call(
                    self.call.tenant, self.call.request, self.call.asset,
                    self.call.capability, referer)))

    def test_denied_grant_cannot_be_revived_by_referer(self):
        for flag in ("approved", "active", "issuer_verified"):
            with self.subTest(flag=flag):
                values = dict(tenant=self.grant.tenant, request=self.grant.request,
                              asset=self.grant.asset, capability=self.grant.capability)
                values.update({flag: False})
                denied = Grant(**values)
                for label in ("https://admin.example.invalid/approved",
                              "https://example.invalid/signed", None):
                    self.assertFalse(permitted(denied, Call(
                        self.call.tenant, self.call.request, self.call.asset,
                        self.call.capability, label)))

    def test_identity_substitutions_denied_even_with_matching_referer(self):
        for field, foreign in (("tenant", "tenant-b"), ("request", "req-2"),
                               ("asset", "other.invalid"), ("capability", "tls-baseline")):
            with self.subTest(field=field):
                values = dict(tenant=self.call.tenant, request=self.call.request,
                              asset=self.call.asset, capability=self.call.capability)
                values[field] = foreign
                self.assertFalse(permitted(self.grant, Call(
                    **values, referer="https://admin.example.invalid/approved")))

    def test_referer_never_repairs_malformed_identity(self):
        for bad in (None, 12, True, ["tenant-a"], {"tenant": "tenant-a"}):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(permitted(
                    self.grant, Call(bad, self.call.request, self.call.asset,
                                     self.call.capability, "https://admin.example.invalid")))

    def test_grant_boolean_metadata_must_be_exact_true(self):
        for flag in ("approved", "active", "issuer_verified"):
            for bad in ("true", 1, [], None):
                with self.subTest(flag=flag, bad=repr(bad)):
                    values = dict(tenant=self.grant.tenant, request=self.grant.request,
                                  asset=self.grant.asset, capability=self.grant.capability)
                    values[flag] = bad
                    self.assertFalse(permitted(Grant(**values), self.call))


    def test_matching_malformed_grant_and_call_identity_denied(self):
        for field in ("tenant", "request", "asset", "capability"):
            for invalid in (None, 3, True, "", "bad\nvalue", "bad\x7fvalue"):
                with self.subTest(field=field, invalid=repr(invalid)):
                    values = dict(tenant=self.call.tenant, request=self.call.request,
                                  asset=self.call.asset, capability=self.call.capability)
                    values[field] = invalid
                    self.assertFalse(permitted(
                        Grant(**values), Call(**values, referer="https://approved.invalid")))

    def test_polymorphic_identity_string_rejected_on_both_sides(self):
        class SpoofedIdentity(str):
            def __eq__(self, other):
                return True

            __hash__ = str.__hash__

        for field in ("tenant", "request", "asset", "capability"):
            for side in ("grant", "call"):
                with self.subTest(field=field, side=side):
                    values = dict(tenant=self.call.tenant, request=self.call.request,
                                  asset=self.call.asset, capability=self.call.capability)
                    values[field] = SpoofedIdentity("different")
                    if side == "grant":
                        self.assertFalse(permitted(Grant(**values), self.call))
                    else:
                        self.assertFalse(permitted(
                            self.grant, Call(**values, referer="https://approved.invalid")))

    def test_polymorphic_envelope_rejected(self):
        class SpoofedGrant(Grant):
            pass

        class SpoofedCall(Call):
            pass

        self.assertFalse(permitted(SpoofedGrant(**vars(self.grant)), self.call))
        self.assertFalse(permitted(self.grant, SpoofedCall(**vars(self.call))))

    def test_referer_mutation_does_not_change_grant_or_call(self):
        referer = {"headers": ["approved"]}
        call = Call(self.call.tenant, self.call.request, self.call.asset,
                    self.call.capability, referer)
        original_grant = vars(self.grant).copy()
        original_identity = (call.tenant, call.request, call.asset, call.capability)
        self.assertTrue(permitted(self.grant, call))
        referer["headers"].append("revoked")
        self.assertTrue(permitted(self.grant, call))
        self.assertEqual(vars(self.grant), original_grant)
        self.assertEqual((call.tenant, call.request, call.asset, call.capability),
                         original_identity)


if __name__ == "__main__":
    unittest.main()
