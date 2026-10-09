"""Offline reference: transport media-type labels cannot establish assessment authority."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    request: str
    revision: int
    capability: str
    active: bool
    issuer_verified: bool


@dataclass(frozen=True)
class Dispatch:
    tenant: str
    request: str
    revision: int
    capability: str


def allowed(grant, dispatch, *, media_type="application/json", declared_charset="utf-8",
            parser_success=True, content_digest_verified=True):
    """Reference consistency only. NEVER authenticates issuer or grants permission."""
    # Content-Type, charset, parser acceptance and digest are deliberately NON-authoritative.
    # The real executor must independently authenticate issuer-owned, current consent.
    if type(grant) is not Grant or type(dispatch) is not Dispatch:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.issuer_verified) is not bool or grant.issuer_verified is not True:
        return False
    if type(grant.revision) is not int or type(dispatch.revision) is not int:
        return False
    if grant.revision < 1 or dispatch.revision < 1:
        return False
    for value in (grant.tenant, dispatch.tenant, grant.request, dispatch.request,
                  grant.capability, dispatch.capability):
        if type(value) is not str or not 1 <= len(value) <= 128:
            return False
        if not all(0x21 <= ord(ch) <= 0x7e for ch in value):
            return False
    return (grant.tenant == dispatch.tenant
            and grant.request == dispatch.request
            and grant.revision == dispatch.revision
            and grant.capability == dispatch.capability)


class MediaTypeNonAuthority(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-a", "request-a", 7, "header-review", True, True)
        self.dispatch = Dispatch("tenant-a", "request-a", 7, "header-review")

    def test_consistent_reference_is_not_real_authorization(self):
        self.assertTrue(allowed(self.grant, self.dispatch))

    def test_media_type_cannot_restore_revocation(self):
        for typ in ("application/json", "application/vnd.lightup.grant+json", "text/plain"):
            with self.subTest(typ=typ):
                revoked = Grant("tenant-a", "request-a", 7, "header-review", False, True)
                self.assertFalse(allowed(revoked, self.dispatch, media_type=typ))

    def test_charset_cannot_restore_unverified_issuer(self):
        for charset in ("utf-8", "UTF-8", "utf-16", "latin-1"):
            self.assertFalse(allowed(Grant("tenant-a", "request-a", 7, "header-review", True, False),
                                     self.dispatch, declared_charset=charset))

    def test_successful_parser_cannot_cross_tenants(self):
        self.assertFalse(allowed(self.grant, Dispatch("tenant-b", "request-a", 7, "header-review"),
                                 parser_success=True))

    def test_valid_digest_cannot_cross_requests(self):
        self.assertFalse(allowed(self.grant, Dispatch("tenant-a", "request-b", 7, "header-review"),
                                 content_digest_verified=True))

    def test_media_type_cannot_override_revision(self):
        self.assertFalse(allowed(self.grant, Dispatch("tenant-a", "request-a", 8, "header-review"),
                                 media_type="application/vnd.lightup.grant+json"))

    def test_content_digest_cannot_expand_capability(self):
        self.assertFalse(allowed(self.grant, Dispatch("tenant-a", "request-a", 7, "service-probe"),
                                 content_digest_verified=True))

    def test_truthy_flags_fail_closed(self):
        for flag in (1, "true", [], object()):
            with self.subTest(flag=repr(flag)):
                self.assertFalse(allowed(Grant("tenant-a", "request-a", 7, "header-review", flag, True),
                                         self.dispatch))
                self.assertFalse(allowed(Grant("tenant-a", "request-a", 7, "header-review", True, flag),
                                         self.dispatch))

    def test_bool_revision_is_not_integer(self):
        self.assertFalse(allowed(Grant("tenant-a", "request-a", True, "header-review", True, True),
                                 self.dispatch))

    def test_control_and_whitespace_identities_fail_even_if_matching(self):
        for bad in (" tenant-a", "tenant-a ", "tenant\n-a", "tenant\x00-a", "ténant-a", "tenant\x7f"):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(allowed(Grant(bad, "request-a", 7, "header-review", True, True),
                                         Dispatch(bad, "request-a", 7, "header-review")))

    def test_forged_envelope_fails(self):
        self.assertFalse(allowed(vars(self.grant), self.dispatch))
        class SubGrant(Grant):
            pass
        self.assertFalse(allowed(SubGrant(**vars(self.grant)), self.dispatch))

    def test_missing_or_zero_revision_fails(self):
        self.assertFalse(allowed(Grant("tenant-a", "request-a", 0, "header-review", True, True),
                                 Dispatch("tenant-a", "request-a", 0, "header-review")))

    def test_every_identity_field_rejects_matching_control_bytes(self):
        for field in ("tenant", "request", "capability"):
            for bad in ("valid\\nname", "valid\\rname", "valid\\x00name", "valid\\x7fname"):
                with self.subTest(field=field, bad=repr(bad)):
                    grant = {**vars(self.grant), field: bad}
                    dispatch = {**vars(self.dispatch), field: bad}
                    self.assertFalse(allowed(Grant(**grant), Dispatch(**dispatch)))

    def test_dispatch_revision_type_and_bounds(self):
        for invalid in (True, False, 0, -1, "7", 7.0, None):
            with self.subTest(invalid=repr(invalid)):
                self.assertFalse(allowed(self.grant,
                                         Dispatch("tenant-a", "request-a", invalid, "header-review")))

    def test_grant_revision_type_and_bounds(self):
        for invalid in (False, 0, -1, "7", 7.0, None):
            with self.subTest(invalid=repr(invalid)):
                self.assertFalse(allowed(Grant("tenant-a", "request-a", invalid, "header-review", True, True),
                                         self.dispatch))

    def test_input_records_remain_unchanged(self):
        grant_before, dispatch_before = vars(self.grant).copy(), vars(self.dispatch).copy()
        self.assertTrue(allowed(self.grant, self.dispatch, media_type=object(),
                                parser_success=False, content_digest_verified=False))
        self.assertEqual(vars(self.grant), grant_before)
        self.assertEqual(vars(self.dispatch), dispatch_before)

    def test_transport_claims_do_not_change_validity(self):
        for typ in ("application/json", "text/html", None, object()):
            for parsed in (True, False, "true"):
                with self.subTest(typ=repr(typ), parsed=repr(parsed)):
                    self.assertTrue(allowed(self.grant, self.dispatch,
                                            media_type=typ, parser_success=parsed))


if __name__ == "__main__":
    unittest.main()
