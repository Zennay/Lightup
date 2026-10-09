"""Offline reference: authorization evidence must not be silently downgraded.

This is deliberately NOT production approval verification or a dispatch gate.
No network access, target resolution, or external credentials.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Evidence:
    tenant: str
    request: str
    revision: int
    issuer: str
    source: str
    verified: bool
    revoked: bool


TRUSTED_SOURCE = "issuer_authorization_register"


def evidence_satisfies_request(evidence, *, tenant, request, revision, issuer):
    """Fail closed when provenance weakens, even if identity still matches."""
    if type(evidence) is not Evidence:
        return False
    if any(type(value) is not str or not value or not value.isascii()
           or any(ord(char) <= 32 or ord(char) == 127 for char in value)
           for value in (tenant, request, issuer, evidence.tenant,
                         evidence.request, evidence.issuer, evidence.source)):
        return False
    if type(revision) is not int or revision < 1:
        return False
    if type(evidence.revision) is not int or evidence.revision < 1:
        return False
    if type(evidence.verified) is not bool or type(evidence.revoked) is not bool:
        return False
    return (evidence.source == TRUSTED_SOURCE
            and evidence.verified is True
            and evidence.revoked is False
            and evidence.tenant == tenant
            and evidence.request == request
            and evidence.revision == revision
            and evidence.issuer == issuer)


class EvidenceDowngradeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.good = Evidence("tenantA", "req1", 3, "issuerA",
                             TRUSTED_SOURCE, True, False)
        self.claim = dict(tenant="tenantA", request="req1",
                          revision=3, issuer="issuerA")

    def assert_denied(self, **changes):
        data = {**self.good.__dict__, **changes}
        self.assertFalse(evidence_satisfies_request(Evidence(**data), **self.claim))

    def test_exact_identity_conditional_reference(self):
        self.assertTrue(evidence_satisfies_request(self.good, **self.claim))

    def test_report_is_not_an_issuer(self):
        for source in ("scanner_report", "client_attachment", "lab_fixture",
                       "unverified_cache", "trusted_authorization_register_v2"):
            with self.subTest(source=source):
                self.assert_denied(source=source)

    def test_false_and_truthy_verified(self):
        for value in (False, 1, "true", [], None):
            with self.subTest(value=value):
                self.assert_denied(verified=value)

    def test_revocation_and_truthy_flags(self):
        for value in (True, 1, "false", None):
            with self.subTest(value=value):
                self.assert_denied(revoked=value)

    def test_identity_downgrades(self):
        for field, value in (("tenant", "tenantB"), ("request", "req2"),
                             ("issuer", "issuerB"), ("revision", 2),
                             ("revision", True)):
            with self.subTest(field=field, value=value):
                self.assert_denied(**{field: value})

    def test_bad_claim_revision(self):
        for value in (True, 3.0, "3", 0, -1):
            with self.subTest(value=value):
                self.assertFalse(evidence_satisfies_request(
                    self.good, **{**self.claim, "revision": value}))

    def test_control_and_ambiguous_identity(self):
        for value in ("tenantA ", "tenantA\n", "tenantA\x00", "ténantA"):
            with self.subTest(value=value):
                self.assert_denied(tenant=value)

    def test_polymorphic_evidence_rejected(self):
        class ForgedEvidence(Evidence):
            pass
        forged = ForgedEvidence(**self.good.__dict__)
        self.assertFalse(evidence_satisfies_request(forged, **self.claim))

    def test_dict_cannot_impersonate_evidence(self):
        self.assertFalse(evidence_satisfies_request(self.good.__dict__, **self.claim))

    def test_matched_invalid_identity_never_becomes_authority(self):
        for value in ("tenantA ", "tenantA\\n", "tenantA\\x00", "ténantA", ""):
            with self.subTest(value=value):
                bad = Evidence(value, self.good.request, self.good.revision,
                               self.good.issuer, TRUSTED_SOURCE, True, False)
                self.assertFalse(evidence_satisfies_request(
                    bad, **{**self.claim, "tenant": value}))

    def test_exact_string_identity_rejects_polymorphic_values(self):
        class ForgedString(str):
            pass
        for field in ("tenant", "request", "issuer"):
            with self.subTest(field=field):
                self.assertFalse(evidence_satisfies_request(
                    self.good, **{**self.claim, field: ForgedString(self.claim[field])}))
                bad = Evidence(**{**self.good.__dict__,
                                  field: ForgedString(getattr(self.good, field))})
                self.assertFalse(evidence_satisfies_request(bad, **self.claim))

    def test_does_not_mutate_input(self):
        before = self.good
        self.assertTrue(evidence_satisfies_request(self.good, **self.claim))
        self.assertEqual(self.good, before)


if __name__ == "__main__":
    unittest.main()
