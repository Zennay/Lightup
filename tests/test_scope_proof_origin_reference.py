"""Offline reference: evidence origin cannot be substituted for authorization.

This is a contract fixture, not the production permission engine.
No network, filesystem access, or target interaction.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class DecisionInput:
    tenant: str
    request: str
    issuer: str
    authorization_ref: str
    proof_origin: str
    proof_tenant: str
    proof_request: str
    proof_issuer: str
    proof_authorization_ref: str
    proof_approved: bool


def eligible(x: DecisionInput) -> bool:
    if type(x) is not DecisionInput:
        return False
    fields = (
        x.tenant, x.request, x.issuer, x.authorization_ref,
        x.proof_origin, x.proof_tenant, x.proof_request,
        x.proof_issuer, x.proof_authorization_ref,
    )
    if any(
        type(v) is not str
        or not v
        or len(v) > 128
        or v != v.strip()
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in v)
        for v in fields
    ):
        return False
    if x.proof_origin != "trusted_authorization_register":
        return False
    if x.proof_approved is not True:
        return False
    return (
        x.tenant == x.proof_tenant
        and x.request == x.proof_request
        and x.issuer == x.proof_issuer
        and x.authorization_ref == x.proof_authorization_ref
    )


class ProofOriginReferenceTests(unittest.TestCase):
    def setUp(self):
        self.good = DecisionInput(
            "tenant-A", "request-1", "issuer-1", "grant-1",
            "trusted_authorization_register", "tenant-A", "request-1",
            "issuer-1", "grant-1", True
        )

    def test_exact_reference_case_only(self):
        self.assertTrue(eligible(self.good))

    def test_untrusted_proof_origins_cannot_authorize(self):
        from dataclasses import replace
        for origin in ("report", "scanner", "lab_fixture", "client_upload", "", "TRUSTED_AUTHORIZATION_REGISTER"):
            with self.subTest(origin=origin):
                self.assertFalse(eligible(replace(self.good, proof_origin="trusted_authorization_register\n")))

    def test_subclass_is_not_a_trusted_envelope(self):
        class Derived(DecisionInput):
            pass
        self.assertFalse(eligible(Derived(**vars(self.good))))


if __name__ == "__main__":
    unittest.main()
