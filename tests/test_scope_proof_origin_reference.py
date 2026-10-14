"""Pure offline acceptance reference; never grants production authorization."""
import unittest
from dataclasses import dataclass, replace


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
        type(value) is not str
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        for value in fields
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
            "issuer-1", "grant-1", True,
        )

    def test_conditional_positive_fixture(self):
        self.assertTrue(eligible(self.good))

    def test_untrusted_proof_origins(self):
        for origin in ("report", "scanner", "lab_fixture", "client_upload", "",
                       "TRUSTED_AUTHORIZATION_REGISTER"):
            with self.subTest(origin=origin):
                self.assertFalse(eligible(replace(self.good, proof_origin=origin)))

    def test_proof_identity_binding(self):
        for field in ("proof_tenant", "proof_request", "proof_issuer",
                      "proof_authorization_ref"):
            with self.subTest(field=field):
                self.assertFalse(eligible(replace(self.good, **{field: "other"})))

    def test_request_identity_binding(self):
        for field in ("tenant", "request", "issuer", "authorization_ref"):
            with self.subTest(field=field):
                self.assertFalse(eligible(replace(self.good, **{field: "other"})))

    def test_non_boolean_approval(self):
        for value in (1, "yes", [], None, object()):
            with self.subTest(value=repr(value)):
                self.assertFalse(eligible(replace(self.good, proof_approved=value)))

    def test_malformed_identity_types(self):
        for field in ("tenant", "request", "issuer", "authorization_ref",
                      "proof_tenant", "proof_request", "proof_issuer",
                      "proof_authorization_ref", "proof_origin"):
            for value in (None, 7, "", "x" * 129):
                with self.subTest(field=field, value=repr(value)):
                    self.assertFalse(eligible(replace(self.good, **{field: value})))

    def test_control_characters_and_edge_whitespace(self):
        for field in ("tenant", "request", "issuer", "authorization_ref",
                      "proof_tenant", "proof_request", "proof_issuer",
                      "proof_authorization_ref"):
            for value in (" tenant", "tenant ", "tenant" + chr(10) + "other",
                          "tenant" + chr(13) + "other", "tenant" + chr(9) + "other",
                          "tenant" + chr(0) + "other", "tenant" + chr(127) + "other"):
                with self.subTest(field=field, value=repr(value)):
                    self.assertFalse(eligible(replace(self.good, **{field: value})))

    def test_control_character_in_proof_origin(self):
        self.assertFalse(eligible(replace(
            self.good, proof_origin="trusted_authorization_register" + chr(10)
        )))

    def test_subclass_envelope_rejected(self):
        class Derived(DecisionInput):
            pass
        self.assertFalse(eligible(Derived(**vars(self.good))))

    def test_frozen_fixture_remains_unchanged(self):
        before = vars(self.good).copy()
        eligible(self.good)
        self.assertEqual(vars(self.good), before)


if __name__ == "__main__":
    unittest.main()
