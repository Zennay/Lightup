"""Offline reference: a credential fingerprint is not scope authority.

Pure stdlib fixtures. No secret, network, DNS, target or production executor.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class IssuerGrant:
    tenant: str
    request: str
    revision: int
    capability: str
    active: bool


@dataclass(frozen=True)
class Request:
    tenant: str
    request: str
    revision: int
    capability: str
    credential_fingerprint: str


def conditionally_consistent(grant: object, request: object) -> bool:
    """Necessary comparison only; never a production authorization decision."""
    if type(grant) is not IssuerGrant or type(request) is not Request:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.revision) is not int or type(request.revision) is not int:
        return False
    if not 1 <= grant.revision <= 2**63 - 1:
        return False
    if not 1 <= request.revision <= 2**63 - 1:
        return False
    for name in ("tenant", "request", "capability"):
        left, right = getattr(grant, name), getattr(request, name)
        if type(left) is not str or type(right) is not str:
            return False
        if not 1 <= len(left) <= 128 or any(not ("a" <= c <= "z" or "A" <= c <= "Z" or "0" <= c <= "9" or c in "-_.") for c in left):
            return False
        if left != right:
            return False
    if type(request.credential_fingerprint) is not str:
        return False
    # An attacker-controlled digest/label is never consulted in the eligibility
    # comparison; a credential check belongs at an independently trusted boundary.
    return grant.revision == request.revision


class CredentialFingerprintNonAuthorityReference(unittest.TestCase):
    def setUp(self):
        self.grant = IssuerGrant("tenant-1", "assessment-3", 2, "http-head", True)
        self.call = Request("tenant-1", "assessment-3", 2, "http-head", "sha256:fake")

    def test_matching_claims_are_only_conditionally_consistent(self):
        self.assertTrue(conditionally_consistent(self.grant, self.call))

    def test_fingerprint_mutation_cannot_change_scope_consistency(self):
        for fingerprint in ("", "sha256:fake", "admin", "revoked", "0" * 64, "a\nadmin"):
            self.assertEqual(
                conditionally_consistent(self.grant, self.call),
                conditionally_consistent(self.grant, Request("tenant-1", "assessment-3", 2, "http-head", fingerprint)),
            )

    def test_fingerprint_cannot_override_tenant_mismatch(self):
        self.assertFalse(conditionally_consistent(self.grant, Request("tenant-2", "assessment-3", 2, "http-head", "trusted")))

    def test_fingerprint_cannot_override_request_mismatch(self):
        self.assertFalse(conditionally_consistent(self.grant, Request("tenant-1", "assessment-4", 2, "http-head", "trusted")))

    def test_fingerprint_cannot_override_revision_mismatch(self):
        self.assertFalse(conditionally_consistent(self.grant, Request("tenant-1", "assessment-3", 3, "http-head", "trusted")))

    def test_fingerprint_cannot_override_capability_mismatch(self):
        self.assertFalse(conditionally_consistent(self.grant, Request("tenant-1", "assessment-3", 2, "tcp-connect", "trusted")))

    def test_fingerprint_cannot_override_revocation(self):
        revoked = IssuerGrant("tenant-1", "assessment-3", 2, "http-head", False)
        self.assertFalse(conditionally_consistent(revoked, self.call))

    def test_truthy_active_does_not_pass(self):
        self.assertFalse(conditionally_consistent(IssuerGrant("tenant-1", "assessment-3", 2, "http-head", "true"), self.call))

    def test_invalid_revision_types_denied(self):
        for value in (True, 2.0, "2", 0, -1, 2**63):
            self.assertFalse(conditionally_consistent(IssuerGrant("tenant-1", "assessment-3", value, "http-head", True), self.call))
            self.assertFalse(conditionally_consistent(self.grant, Request("tenant-1", "assessment-3", value, "http-head", "trusted")))

    def test_malformed_identity_denied_even_if_equal(self):
        for identity in (" tenant", "tenant\n1", "ténant", "", "x" * 129):
            self.assertFalse(conditionally_consistent(IssuerGrant(identity, "assessment-3", 2, "http-head", True), Request(identity, "assessment-3", 2, "http-head", "trusted")))

    def test_polymorphic_grants_denied(self):
        class Forged(IssuerGrant):
            pass
        self.assertFalse(conditionally_consistent(Forged("tenant-1", "assessment-3", 2, "http-head", True), self.call))

    def test_polymorphic_request_denied(self):
        class ForgedRequest(Request):
            pass
        self.assertFalse(conditionally_consistent(
            self.grant, ForgedRequest("tenant-1", "assessment-3", 2, "http-head", "trusted")
        ))

    def test_matched_malformed_capability_denied(self):
        for capability in ("http head", "http\\nhead", "http/head", "é", "", "x" * 129):
            self.assertFalse(conditionally_consistent(
                IssuerGrant("tenant-1", "assessment-3", 2, capability, True),
                Request("tenant-1", "assessment-3", 2, capability, "trusted"),
            ))

    def test_request_and_grant_are_immutable(self):
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            self.grant.active = False
        with self.assertRaises(FrozenInstanceError):
            self.call.credential_fingerprint = "trusted"

    def test_invalid_fingerprint_type_denied(self):
        self.assertFalse(conditionally_consistent(self.grant, Request("tenant-1", "assessment-3", 2, "http-head", None)))


if __name__ == "__main__":
    unittest.main()
