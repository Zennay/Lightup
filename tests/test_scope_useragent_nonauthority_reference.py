"""Offline reference: transport User-Agent labels cannot confer scope authorization.

Synthetic records only. This is NOT production enforcement or issuer authentication.
Run: python -m unittest tests/test_scope_useragent_nonauthority_reference.py
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    request: str
    asset: str
    capability: str
    active: bool
    issuer_verified: bool


@dataclass(frozen=True)
class Attempt:
    tenant: str
    request: str
    asset: str
    capability: str
    user_agent: str


def permitted(grant: Grant, attempt: Attempt) -> bool:
    """Closed-world synthetic decision; the agent label is never authority."""
    if type(grant) is not Grant or type(attempt) is not Attempt:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.issuer_verified) is not bool or grant.issuer_verified is not True:
        return False
    for name in ("tenant", "request", "asset", "capability"):
        a, b = getattr(grant, name), getattr(attempt, name)
        if type(a) is not str or type(b) is not str:
            return False
        if not a or a.strip() != a or any(ord(c) < 33 or ord(c) > 126 for c in a):
            return False
        if a != b:
            return False
    return True


class UserAgentNonAuthorityReference(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-1", "request-1", "lab-asset-1", "headers", True, True)
        self.attempt = Attempt("tenant-1", "request-1", "lab-asset-1", "headers", "LightUp/1")

    def test_valid_synthetic_control(self):
        self.assertTrue(permitted(self.grant, self.attempt))

    def test_user_agent_cannot_create_missing_grant(self):
        for label in ("LightUp/1", "Approved-Scope/1", "Admin-Authorized/yes", ""):
            with self.subTest(label=label):
                self.assertFalse(permitted(replace(self.grant, active=False), replace(self.attempt, user_agent=label)))

    def test_user_agent_cannot_authenticate_issuer(self):
        self.assertFalse(permitted(replace(self.grant, issuer_verified=False), replace(self.attempt, user_agent="Trusted-Issuer/1")))

    def test_user_agent_cannot_cross_scope_identity(self):
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                self.assertFalse(permitted(self.grant, replace(self.attempt, **{field: "another"} , user_agent="Authorized/true")))

    def test_user_agent_changes_do_not_change_decision(self):
        labels = ("LightUp/1", "curl/8", "admin", "\r\nX-Approved: yes", "\u202eapproved", "A" * 10000)
        for label in labels:
            with self.subTest(label=label[:20]):
                self.assertEqual(permitted(self.grant, self.attempt), permitted(self.grant, replace(self.attempt, user_agent=label)))
                self.assertFalse(permitted(replace(self.grant, active=False), replace(self.attempt, user_agent=label)))

    def test_polymorphic_grant_and_attempt_rejected(self):
        class ForgedGrant(Grant):
            pass
        class ForgedAttempt(Attempt):
            pass
        self.assertFalse(permitted(ForgedGrant(**vars(self.grant)), self.attempt))
        self.assertFalse(permitted(self.grant, ForgedAttempt(**vars(self.attempt))))

    def test_truthy_flags_rejected(self):
        self.assertFalse(permitted(replace(self.grant, active=1), self.attempt))
        self.assertFalse(permitted(replace(self.grant, issuer_verified="yes"), self.attempt))

    def test_reject_invalid_even_when_matching(self):
        for bad in (" tenant-1", "tenant-1 ", "tenant\n1", "ténant-1", ""):
            with self.subTest(bad=bad):
                self.assertFalse(permitted(replace(self.grant, tenant=bad), replace(self.attempt, tenant=bad)))

    def test_all_binding_fields_fail_closed_on_matching_invalid_values(self):
        invalid = ("", " space", "space ", "new\nline", "tab\tname", "café", "a\x7fb")
        for field in ("tenant", "request", "asset", "capability"):
            for bad in invalid:
                with self.subTest(field=field, value=repr(bad)):
                    self.assertFalse(permitted(
                        replace(self.grant, **{field: bad}),
                        replace(self.attempt, **{field: bad}),
                    ))

    def test_all_binding_fields_reject_polymorphic_strings(self):
        class Identity(str):
            pass
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                original = getattr(self.grant, field)
                self.assertFalse(permitted(replace(self.grant, **{field: Identity(original)}), self.attempt))
                self.assertFalse(permitted(self.grant, replace(self.attempt, **{field: Identity(original)})))

    def test_inputs_unchanged(self):
        before = (repr(self.grant), repr(self.attempt))
        permitted(self.grant, self.attempt)
        self.assertEqual(before, (repr(self.grant), repr(self.attempt)))


if __name__ == "__main__":
    unittest.main()
