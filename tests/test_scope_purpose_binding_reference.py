"""Offline reference: authorization grants cannot silently cross assessment purposes.

This reference deliberately does not import the production executor and cannot
issue a grant or permit target interaction.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class PurposeGrant:
    tenant_id: str
    request_id: str
    purpose: str
    active: bool


_ALLOWED_PURPOSES = frozenset(("current-assessment", "future-simulation", "lab-evaluation"))


def purpose_eligible(grant: object, *, tenant_id: object, request_id: object, purpose: object) -> bool:
    """Return conditional reference eligibility, never executable authority."""
    if type(grant) is not PurposeGrant:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    for value in (grant.tenant_id, grant.request_id, grant.purpose, tenant_id, request_id, purpose):
        if type(value) is not str or not value or len(value) > 128:
            return False
        if value != value.strip() or not value.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in value):
            return False
    return (
        grant.purpose in _ALLOWED_PURPOSES
        and grant.tenant_id == tenant_id
        and grant.request_id == request_id
        and grant.purpose == purpose
    )


class PurposeBindingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = PurposeGrant("tenant-1", "request-1", "current-assessment", True)

    def check(self, grant=None, **changes):
        inputs = dict(tenant_id="tenant-1", request_id="request-1", purpose="current-assessment")
        inputs.update(changes)
        return purpose_eligible(self.grant if grant is None else grant, **inputs)

    def test_exact_current_assessment_is_conditionally_eligible(self):
        self.assertTrue(self.check())

    def test_cross_purpose_simulation_is_denied(self):
        self.assertFalse(self.check(purpose="future-simulation"))
        self.assertFalse(self.check(purpose="lab-evaluation"))

    def test_future_simulation_cannot_be_used_for_current_assessment(self):
        grant = PurposeGrant("tenant-1", "request-1", "future-simulation", True)
        self.assertFalse(self.check(grant))
        self.assertTrue(self.check(grant, purpose="future-simulation"))

    def test_lab_evaluation_never_authorizes_current_or_future(self):
        grant = PurposeGrant("tenant-1", "request-1", "lab-evaluation", True)
        self.assertTrue(self.check(grant, purpose="lab-evaluation"))
        self.assertFalse(self.check(grant, purpose="current-assessment"))
        self.assertFalse(self.check(grant, purpose="future-simulation"))

    def test_malformed_grant_identity_never_mints_eligibility(self):
        for tenant_id, request_id in (
            ("tenant-1 ", "request-1"),
            ("tenant-1", "request-1\\n"),
            ("tenant-1", "request-1\\x00"),
            ("", "request-1"),
            ("tenant-1", ""),
            ("x" * 129, "request-1"),
            (1, "request-1"),
            ("tenant-1", None),
        ):
            with self.subTest(tenant_id=tenant_id, request_id=request_id):
                grant = PurposeGrant(tenant_id, request_id, "current-assessment", True)
                self.assertFalse(self.check(grant))

    def test_cross_tenant_and_request_are_denied(self):
        self.assertFalse(self.check(tenant_id="tenant-2"))
        self.assertFalse(self.check(request_id="request-2"))

    def test_unknown_or_unbounded_purpose_is_denied(self):
        for purpose in ("", "any", "*", "passive-discovery", "current-assessment ", "CURRENT-ASSESSMENT", "x" * 129):
            with self.subTest(purpose=purpose):
                self.assertFalse(self.check(purpose=purpose))

    def test_malformed_grant_purpose_is_denied(self):
        for value in ("*", "future-simulation\n", "current-assessment\x7f", "", "x" * 129):
            with self.subTest(value=value):
                self.assertFalse(self.check(PurposeGrant("tenant-1", "request-1", value, True)))

    def test_truthy_active_and_non_string_fields_are_denied(self):
        self.assertFalse(self.check(PurposeGrant("tenant-1", "request-1", "current-assessment", 1)))
        self.assertFalse(self.check(PurposeGrant("tenant-1", "request-1", "current-assessment", "yes")))
        self.assertFalse(self.check(purpose=1))
        self.assertFalse(self.check(tenant_id=1))
        self.assertFalse(self.check(request_id=None))

    def test_polymorphic_grant_is_denied(self):
        class ForgedGrant(PurposeGrant):
            pass
        self.assertFalse(self.check(ForgedGrant("tenant-1", "request-1", "current-assessment", True)))

    def test_inactive_grant_is_denied(self):
        self.assertFalse(self.check(PurposeGrant("tenant-1", "request-1", "current-assessment", False)))

    def test_unicode_identity_confusables_fail_closed(self):
        for value in ("current-assessment\u200b", "current‐assessment", "tenant－1"):
            with self.subTest(value=value):
                self.assertFalse(self.check(purpose=value))
                self.assertFalse(self.check(PurposeGrant("tenant-1", "request-1", value, True)))
        self.assertFalse(self.check(tenant_id="tenant\u200b-1"))
        self.assertFalse(self.check(request_id="request\u200b-1"))

    def test_unicode_grant_identities_fail_closed(self):
        self.assertFalse(self.check(PurposeGrant("tenant\u200b-1", "request-1", "current-assessment", True)))
        self.assertFalse(self.check(PurposeGrant("tenant-1", "request\u200b-1", "current-assessment", True)))

    def test_input_is_unchanged(self):
        before = repr(self.grant)
        self.assertFalse(self.check(purpose="future-simulation"))
        self.assertEqual(repr(self.grant), before)


if __name__ == "__main__":
    unittest.main()
