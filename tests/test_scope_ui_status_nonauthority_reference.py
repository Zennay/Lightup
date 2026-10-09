"""Offline reference: UI approval status is never executable authority.

This is an intentionally isolated reference model, not a production gate.
No sockets, persistence, targets, grants or capabilities are touched.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class DisplayState:
    label: str
    color: str
    approved: bool
    authorization_ref: str


@dataclass(frozen=True)
class TrustedDecision:
    tenant_id: str
    request_id: str
    revision: int
    capability: str
    active: bool
    issuer_verified: bool


def reference_eligible(tenant_id, request_id, revision, capability, trusted_decision, display):
    """Fail closed on untrusted view metadata and malformed issuer decision."""
    # The view is intentionally not inspected: it is presentation-only.
    del display
    if not all(type(v) is str and bool(v) for v in (tenant_id, request_id, capability)):
        return False
    if type(revision) is not int or revision < 1:
        return False
    if type(trusted_decision) is not TrustedDecision:
        return False
    d = trusted_decision
    return (
        type(d.tenant_id) is str and d.tenant_id == tenant_id
        and type(d.request_id) is str and d.request_id == request_id
        and type(d.revision) is int and d.revision == revision
        and type(d.capability) is str and d.capability == capability
        and type(d.active) is bool and d.active is True
        and type(d.issuer_verified) is bool and d.issuer_verified is True
    )


class ScopeUiStatusNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.args = ("tenant-a", "request-a", 3, "web-baseline")
        self.issued = TrustedDecision("tenant-a", "request-a", 3, "web-baseline", True, True)
        self.green = DisplayState("Approved", "green", True, "grant-a")

    def eligible(self, decision=None, display=None):
        return reference_eligible(*self.args, self.issued if decision is None else decision,
                                  self.green if display is None else display)

    def test_valid_issuer_decision_remains_eligible_with_neutral_view(self):
        self.assertTrue(self.eligible(display=None))

    def test_green_badge_cannot_invent_missing_decision(self):
        self.assertFalse(self.eligible(decision=False))

    def test_green_badge_cannot_override_revocation(self):
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-a", "request-a", 3, "web-baseline", False, True)))

    def test_green_badge_cannot_override_unverified_issuer(self):
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-a", "request-a", 3, "web-baseline", True, False)))

    def test_view_reference_cannot_redirect_to_other_tenant(self):
        forged = DisplayState("Approved", "green", True, "tenant-b/grant-b")
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-b", "request-a", 3, "web-baseline", True, True), display=forged))

    def test_stale_revision_not_reauthorized_by_badge(self):
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-a", "request-a", 2, "web-baseline", True, True)))

    def test_changed_capability_not_reauthorized_by_badge(self):
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-a", "request-a", 3, "host-inventory", True, True)))

    def test_truthy_issuer_fields_fail_closed(self):
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-a", "request-a", 3, "web-baseline", 1, True)))
        self.assertFalse(self.eligible(decision=TrustedDecision(
            "tenant-a", "request-a", 3, "web-baseline", True, "yes")))

    def test_subclass_envelopes_do_not_inherit_authority(self):
        class SubclassDecision(TrustedDecision):
            pass
        self.assertFalse(self.eligible(decision=SubclassDecision(
            "tenant-a", "request-a", 3, "web-baseline", True, True)))

    def test_hostile_presentation_objects_are_not_evaluated(self):
        class HostilePresentation:
            def __getattribute__(self, name):
                raise AssertionError("view metadata is not authority")
            def __bool__(self):
                raise AssertionError("view metadata must not be consulted")
        self.assertTrue(self.eligible(display=HostilePresentation()))
        self.assertFalse(self.eligible(decision=False, display=HostilePresentation()))

    def test_inputs_are_not_mutated(self):
        before = repr(self.issued), repr(self.green)
        self.assertTrue(self.eligible())
        self.assertEqual(before, (repr(self.issued), repr(self.green)))


if __name__ == "__main__":
    unittest.main()
