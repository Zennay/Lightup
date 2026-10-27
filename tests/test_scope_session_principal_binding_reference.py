"""Offline reference: session principal cannot substitute for approved operator.

Not a production policy, authenticated session or permission to test targets.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Approval:
    tenant: str
    request: str
    approver: str
    operator: str
    session_principal: str
    revision: int
    active: bool


def exact_id(value):
    return type(value) is str and 0 < len(value) <= 128 and value.isascii() and all(
        c.isalnum() or c in "_-." for c in value
    )


def can_use_approval(approval, *, tenant, request, operator, session_principal, revision):
    if type(approval) is not Approval or type(approval.active) is not bool or approval.active is not True:
        return False
    if type(approval.revision) is not int or type(revision) is not int or approval.revision < 1:
        return False
    fields = (approval.tenant, approval.request, approval.approver, approval.operator,
              approval.session_principal, tenant, request, operator, session_principal)
    if not all(exact_id(field) for field in fields):
        return False
    return (
        approval.tenant == tenant
        and approval.request == request
        and approval.operator == operator
        and approval.session_principal == session_principal
        and approval.revision == revision
        and approval.approver != approval.operator
        and approval.approver != approval.session_principal
        and approval.operator == approval.session_principal
    )


class SessionPrincipalBindingTests(unittest.TestCase):
    def setUp(self):
        self.approval = Approval("tenant_a", "request_a", "reviewer_a",
                                 "operator_a", "operator_a", 3, True)
        self.context = dict(tenant="tenant_a", request="request_a",
                            operator="operator_a", session_principal="operator_a", revision=3)

    def test_valid_exact_context_is_conditional_reference_only(self):
        self.assertTrue(can_use_approval(self.approval, **self.context))

    def test_swapped_session_is_denied(self):
        self.assertFalse(can_use_approval(self.approval, **{**self.context, "session_principal": "operator_b"}))

    def test_swapped_operator_is_denied(self):
        self.assertFalse(can_use_approval(self.approval, **{**self.context, "operator": "operator_b"}))

    def test_cross_tenant_or_request_is_denied(self):
        for key in ("tenant", "request"):
            with self.subTest(key=key):
                self.assertFalse(can_use_approval(self.approval, **{**self.context, key: "other"}))

    def test_revision_and_inactive_denied(self):
        self.assertFalse(can_use_approval(self.approval, **{**self.context, "revision": 4}))
        self.assertFalse(can_use_approval(Approval(**{**self.approval.__dict__, "active": False}), **self.context))
        self.assertFalse(can_use_approval(Approval(**{**self.approval.__dict__, "active": "true"}), **self.context))

    def test_self_approval_is_denied(self):
        bad = Approval(**{**self.approval.__dict__, "approver": "operator_a"})
        self.assertFalse(can_use_approval(bad, **self.context))

    def test_session_approver_mismatch_denied(self):
        bad = Approval(**{**self.approval.__dict__, "session_principal": "reviewer_a"})
        self.assertFalse(can_use_approval(bad, **self.context))

    def test_invalid_principal_types_and_control_characters_denied(self):
        for value in (True, 0, None, "", " operator_a", "operator_a\n", "opérator", "operator_a/other"):
            with self.subTest(value=value):
                self.assertFalse(can_use_approval(self.approval, **{**self.context, "session_principal": value}))

    def test_polymorphic_approval_denied(self):
        class Forged(Approval):
            pass
        self.assertFalse(can_use_approval(Forged(**self.approval.__dict__), **self.context))


    def test_approval_side_identity_is_also_validated(self):
        for field in ("tenant", "request", "approver", "operator", "session_principal"):
            for invalid in (None, True, "", "bad\\nvalue", "with space", "é", "x" * 129):
                with self.subTest(field=field, invalid=invalid):
                    candidate = Approval(**{**self.approval.__dict__, field: invalid})
                    self.assertFalse(can_use_approval(candidate, **self.context))

    def test_boolean_and_foreign_revision_values_are_denied(self):
        for revision in (True, False, 3.0, "3", None, 0, -1):
            with self.subTest(revision=revision):
                self.assertFalse(can_use_approval(self.approval, **{**self.context, "revision": revision}))
                candidate = Approval(**{**self.approval.__dict__, "revision": revision})
                self.assertFalse(can_use_approval(candidate, **self.context))

    def test_session_and_operator_divergence_cannot_be_approved(self):
        candidate = Approval(**{**self.approval.__dict__, "session_principal": "operator_b"})
        context = {**self.context, "session_principal": "operator_b"}
        self.assertFalse(can_use_approval(candidate, **context))

    def test_inputs_remain_unchanged(self):
        before = self.approval
        context = self.context.copy()
        can_use_approval(self.approval, **self.context)
        self.assertEqual(self.approval, before)
        self.assertEqual(self.context, context)


if __name__ == "__main__":
    unittest.main()
