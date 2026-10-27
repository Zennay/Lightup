"""Offline *reference* for independent scope-approval identity; not production authorization."""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class Approval:
    tenant: str
    request_id: str
    revision: int
    requester: str
    approver: str
    active: bool


def independently_approved(request_tenant, request_id, request_revision, requester, approval):
    """Conditional eligibility only: cannot establish trusted issuer/provenance."""
    if type(approval) is not Approval:
        return False
    fields = (request_tenant, request_id, requester, approval.tenant,
              approval.request_id, approval.requester, approval.approver)
    if any(type(value) is not str or not value or len(value) > 128 or
           value != value.strip() for value in fields):
        return False
    if type(request_revision) is not int or request_revision < 1:
        return False
    if type(approval.revision) is not int or approval.revision < 1:
        return False
    if type(approval.active) is not bool or not approval.active:
        return False
    return (approval.tenant == request_tenant
            and approval.request_id == request_id
            and approval.revision == request_revision
            and approval.requester == requester
            and approval.approver != requester)


class ApprovalSeparationReferenceTests(unittest.TestCase):
    def setUp(self):
        self.approval = Approval("tenant-a", "req-1", 2, "alice", "bob")

    def check(self, approval=None, **overrides):
        request = dict(request_tenant="tenant-a", request_id="req-1",
                       request_revision=2, requester="alice")
        request.update(overrides)
        return independently_approved(**request, approval=self.approval if approval is None else approval)

    def test_positive_is_only_conditional(self):
        self.assertTrue(self.check())

    def test_self_approval_denied(self):
        self.assertFalse(self.check(dataclasses.replace(self.approval, approver="alice")))

    def test_cross_tenant_denied(self):
        self.assertFalse(self.check(request_tenant="tenant-b"))

    def test_cross_request_denied(self):
        self.assertFalse(self.check(request_id="req-2"))

    def test_stale_revision_denied(self):
        self.assertFalse(self.check(request_revision=3))

    def test_requester_substitution_denied(self):
        self.assertFalse(self.check(requester="carol"))

    def test_inactive_and_truthy_flags_denied(self):
        for active in (False, 1, "yes", None):
            with self.subTest(active=active):
                self.assertFalse(self.check(dataclasses.replace(self.approval, active=active)))

    def test_boolean_or_invalid_revision_denied(self):
        for revision in (True, 0, -1, 2.0, "2"):
            with self.subTest(revision=revision):
                self.assertFalse(self.check(request_revision=revision))
                self.assertFalse(self.check(dataclasses.replace(self.approval, revision=revision)))

    def test_noncanonical_identity_denied(self):
        for identity in ("", " alice", "alice ", "x" * 129, 123, None):
            with self.subTest(identity=identity):
                self.assertFalse(self.check(dataclasses.replace(self.approval, approver=identity)))

    def test_subclass_and_duck_approval_denied(self):
        class SubApproval(Approval):
            pass
        self.assertFalse(self.check(SubApproval("tenant-a", "req-1", 2, "alice", "bob")))
        self.assertFalse(self.check({"tenant": "tenant-a", "approver": "bob"}))

    def test_inputs_remain_unchanged(self):
        snapshot = dataclasses.asdict(self.approval)
        self.assertTrue(self.check())
        self.assertEqual(dataclasses.asdict(self.approval), snapshot)


if __name__ == "__main__":
    unittest.main()
