"""Offline reference-only scope approval separation-of-duties acceptance checks.

No product imports, network calls, authorization issuers, or target interaction.
"""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class Request:
    tenant: str
    request_id: str
    revision: int
    requester: str
    scope_digest: str
    risk: int


@dataclasses.dataclass(frozen=True)
class Approval:
    tenant: str
    request_id: str
    revision: int
    reviewer: str
    scope_digest: str
    max_risk: int
    active: bool


def is_independent_review(request, approvals, required=1):
    """Illustrative reference policy, NOT the LightUp production scope gate."""
    if type(request) is not Request or type(approvals) not in (tuple, list):
        return False
    if type(required) is not int or required < 1:
        return False
    for value in (request.tenant, request.request_id, request.requester, request.scope_digest):
        if type(value) is not str or not value.strip():
            return False
    if type(request.revision) is not int or request.revision < 1:
        return False
    if type(request.risk) is not int or not 0 <= request.risk <= 5:
        return False
    seen = set()
    for approval in approvals:
        if type(approval) is not Approval or type(approval.active) is not bool or not approval.active:
            continue
        if type(approval.reviewer) is not str or not approval.reviewer.strip():
            continue
        if approval.reviewer == request.requester:
            continue
        if (approval.tenant, approval.request_id, approval.revision, approval.scope_digest) != (
            request.tenant, request.request_id, request.revision, request.scope_digest
        ):
            continue
        if type(approval.max_risk) is not int or approval.max_risk < request.risk or approval.max_risk > 5:
            continue
        seen.add(approval.reviewer)
    return len(seen) >= required


class SeparationOfDutiesContractTests(unittest.TestCase):
    def setUp(self):
        self.request = Request("tenant-1", "request-1", 4, "user-A", "sha256:abc", 3)
        self.approval = Approval("tenant-1", "request-1", 4, "user-B", "sha256:abc", 3, True)

    def test_valid_independent_review_reference(self):
        self.assertTrue(is_independent_review(self.request, [self.approval]))

    def test_self_approval_is_rejected_even_with_admin_label(self):
        self.assertFalse(is_independent_review(self.request, [dataclasses.replace(self.approval, reviewer="user-A")]))

    def test_replay_and_scope_changes_rejected(self):
        for change in ({"tenant": "tenant-2"}, {"request_id": "request-2"}, {"revision": 3}, {"scope_digest": "sha256:def"}):
            with self.subTest(change=change):
                self.assertFalse(is_independent_review(self.request, [dataclasses.replace(self.approval, **change)]))

    def test_inactive_boolean_and_lower_risk_rejected(self):
        for change in ({"active": False}, {"active": 1}, {"max_risk": True}, {"max_risk": 2}):
            with self.subTest(change=change):
                self.assertFalse(is_independent_review(self.request, [dataclasses.replace(self.approval, **change)]))

    def test_distinct_reviewers_required_for_two_person_rule(self):
        self.assertFalse(is_independent_review(self.request, [self.approval, self.approval], required=2))
        self.assertTrue(is_independent_review(self.request, [self.approval, dataclasses.replace(self.approval, reviewer="user-C")], required=2))

    def test_malformed_principal_and_revision_inputs_fail_closed(self):
        for update in ({"requester": ""}, {"requester": True}, {"revision": True}, {"risk": True}, {"tenant": ""}):
            with self.subTest(update=update):
                self.assertFalse(is_independent_review(dataclasses.replace(self.request, **update), [self.approval]))

    def test_subclass_approval_is_not_trusted(self):
        class UntrustedApproval(Approval):
            pass
        self.assertFalse(is_independent_review(self.request, [UntrustedApproval(**dataclasses.asdict(self.approval))]))


    def test_required_reviewer_count_is_strict(self):
        for count in (0, -1, True, 1.0, "1", None):
            with self.subTest(count=count):
                self.assertFalse(is_independent_review(self.request, [self.approval], required=count))

    def test_untrusted_approval_shapes_do_not_supply_authority(self):
        for payload in (None, {}, (), [object()], ["user-B"], [dataclasses.asdict(self.approval)]):
            with self.subTest(payload=repr(payload)):
                self.assertFalse(is_independent_review(self.request, payload))

    def test_approval_collection_and_reference_request_are_not_mutated(self):
        approvals = [self.approval]
        before = tuple(approvals)
        request_before = dataclasses.asdict(self.request)
        self.assertTrue(is_independent_review(self.request, approvals))
        self.assertEqual(tuple(approvals), before)
        self.assertEqual(dataclasses.asdict(self.request), request_before)

    def test_invalid_reviewer_principal_never_counts(self):
        for reviewer in ("", "   ", None, True, 42):
            with self.subTest(reviewer=reviewer):
                self.assertFalse(is_independent_review(self.request, [dataclasses.replace(self.approval, reviewer=reviewer)]))


if __name__ == "__main__":
    unittest.main()
