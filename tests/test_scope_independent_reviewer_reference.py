"""Pure offline reference checks for independent reviewer separation.

This test-only model is NOT wired to production authorization or execution.
It intentionally cannot issue an approval, grant, permit, or active dispatch.
"""
import unittest
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class Request:
    tenant: str
    engagement: str
    revision_digest: str
    requester_principal: str
    finalized_at: datetime


@dataclass(frozen=True)
class Decision:
    tenant: str
    engagement: str
    revision_digest: str
    approver_principal: str
    principal_verified: bool
    permitted_tenants: frozenset[str]
    decided_at: datetime
    affirmative: bool = True
    revoked: bool = False


def conditionally_eligible(request: Request, decision: Decision) -> bool:
    """Deliberately narrow offline predicate, never an authorization grant."""
    if type(request) is not Request or type(decision) is not Decision:
        return False
    if any(type(value) is not str or not value.strip() for value in (
        request.tenant, request.engagement, request.revision_digest,
        request.requester_principal, decision.tenant, decision.engagement,
        decision.revision_digest, decision.approver_principal
    )):
        return False
    if type(decision.principal_verified) is not bool or not decision.principal_verified:
        return False
    if type(decision.affirmative) is not bool or not decision.affirmative:
        return False
    if type(decision.revoked) is not bool or decision.revoked:
        return False
    if type(decision.permitted_tenants) is not frozenset:
        return False
    if any(type(tenant) is not str for tenant in decision.permitted_tenants):
        return False
    if request.requester_principal == decision.approver_principal:
        return False
    if (request.tenant != decision.tenant or
        request.engagement != decision.engagement or
        request.revision_digest != decision.revision_digest or
        request.tenant not in decision.permitted_tenants):
        return False
    for timestamp in (request.finalized_at, decision.decided_at):
        if type(timestamp) is not datetime or timestamp.tzinfo is None:
            return False
        if timestamp.utcoffset() is None:
            return False
    return decision.decided_at > request.finalized_at


class IndependentReviewerReferenceTests(unittest.TestCase):
    def setUp(self):
        now = datetime(2026, 10, 8, 1, 0, tzinfo=timezone.utc)
        self.request = Request("tenant-a", "eng-1", "digest-1", "human-1", now)
        self.decision = Decision("tenant-a", "eng-1", "digest-1", "human-2",
                                 True, frozenset({"tenant-a"}),
                                 now + timedelta(minutes=1))

    def test_positive_is_only_conditionally_eligible(self):
        self.assertTrue(conditionally_eligible(self.request, self.decision))

    def test_self_approval_and_account_alias(self):
        self.assertFalse(conditionally_eligible(self.request,
            replace(self.decision, approver_principal="human-1")))

    def test_missing_or_unverified_identity(self):
        for principal, verified in (("", True), ("human-2", False),
                                    ("human-2", 1)):
            with self.subTest(principal=principal, verified=verified):
                self.assertFalse(conditionally_eligible(self.request,
                    replace(self.decision, approver_principal=principal,
                            principal_verified=verified)))

    def test_cross_tenant_and_engagement_replay(self):
        for changes in ({"tenant": "tenant-b"}, {"engagement": "eng-2"},
                        {"permitted_tenants": frozenset({"tenant-b"})}):
            with self.subTest(changes=changes):
                self.assertFalse(conditionally_eligible(
                    self.request, replace(self.decision, **changes)))

    def test_revision_change_invalidates_approval(self):
        self.assertFalse(conditionally_eligible(
            replace(self.request, revision_digest="digest-2"), self.decision))

    def test_approval_must_follow_finalization(self):
        for timestamp in (self.request.finalized_at,
                          self.request.finalized_at - timedelta(seconds=1)):
            with self.subTest(timestamp=timestamp):
                self.assertFalse(conditionally_eligible(self.request,
                    replace(self.decision, decided_at=timestamp)))

    def test_offset_aware_comparison(self):
        different_zone = timezone(timedelta(hours=2))
        decision = replace(self.decision,
            decided_at=self.decision.decided_at.astimezone(different_zone))
        self.assertTrue(conditionally_eligible(self.request, decision))

    def test_naive_dates_fail_closed(self):
        self.assertFalse(conditionally_eligible(
            replace(self.request, finalized_at=self.request.finalized_at.replace(tzinfo=None)),
            self.decision))
        self.assertFalse(conditionally_eligible(self.request,
            replace(self.decision, decided_at=self.decision.decided_at.replace(tzinfo=None))))

    def test_rejected_revoked_and_truthy_flags_fail_closed(self):
        for changes in ({"affirmative": False}, {"revoked": True},
                        {"affirmative": 1}, {"revoked": 0}):
            with self.subTest(changes=changes):
                self.assertFalse(conditionally_eligible(
                    self.request, replace(self.decision, **changes)))

    def test_invalid_permission_container_fails_closed(self):
        self.assertFalse(conditionally_eligible(self.request,
            replace(self.decision, permitted_tenants={"tenant-a"})))

    def test_subclass_instances_do_not_become_authority(self):
        @dataclass(frozen=True)
        class ExpandedDecision(Decision):
            delegated_admin: bool = True
        self.assertFalse(conditionally_eligible(
            self.request, ExpandedDecision(**vars(self.decision))))
