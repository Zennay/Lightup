"""Issue #777: test-only pure policy-narrowing preview against real main types.

This is not installed, callable from production, or proof of real customer
consent. It demonstrates the minimum fail-closed contract for the source owner.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind, PolicyDecision


class StringImposter(str):
    pass


def _preview_narrowed_decide(policy: ExecutionPolicy, request: ExecutionRequest) -> PolicyDecision:
    """Pure test-only prototype. Never mint authority or mutate caller objects."""
    if request.interaction is InteractionKind.TARGET_ACTIVE and request.authorization is not None:
        grant = request.authorization
        for value in (grant.approved_by, grant.reference):
            if type(value) is not str or not value.strip() or value != value.strip():
                return PolicyDecision(False, "authorization provenance is not canonical")
    return policy.decide(request)


class PureDirectProvenancePreviewTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="fictional-grant", client_id="fictional-client",
            engagement_id="fictional-engagement", approved_by="fictional-operator",
            reference="ROE-FICTIONAL", scope=ScopeDefinition(
                assets=("example.test",), max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("fictional-check",),
            ), valid_from=now-timedelta(hours=1), valid_until=now+timedelta(hours=1),
        )
        self.policy = ExecutionPolicy()

    def _request(self, grant, kind=InteractionKind.TARGET_ACTIVE):
        return ExecutionRequest(interaction=kind, asset="example.test",
                                capability_id="fictional-check",
                                requested_risk=RiskLevel.LOW_IMPACT,
                                authorization=grant)

    def test_fourteen_direct_provenance_bypasses_are_all_denied(self):
        variants = (
            {"approved_by": ""}, {"approved_by": " \t "},
            {"approved_by": " fictional-operator "},
            {"approved_by": StringImposter("fictional-operator")},
            {"approved_by": b"fictional-operator"},
            {"approved_by": None},
            {"approved_by": "\u2003fictional-operator"},
            {"reference": ""}, {"reference": " \t "},
            {"reference": " ROE-FICTIONAL "},
            {"reference": StringImposter("ROE-FICTIONAL")},
            {"reference": 123}, {"reference": None},
            {"reference": "ROE-FICTIONAL\u00a0"},
        )
        for case in variants:
            with self.subTest(case=case):
                grant = replace(self.grant, **case)
                snapshot = grant.__dict__.copy()
                request = self._request(grant)
                request_snapshot = request.__dict__.copy()
                decision = _preview_narrowed_decide(self.policy, request)
                self.assertIs(type(decision), PolicyDecision)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "authorization provenance is not canonical")
                self.assertEqual(grant.__dict__, snapshot)
                self.assertEqual(request.__dict__, request_snapshot)

    def test_canonical_active_remains_allowed(self):
        self.assertTrue(_preview_narrowed_decide(self.policy, self._request(self.grant)).allowed)

    def test_missing_grant_does_not_gain_authority(self):
        self.assertFalse(_preview_narrowed_decide(self.policy, self._request(None)).allowed)

    def test_expired_and_out_of_scope_stay_denied(self):
        expired = replace(self.grant,
                          valid_from=self.grant.valid_from-timedelta(days=3),
                          valid_until=self.grant.valid_from-timedelta(days=1))
        out = replace(self.grant, scope=replace(self.grant.scope, assets=("not-allowed.example",)))
        for grant in (expired, out):
            with self.subTest(grant=grant.grant_id):
                self.assertFalse(_preview_narrowed_decide(self.policy, self._request(grant)).allowed)

    def test_passive_unrelated_to_direct_grant_provenance(self):
        request = ExecutionRequest(interaction=InteractionKind.PASSIVE_PUBLIC,
                                   asset="example.test", capability_id="fictional-check",
                                   requested_risk=RiskLevel.PASSIVE,
                                   authorization=replace(self.grant, approved_by=""))
        before = self.policy.decide(request)
        after = _preview_narrowed_decide(self.policy, request)
        self.assertEqual(after, before)

    def test_no_unexpected_grants_for_invalid_types(self):
        for value in (None, False, 0, [], {}, b"operator"):
            with self.subTest(value=value):
                grant = replace(self.grant, reference=value)
                self.assertFalse(_preview_narrowed_decide(self.policy, self._request(grant)).allowed)


if __name__ == "__main__":
    unittest.main()
