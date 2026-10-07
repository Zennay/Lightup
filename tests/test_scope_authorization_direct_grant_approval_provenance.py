import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class _ProvenanceString(str):
    """Same-value string subclass that must not cross the authorization boundary."""


class DirectGrantApprovalProvenanceTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="grant-direct-provenance",
            client_id="client-1",
            engagement_id="eng-1",
            approved_by="security-owner@example.test",
            reference="signed-roE-1",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        self.request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="app.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.STANDARD,
            client_id="client-1",
            engagement_id="eng-1",
            authorization=self.grant,
        )
        self.policy = ExecutionPolicy()

    def _decision_for(self, **changes):
        grant = replace(self.grant, **changes)
        request = replace(self.request, authorization=grant)
        return grant, request, self.policy.decide(request)

    def test_canonical_direct_grant_provenance_remains_authorized(self):
        decision = self.policy.decide(self.request)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized active assessment")

    def test_blank_direct_approved_by_fails_closed(self):
        grant, request, decision = self._decision_for(approved_by="")
        self.assertFalse(decision.allowed)
        self.assertEqual(grant.approved_by, "")
        self.assertIs(request.authorization, grant)

    def test_whitespace_direct_reference_fails_closed(self):
        grant, request, decision = self._decision_for(reference="   ")
        self.assertFalse(decision.allowed)
        self.assertEqual(grant.reference, "   ")
        self.assertIs(request.authorization, grant)

    def test_padded_direct_provenance_fails_closed_instead_of_normalizing(self):
        grant, request, decision = self._decision_for(
            approved_by=" security-owner@example.test ",
            reference=" signed-roE-1 ",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(grant.approved_by, " security-owner@example.test ")
        self.assertEqual(grant.reference, " signed-roE-1 ")
        self.assertIs(request.authorization, grant)

    def test_polymorphic_direct_approved_by_fails_closed(self):
        value = _ProvenanceString("security-owner@example.test")
        grant, request, decision = self._decision_for(approved_by=value)
        self.assertFalse(decision.allowed)
        self.assertIs(grant.approved_by, value)
        self.assertIs(request.authorization, grant)

    def test_polymorphic_direct_reference_fails_closed(self):
        value = _ProvenanceString("signed-roE-1")
        grant, request, decision = self._decision_for(reference=value)
        self.assertFalse(decision.allowed)
        self.assertIs(grant.reference, value)
        self.assertIs(request.authorization, grant)


if __name__ == "__main__":
    unittest.main()
