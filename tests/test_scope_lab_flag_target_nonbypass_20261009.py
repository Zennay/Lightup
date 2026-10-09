"""Offline regression: a lab context flag is not an active-target authorization grant.

No sockets, DNS, approvals, filesystem targets or production dispatch are used.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class LabMarkerNonBypassTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="synthetic-grant",
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="owner@example.test",
            reference="synthetic-only",
            scope=ScopeDefinition(
                assets=("authorized.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("synthetic-check",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=5),
        )

    def test_lab_flag_without_grant_cannot_authorize_target_active(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("authorization", result.reason)

    def test_lab_flag_with_grant_does_not_override_asset_scope(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="outside.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("scope", result.reason)

    def test_lab_flag_with_grant_does_not_override_capability_scope(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="not-granted",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("scope", result.reason)

    def test_lab_interaction_without_lab_flag_denied_despite_grant(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=False,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("lab", result.reason)


if __name__ == "__main__":
    unittest.main()
