"""RED security contract: unknown interaction kinds cannot inherit active authority.

This test is intentionally isolated from production-owned policy changes.
No network I/O, target access, grant issuance or runtime activation occurs.
"""
from datetime import datetime, timedelta, timezone
import unittest

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class UnknownInteractionFailClosedContract(unittest.TestCase):
    def test_unknown_kind_must_not_reuse_active_grant(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="synthetic-grant",
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="synthetic-reviewer",
            reference="synthetic-offline-reference",
            scope=ScopeDefinition(
                assets=("lab.example.invalid",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("synthetic-read",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=1),
        )
        request = ExecutionRequest(
            interaction="target_actve",  # typo, not an InteractionKind member
            asset="lab.example.invalid",
            capability_id="synthetic-read",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=grant,
        )
        result = ExecutionPolicy().decide(request)
        self.assertFalse(result.allowed, "Unknown interaction must fail closed even with a valid grant")

    def test_known_active_interaction_remains_authorized(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="synthetic-grant", client_id="synthetic-client",
            engagement_id="synthetic-engagement", approved_by="synthetic-reviewer",
            reference="synthetic-offline-reference",
            scope=ScopeDefinition(assets=("lab.example.invalid",),
                                  max_risk=RiskLevel.STANDARD,
                                  allowed_capabilities=("synthetic-read",)),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=1),
        )
        request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="lab.example.invalid", capability_id="synthetic-read",
            requested_risk=RiskLevel.LOW_IMPACT, authorization=grant,
        )
        self.assertTrue(ExecutionPolicy().decide(request).allowed)


if __name__ == "__main__":
    unittest.main()
