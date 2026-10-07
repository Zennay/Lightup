import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class SpoofedLineage(str):
    """A foreign lineage value that lies about equality."""

    def __new__(cls, value: str):
        return super().__new__(cls, value)

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class DirectGrantLineageTypingTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.scope = ScopeDefinition(
            assets=("app.example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.policy = ExecutionPolicy()
        self.canonical = AuthorizationGrant(
            grant_id="grant-1",
            client_id="client-1",
            engagement_id="eng-1",
            approved_by="operator@example.test",
            reference="roe-1",
            scope=self.scope,
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )

    def request(self, grant: AuthorizationGrant, *, client_id="client-1", engagement_id="eng-1"):
        return ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="app.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.STANDARD,
            client_id=client_id,
            engagement_id=engagement_id,
            authorization=grant,
        )

    def test_canonical_matching_lineage_remains_allowed(self):
        decision = self.policy.decide(self.request(self.canonical))
        self.assertTrue(decision.allowed)

    def test_canonical_foreign_client_lineage_remains_denied(self):
        foreign = AuthorizationGrant(
            **{**self.canonical.__dict__, "client_id": "client-2"}
        )
        decision = self.policy.decide(self.request(foreign))
        self.assertFalse(decision.allowed)

    def test_canonical_foreign_engagement_lineage_remains_denied(self):
        foreign = AuthorizationGrant(
            **{**self.canonical.__dict__, "engagement_id": "eng-2"}
        )
        decision = self.policy.decide(self.request(foreign))
        self.assertFalse(decision.allowed)

    def test_foreign_client_lineage_cannot_equality_spoof_request(self):
        spoofed = AuthorizationGrant(
            **{**self.canonical.__dict__, "client_id": SpoofedLineage("client-foreign")}
        )
        before = spoofed
        decision = self.policy.decide(self.request(spoofed))
        self.assertFalse(decision.allowed)
        self.assertIs(spoofed, before)
        self.assertEqual(str(spoofed.client_id), "client-foreign")

    def test_foreign_engagement_lineage_cannot_equality_spoof_request(self):
        spoofed = AuthorizationGrant(
            **{
                **self.canonical.__dict__,
                "engagement_id": SpoofedLineage("eng-foreign"),
            }
        )
        before = spoofed
        decision = self.policy.decide(self.request(spoofed))
        self.assertFalse(decision.allowed)
        self.assertIs(spoofed, before)
        self.assertEqual(str(spoofed.engagement_id), "eng-foreign")

    def test_same_text_client_string_subclass_is_noncanonical(self):
        spoofed = AuthorizationGrant(
            **{**self.canonical.__dict__, "client_id": SpoofedLineage("client-1")}
        )
        decision = self.policy.decide(self.request(spoofed))
        self.assertFalse(decision.allowed)

    def test_same_text_engagement_string_subclass_is_noncanonical(self):
        spoofed = AuthorizationGrant(
            **{**self.canonical.__dict__, "engagement_id": SpoofedLineage("eng-1")}
        )
        decision = self.policy.decide(self.request(spoofed))
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
