from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class SpoofedIdentity(str):
    """A foreign runtime identity that lies about value equality."""

    def __new__(cls, value: str, masquerades_as: str):
        obj = str.__new__(cls, value)
        obj._masquerades_as = masquerades_as
        return obj

    def __eq__(self, other: object) -> bool:
        return str(other) == self._masquerades_as

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self._masquerades_as)


class MatchingIdentity(str):
    """Same textual identity, but still a non-canonical runtime string type."""


class DirectGrantLineageIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        now = datetime.now(timezone.utc)
        self.scope = ScopeDefinition(
            assets=("asset.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        )
        self.grant = AuthorizationGrant(
            grant_id="grant-743",
            client_id="client-743",
            engagement_id="engagement-743",
            approved_by="CISO",
            reference="AUTH-743",
            scope=self.scope,
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(minutes=5),
        )
        self.request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="asset.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=False,
            client_id="client-743",
            engagement_id="engagement-743",
        )
        self.policy = ExecutionPolicy()

    def test_canonical_exact_lineage_remains_allowed(self) -> None:
        decision = self.policy.decide(self.request)
        self.assertTrue(decision.allowed, decision.reason)

    def test_canonical_exact_client_mismatch_remains_denied(self) -> None:
        request = replace(self.request, client_id="other-client")
        decision = self.policy.decide(request)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "authorization client does not match execution client",
        )

    def test_canonical_exact_engagement_mismatch_remains_denied(self) -> None:
        request = replace(self.request, engagement_id="other-engagement")
        decision = self.policy.decide(request)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "authorization engagement does not match execution engagement",
        )

    def test_foreign_grant_client_identity_cannot_equality_spoof_request(self) -> None:
        grant = replace(
            self.grant,
            client_id=SpoofedIdentity("foreign-client", "client-743"),
        )
        decision = self.policy.decide(replace(self.request, authorization=grant))
        self.assertFalse(
            decision.allowed,
            "foreign grant client lineage must not inherit canonical request authority",
        )

    def test_foreign_grant_engagement_identity_cannot_equality_spoof_request(self) -> None:
        grant = replace(
            self.grant,
            engagement_id=SpoofedIdentity("foreign-engagement", "engagement-743"),
        )
        decision = self.policy.decide(replace(self.request, authorization=grant))
        self.assertFalse(
            decision.allowed,
            "foreign grant engagement lineage must not inherit canonical request authority",
        )

    def test_matching_text_grant_client_subclass_is_not_canonical_lineage(self) -> None:
        grant = replace(self.grant, client_id=MatchingIdentity("client-743"))
        decision = self.policy.decide(replace(self.request, authorization=grant))
        self.assertFalse(
            decision.allowed,
            "grant client lineage requires exact built-in str identity",
        )

    def test_matching_text_grant_engagement_subclass_is_not_canonical_lineage(self) -> None:
        grant = replace(
            self.grant,
            engagement_id=MatchingIdentity("engagement-743"),
        )
        decision = self.policy.decide(replace(self.request, authorization=grant))
        self.assertFalse(
            decision.allowed,
            "grant engagement lineage requires exact built-in str identity",
        )


if __name__ == "__main__":
    unittest.main()
