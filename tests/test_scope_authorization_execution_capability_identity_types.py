from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class EqualitySpoof(str):
    """Foreign capability identity that lies about equality."""

    def __eq__(self, other: object) -> bool:
        return other == "network-services"

    def __ne__(self, other: object) -> bool:
        return False

    __hash__ = str.__hash__


class MatchingCapabilitySubclass(str):
    """Textually canonical but still not an exact built-in string."""


class ExecutionCapabilityIdentityTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="grant-capability-type",
            client_id="client-capability-type",
            engagement_id="engagement-capability-type",
            approved_by="CISO Capability",
            reference="AUTH-CAPABILITY-TYPE-001",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        self.policy = ExecutionPolicy()

    def _request(self, capability_id: str) -> ExecutionRequest:
        return ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="allowed.test",
            capability_id=capability_id,
            requested_risk=RiskLevel.STANDARD,
            authorization=self.grant,
            is_lab=False,
            client_id=self.grant.client_id,
            engagement_id=self.grant.engagement_id,
        )

    def _assert_denied_deterministically(self, capability_id: str) -> None:
        before = self.grant
        first = self.policy.decide(self._request(capability_id))
        second = self.policy.decide(self._request(capability_id))
        self.assertFalse(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(first, second)
        self.assertEqual(self.grant, before)

    def test_canonical_exact_capability_remains_authorized(self) -> None:
        decision = self.policy.decide(self._request("network-services"))
        self.assertTrue(decision.allowed)

    def test_plain_foreign_capability_remains_denied(self) -> None:
        self._assert_denied_deterministically("forged-capability")

    def test_polymorphic_foreign_capability_cannot_equality_spoof_scope(self) -> None:
        forged = EqualitySpoof("forged-capability")
        self.assertEqual(str(forged), "forged-capability")
        self.assertNotEqual(str(forged), "network-services")
        self.assertIsNot(type(forged), str)
        self._assert_denied_deterministically(forged)

    def test_polymorphic_matching_capability_is_still_denied(self) -> None:
        forged = MatchingCapabilitySubclass("network-services")
        self.assertEqual(str(forged), "network-services")
        self.assertIsNot(type(forged), str)
        self._assert_denied_deterministically(forged)


if __name__ == "__main__":
    unittest.main()
