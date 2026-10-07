from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


NOW = datetime.now(timezone.utc)
SCOPE = ScopeDefinition(
    assets=("example.test",),
    max_risk=RiskLevel.STANDARD,
    allowed_capabilities=("web-baseline",),
)


class _ExpiredButAlwaysCurrentGrant(AuthorizationGrant):
    def is_current(self, now: datetime | None = None) -> bool:
        return True


class _DuckGrant:
    grant_id = "duck-grant"
    client_id = "client-1"
    engagement_id = "engagement-1"
    approved_by = "operator-1"
    reference = "AUTH-DUCK"
    scope = SCOPE
    valid_from = NOW - timedelta(hours=2)
    valid_until = NOW - timedelta(hours=1)

    def is_current(self, now: datetime | None = None) -> bool:
        return True


def _grant(*, current: bool) -> AuthorizationGrant:
    if current:
        valid_from = NOW - timedelta(hours=1)
        valid_until = NOW + timedelta(hours=1)
    else:
        valid_from = NOW - timedelta(hours=2)
        valid_until = NOW - timedelta(hours=1)
    return AuthorizationGrant(
        grant_id="grant-direct-object",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-DIRECT-OBJECT",
        scope=SCOPE,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _request(grant: object) -> ExecutionRequest:
    return ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset="example.test",
        capability_id="web-baseline",
        requested_risk=RiskLevel.STANDARD,
        authorization=grant,  # type: ignore[arg-type]
        client_id="client-1",
        engagement_id="engagement-1",
    )


class DirectGrantObjectTypeAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ExecutionPolicy()

    def test_exact_current_grant_preserves_canonical_allow(self) -> None:
        self.assertTrue(self.policy.decide(_request(_grant(current=True))).allowed)

    def test_exact_expired_grant_preserves_canonical_denial(self) -> None:
        self.assertFalse(self.policy.decide(_request(_grant(current=False))).allowed)

    def test_authorization_grant_subclass_cannot_override_expiry(self) -> None:
        grant = _ExpiredButAlwaysCurrentGrant(
            grant_id="grant-subclass",
            client_id="client-1",
            engagement_id="engagement-1",
            approved_by="operator-1",
            reference="AUTH-SUBCLASS",
            scope=SCOPE,
            valid_from=NOW - timedelta(hours=2),
            valid_until=NOW - timedelta(hours=1),
        )
        before = (grant.valid_from, grant.valid_until, grant.scope)
        decision = self.policy.decide(_request(grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(before, (grant.valid_from, grant.valid_until, grant.scope))

    def test_duck_typed_grant_cannot_substitute_trusted_authorization(self) -> None:
        grant = _DuckGrant()
        before = (grant.valid_from, grant.valid_until, grant.scope)
        decision = self.policy.decide(_request(grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(before, (grant.valid_from, grant.valid_until, grant.scope))


if __name__ == "__main__":
    unittest.main()
