from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


NOW = datetime.now(timezone.utc)


class _AllowAllScope(ScopeDefinition):
    def allows_asset(self, asset: str) -> bool:
        return True

    def allows_capability(self, capability_id: str) -> bool:
        return True


class _DuckScope:
    max_risk = RiskLevel.STANDARD

    def allows_asset(self, asset: str) -> bool:
        return True

    def allows_capability(self, capability_id: str) -> bool:
        return True


def _grant(scope: object) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-direct-scope",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-DIRECT-SCOPE",
        scope=scope,  # type: ignore[arg-type]
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(hours=1),
    )


def _request(grant: AuthorizationGrant, *, asset: str, capability_id: str) -> ExecutionRequest:
    return ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset=asset,
        capability_id=capability_id,
        requested_risk=RiskLevel.STANDARD,
        authorization=grant,
        client_id="client-1",
        engagement_id="engagement-1",
    )


class DirectGrantScopeTypeAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ExecutionPolicy()

    def test_exact_scope_preserves_canonical_allow_decision(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        decision = self.policy.decide(
            _request(_grant(scope), asset="example.test", capability_id="web-baseline")
        )

        self.assertTrue(decision.allowed)

    def test_exact_scope_preserves_canonical_out_of_scope_denial(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        decision = self.policy.decide(
            _request(_grant(scope), asset="foreign.test", capability_id="web-baseline")
        )

        self.assertFalse(decision.allowed)

    def test_scope_subclass_cannot_override_membership_to_mint_authority(self) -> None:
        scope = _AllowAllScope(
            assets=(),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(),
        )
        grant = _grant(scope)
        before = grant.scope
        decision = self.policy.decide(
            _request(grant, asset="foreign.test", capability_id="foreign-capability")
        )

        self.assertFalse(decision.allowed)
        self.assertIs(grant.scope, before)

    def test_duck_typed_scope_cannot_mint_authority(self) -> None:
        scope = _DuckScope()
        grant = _grant(scope)
        before = grant.scope
        decision = self.policy.decide(
            _request(grant, asset="foreign.test", capability_id="foreign-capability")
        )

        self.assertFalse(decision.allowed)
        self.assertIs(grant.scope, before)


if __name__ == "__main__":
    unittest.main()
