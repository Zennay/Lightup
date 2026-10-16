"""Offline installed-source owner acceptance: direct grant identity (#741).

Pinned above source owner PR #100, exact SHA
ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f.
Only pure in-memory ExecutionPolicy decisions; no target handlers or I/O.
"""
from __future__ import annotations

import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


ASSET = "fixture.example.test"
CAPABILITY = "fictional-baseline-no-dispatch"
CLIENT = "synthetic-client"
ENGAGEMENT = "synthetic-engagement"


def canonical_grant(*, expired: bool = False) -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="fictional-grant-741",
        client_id=CLIENT,
        engagement_id=ENGAGEMENT,
        approved_by="fictional-operator",
        reference="FAKE-REVIEW-NOT-REAL-CONSENT",
        scope=ScopeDefinition(
            assets=(ASSET,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(CAPABILITY,),
        ),
        valid_from=now - timedelta(days=3),
        valid_until=now - timedelta(days=1) if expired else now + timedelta(days=1),
    )


def request(grant: object, *, client_id: str = CLIENT,
            engagement_id: str = ENGAGEMENT) -> ExecutionRequest:
    return ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset=ASSET,
        capability_id=CAPABILITY,
        requested_risk=RiskLevel.LOW_IMPACT,
        authorization=grant,
        client_id=client_id,
        engagement_id=engagement_id,
    )


class AlwaysCurrentSubclass(AuthorizationGrant):
    """Attacker-supplied subclass hides a stale validity interval."""

    def is_current(self, now=None) -> bool:
        return True


class DuckGrant:
    """Structurally compatible fake; no trusted grant identity or provenance."""

    def __init__(self, g: AuthorizationGrant) -> None:
        self.client_id = g.client_id
        self.engagement_id = g.engagement_id
        self.scope = g.scope

    def is_current(self, now=None) -> bool:
        return True


def subclass_from(g: AuthorizationGrant) -> AuthorizationGrant:
    return AlwaysCurrentSubclass(**vars(g))


class ExactGrantPositiveControls741(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ExecutionPolicy()

    def test_exact_current_grant_preserves_canonical_policy(self) -> None:
        g = canonical_grant()
        self.assertIs(type(g), AuthorizationGrant)
        self.assertTrue(self.policy.decide(request(g)).allowed)

    def test_exact_expired_grant_is_denied(self) -> None:
        self.assertFalse(self.policy.decide(request(canonical_grant(expired=True))).allowed)

    def test_missing_grant_is_denied(self) -> None:
        self.assertFalse(self.policy.decide(request(None)).allowed)

    def test_wrong_client_stays_denied(self) -> None:
        self.assertFalse(
            self.policy.decide(request(canonical_grant(), client_id="other-client")).allowed
        )

    def test_wrong_engagement_stays_denied(self) -> None:
        self.assertFalse(
            self.policy.decide(request(canonical_grant(), engagement_id="other-eng")).allowed
        )

    def test_exact_revoked_grant_denied(self) -> None:
        g = canonical_grant()
        revoked = replace(g, revoked_at=datetime.now(timezone.utc))
        self.assertFalse(self.policy.decide(request(revoked)).allowed)

    def test_decision_does_not_mutate_exact_grant_or_request(self) -> None:
        g = canonical_grant()
        req = request(g)
        grant_snapshot = dict(vars(g))
        request_snapshot = dict(vars(req))
        self.policy.decide(req)
        self.assertEqual(vars(g), grant_snapshot)
        self.assertEqual(vars(req), request_snapshot)


class PolymorphicDirectGrantOwnerRED741(unittest.TestCase):
    """Deliberate source REDs: owner must remove decorators after fixing."""

    @unittest.expectedFailure
    def test_subclass_cannot_override_expired_grant_to_approve(self) -> None:
        g = canonical_grant(expired=True)
        forged = subclass_from(g)
        self.assertIsNot(type(forged), AuthorizationGrant)
        original = dict(vars(forged))
        verdict = ExecutionPolicy().decide(request(forged))
        self.assertFalse(verdict.allowed, "subclass must not supply authority")
        self.assertEqual(vars(forged), original)

    @unittest.expectedFailure
    def test_structural_duck_cannot_substitute_for_exact_grant(self) -> None:
        g = canonical_grant(expired=True)
        forged = DuckGrant(g)
        self.assertIsNot(type(forged), AuthorizationGrant)
        original = dict(vars(forged))
        verdict = ExecutionPolicy().decide(request(forged))
        self.assertFalse(verdict.allowed, "duck grant must not supply authority")
        self.assertEqual(vars(forged), original)


if __name__ == "__main__":
    unittest.main()
