"""Issue #741: forged direct grant must be denied *before* virtual invocation.

This covers a distinct source-owner gap beyond allow/deny assertions: a
non-canonical object supplied at the direct policy boundary may run arbitrary
in-memory user code through is_current. Pure fictional test data, no I/O.
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, ScopeDefinition, RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


CALLS: list[str] = []
ASSET = "synthetic.example.test"
CAPABILITY = "fake-capability-no-handler"


def valid_grant() -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="fictional-741-side-effect",
        client_id="fictional-client",
        engagement_id="fictional-engagement",
        approved_by="not-an-actual-operator",
        reference="fictional-no-consent",
        scope=ScopeDefinition(
            assets=(ASSET,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(CAPABILITY,),
        ),
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(minutes=5),
    )


def request(grant: object) -> ExecutionRequest:
    return ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset=ASSET,
        capability_id=CAPABILITY,
        requested_risk=RiskLevel.LOW_IMPACT,
        authorization=grant,
        client_id="fictional-client",
        engagement_id="fictional-engagement",
    )


class SideEffectSubclass(AuthorizationGrant):
    def is_current(self, now=None) -> bool:
        CALLS.append("forged-subclass-called")
        return True


class TrapSubclass(AuthorizationGrant):
    def is_current(self, now=None) -> bool:
        CALLS.append("trap-method-called")
        raise RuntimeError("noncanonical grant method executed")


class TrapDuck:
    def __init__(self, grant: AuthorizationGrant) -> None:
        self.client_id = grant.client_id
        self.engagement_id = grant.engagement_id
        self.scope = grant.scope

    def is_current(self, now=None) -> bool:
        CALLS.append("duck-method-called")
        raise RuntimeError("untrusted duck grant method executed")


class SourceOwnerPreinvokeRED741(unittest.TestCase):
    def setUp(self) -> None:
        CALLS.clear()
        self.policy = ExecutionPolicy()

    def tearDown(self) -> None:
        CALLS.clear()

    def assert_denied_without_invocation(self, forged: object) -> None:
        decision = self.policy.decide(request(forged))
        self.assertFalse(decision.allowed)
        self.assertEqual(CALLS, [])

    def test_exact_grant_is_not_an_implicit_virtual_trap(self) -> None:
        self.assertTrue(self.policy.decide(request(valid_grant())).allowed)
        self.assertEqual(CALLS, [])

    @unittest.expectedFailure
    def test_subclass_rejected_without_running_its_override(self) -> None:
        forged = SideEffectSubclass(**vars(valid_grant()))
        self.assert_denied_without_invocation(forged)

    @unittest.expectedFailure
    def test_throwing_subclass_rejected_before_method_call(self) -> None:
        forged = TrapSubclass(**vars(valid_grant()))
        self.assert_denied_without_invocation(forged)

    @unittest.expectedFailure
    def test_throwing_duck_rejected_before_method_call(self) -> None:
        forged = TrapDuck(valid_grant())
        self.assert_denied_without_invocation(forged)


if __name__ == "__main__":
    unittest.main()
