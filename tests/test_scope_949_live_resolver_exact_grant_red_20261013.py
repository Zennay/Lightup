"""Issue #949: exact live AuthorizationGrant identity at the ToolExecutor boundary.

Offline-only; uses real PR #107 executor with an inert handler, disposable
SQLite, no targets/network. Intentionally unresolved RED checks are marked
expectedFailure until the source-owner fixes the production path.
"""
from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.state import StateStore


class DuckGrant:
    """Untrusted arbitrary resolver result impersonating a trusted record."""

    def __init__(self, original, scope=None):
        self.original = original
        self.grant_id = original.grant_id
        self.scope = scope or original.scope

    def __getattr__(self, key):
        return getattr(self.original, key)

    def is_current(self, now=None):
        return True


class GrantSubclass(AuthorizationGrant):
    """Not exact canonical class, even though its fields look familiar."""


class GrantSubclassBypassingExpiry(AuthorizationGrant):
    def is_current(self, now=None):
        return True


class RecordingPolicy(ExecutionPolicy):
    def __init__(self):
        self.received = []

    def decide(self, request):
        self.received.append(request)
        return super().decide(request)


class ResolverCanonicalIdentity949(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-949-")
        self.addCleanup(temp.cleanup)
        self.state = StateStore(Path(temp.name) / "offline-ledger.db")
        self.run_id = self.state.create_run(
            target="allowed.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-949",
        )
        self.now = datetime.now(timezone.utc)
        self.policy = RecordingPolicy()
        self.handler_calls = []
        self.resolver_calls = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "synthetic-canonical-grant-949", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "purely synthetic handler with no IO",
            ),
            self._inert_handler,
        )

    def _inert_handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("inert", "synthetic", b"synthetic")

    def _grant(self):
        return AuthorizationGrant(
            grant_id="grant-949", client_id="client-949",
            engagement_id="engagement-949", approved_by="synthetic-only",
            reference="TEST-949",
            scope=ScopeDefinition(
                assets=("allowed.invalid",), max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("network-services",),
            ),
            valid_from=self.now - timedelta(days=1),
            valid_until=self.now + timedelta(days=1),
        )

    def _subclass(self, base, cls):
        return cls(**{
            item.name: getattr(base, item.name)
            for item in fields(AuthorizationGrant)
        })

    def _count_evidence(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _execute(self, snapshot, resolved, asset="allowed.invalid"):
        def resolver(original):
            self.resolver_calls.append(original)
            return resolved

        executor = ToolExecutor(
            self.registry, self.state, policy=self.policy,
            authorization_resolver=resolver,
        )
        context = RunContext(
            run_id=self.run_id, client_id="client-949",
            engagement_id="engagement-949",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=snapshot, is_lab=False, created_at=self.now,
        )
        return executor.execute(
            context, ToolCall("synthetic-canonical-grant-949", asset)
        )

    def _assert_denied_prepolicy(self, snapshot, resolved, **kwargs):
        before = self._count_evidence()
        with self.assertRaises(ToolDenied):
            self._execute(snapshot, resolved, **kwargs)
        self.assertEqual(self.policy.received, [], "resolver must deny before policy")
        self.assertEqual(self.handler_calls, [], "resolver must deny before handler")
        self.assertEqual(self._count_evidence(), before, "no evidence on denial")
        self.assertEqual(self.resolver_calls, [snapshot])

    @unittest.expectedFailure  # unresolved on source owner PR #107
    def test_duck_grant_with_same_id_must_be_rejected_prepolicy(self):
        original = self._grant()
        self._assert_denied_prepolicy(original, DuckGrant(original))

    @unittest.expectedFailure  # subclasses must not substitute exact grant
    def test_canonical_field_subclass_must_be_rejected_prepolicy(self):
        original = self._grant()
        self._assert_denied_prepolicy(
            original, self._subclass(original, GrantSubclass),
        )

    @unittest.expectedFailure  # overrides may redefine validity at runtime
    def test_expired_subclass_cannot_override_currentness(self):
        original = self._grant()
        expired = replace(original,
                          valid_from=self.now - timedelta(days=4),
                          valid_until=self.now - timedelta(days=2))
        bad = self._subclass(expired, GrantSubclassBypassingExpiry)
        self._assert_denied_prepolicy(original, bad)

    @unittest.expectedFailure  # foreign duck-controlled scope is not authority
    def test_duck_grant_cannot_promote_out_of_scope_asset(self):
        original = self._grant()
        widened = ScopeDefinition(
            assets=("allowed.invalid", "outside.invalid"),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("network-services",),
        )
        self._assert_denied_prepolicy(
            original, DuckGrant(original, scope=widened),
            asset="outside.invalid",
        )

    def test_exact_same_id_canonical_grant_remains_allowed(self):
        canonical = self._grant()
        result = self._execute(canonical, canonical)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(len(self.policy.received), 1)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._count_evidence(), 1)

    def test_none_live_grant_is_denied_prepolicy(self):
        original = self._grant()
        self._assert_denied_prepolicy(original, None)

    def test_exact_different_grant_id_is_denied_prepolicy(self):
        original = self._grant()
        self._assert_denied_prepolicy(
            original, replace(original, grant_id="different-grant"),
        )

    def test_exact_expired_live_grant_denied_by_existing_policy(self):
        original = self._grant()
        expired = replace(
            original,
            valid_from=self.now - timedelta(days=4),
            valid_until=self.now - timedelta(days=2),
        )
        with self.assertRaises(ToolDenied):
            self._execute(original, expired)
        self.assertEqual(len(self.policy.received), 1)
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._count_evidence(), 0)

    def test_exact_wrong_client_live_grant_denied_by_existing_policy(self):
        original = self._grant()
        wrong_client = replace(original, client_id="other-client")
        with self.assertRaises(ToolDenied):
            self._execute(original, wrong_client)
        self.assertEqual(len(self.policy.received), 1)
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._count_evidence(), 0)


if __name__ == "__main__":
    unittest.main()
