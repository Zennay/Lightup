"""Issue #938: immutable live resolver binding throughout ToolExecutor lifetime.

Offline-only synthetic handler and SQLite. Expected failures pin mutable
executor/source-owner #107 gap; no scans, sockets or actual target handlers.
"""
from __future__ import annotations

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
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class ResolverLifetime938(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-938-")
        self.addCleanup(temp.cleanup)
        self.state = StateStore(Path(temp.name) / "offline.db")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-938",
        )
        self.handler_calls = []
        self.resolver_calls = []
        self.registry = ToolRegistry()
        for identifier, cap, interaction, risk in (
            ("synthetic-active-938", "network-services",
             InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT),
            ("synthetic-passive-938", "external-attack-surface",
             InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE),
            ("synthetic-lab-938", "web-baseline",
             InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY),
        ):
            self.registry.register(
                ToolDefinition(identifier, cap, interaction, risk,
                               "in-memory test fixture, never transport"),
                self._inert_handler,
            )

        now = datetime.now(timezone.utc)
        self.snapshot = AuthorizationGrant(
            grant_id="synthetic-938", client_id="client-938",
            engagement_id="engagement-938", approved_by="synthetic",
            reference="TEST-938",
            scope=ScopeDefinition(
                assets=("synthetic.invalid",), max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=1),
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="client-938",
            engagement_id="engagement-938",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=self.snapshot, is_lab=False, created_at=now,
        )

    def _inert_handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("offline", "test", b"offline-only")

    def _evidence_count(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _revoked_resolver(self, snapshot):
        self.resolver_calls.append(snapshot)
        return None

    def _executor(self, resolver):
        return ToolExecutor(
            self.registry, self.state,
            authorization_resolver=resolver,
        )

    def _assert_binding_did_not_change(self, executor):
        self.assertEqual(
            executor.authorization_resolver, self._revoked_resolver,
            "caller must not replace the trusted construction-time resolver",
        )
        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context, ToolCall("synthetic-active-938", "synthetic.invalid")
            )
        self.assertEqual(self.resolver_calls, [self.snapshot])
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)

    @unittest.expectedFailure  # writable attribute on original source-owner #107
    def test_public_attribute_rebinding_must_not_bypass_revocation(self):
        executor = self._executor(self._revoked_resolver)
        try:
            executor.authorization_resolver = lambda grant: grant
        except (AttributeError, TypeError):
            pass
        self._assert_binding_did_not_change(executor)

    @unittest.expectedFailure  # object.__setattr__ must not change policy authority
    def test_object_setattr_must_not_rebind_live_resolver(self):
        executor = self._executor(self._revoked_resolver)
        try:
            object.__setattr__(
                executor, "authorization_resolver", lambda grant: grant
            )
        except (AttributeError, TypeError):
            pass
        self._assert_binding_did_not_change(executor)

    @unittest.expectedFailure  # no dictionary-shadow authority mutation
    def test_instance_dictionary_cannot_shadow_live_resolver(self):
        executor = self._executor(self._revoked_resolver)
        try:
            if hasattr(executor, "__dict__"):
                vars(executor)["authorization_resolver"] = lambda grant: grant
        except (AttributeError, KeyError, TypeError):
            pass
        self._assert_binding_did_not_change(executor)

    @unittest.expectedFailure  # no erasure of trusted construction-time resolver
    def test_deletion_cannot_remove_live_resolver_binding(self):
        executor = self._executor(self._revoked_resolver)
        try:
            del executor.authorization_resolver
        except (AttributeError, TypeError):
            pass
        self._assert_binding_did_not_change(executor)

    def test_original_revoked_resolver_denies_without_evidence(self):
        executor = self._executor(self._revoked_resolver)
        self._assert_binding_did_not_change(executor)

    def test_missing_resolver_denies_before_handler_and_evidence(self):
        executor = self._executor(None)
        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context, ToolCall("synthetic-active-938", "synthetic.invalid")
            )
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)

    def test_construction_time_live_grant_accepts_synthetic_control(self):
        resolver_calls = []
        def resolver(grant):
            resolver_calls.append(grant)
            return grant
        executor = self._executor(resolver)
        result = executor.execute(
            self.context, ToolCall("synthetic-active-938", "synthetic.invalid")
        )
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(resolver_calls, [self.snapshot])
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 1)

    def test_passive_mode_stays_passive_when_live_resolver_rejects(self):
        passive_context = RunContext(
            run_id=self.run_id, client_id="client-938",
            engagement_id="engagement-938",
            mode=AssessmentMode.PASSIVE_DISCOVERY,
            approved_risk=RiskLevel.PASSIVE,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        executor = self._executor(self._revoked_resolver)
        result = executor.execute(
            passive_context, ToolCall("synthetic-passive-938", "synthetic.invalid")
        )
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.resolver_calls, [])
        with self.assertRaises(ToolDenied):
            executor.execute(
                passive_context, ToolCall("synthetic-active-938", "synthetic.invalid")
            )
        self.assertEqual(self.resolver_calls, [])
        self.assertEqual(self.handler_calls, [self.run_id])

    def test_lab_only_mode_never_admits_real_target_tool(self):
        context = RunContext.for_lab(run_id=self.run_id)
        executor = self._executor(self._revoked_resolver)
        lab_result = executor.execute(
            context, ToolCall("synthetic-lab-938", "synthetic.invalid")
        )
        self.assertEqual(lab_result.run_id, self.run_id)
        with self.assertRaises(ToolDenied):
            executor.execute(
                context, ToolCall("synthetic-active-938", "synthetic.invalid")
            )
        self.assertEqual(self.resolver_calls, [])
        self.assertEqual(self.handler_calls, [self.run_id])


if __name__ == "__main__":
    unittest.main()
