"""Issue #942 — canonical execution policy must remain pinned to ToolExecutor.

Real PR #107 executor with inert handlers, synthetic reserved invalid domains,
and disposable SQLite. Expected failures are unresolved RED, not fixes.
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
from lightup.execution_policy import (
    ExecutionPolicy, InteractionKind, PolicyDecision,
)
from lightup.state import StateStore


class AllowEverything:
    """Untrusted constructor-bypassing policy object."""
    def decide(self, request):
        return PolicyDecision(True, "untrusted synthetic permit")


class AllowEverythingSubclass(ExecutionPolicy):
    def decide(self, request):
        return PolicyDecision(True, "untrusted synthetic subclass permit")


class PolicyBinding942(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-942-")
        self.addCleanup(temp.cleanup)
        self.state = StateStore(Path(temp.name) / "offline-evidence.db")
        self.run_id = self.state.create_run(
            target="allowed.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-942",
        )
        self.registry = ToolRegistry()
        self.handler_calls = []
        self.registry.register(
            ToolDefinition(
                "inert-active-942", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "in-memory test handler, no network",
            ),
            self._handler,
        )
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="grant-942", client_id="client-942",
            engagement_id="engagement-942", approved_by="synthetic",
            reference="SYNTHETIC-942",
            scope=ScopeDefinition(
                assets=("allowed.invalid",),
                allowed_capabilities=("network-services",),
                max_risk=RiskLevel.LOW_IMPACT,
            ),
            valid_from=now-timedelta(days=1),
            valid_until=now+timedelta(days=1),
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="client-942",
            engagement_id="engagement-942",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT, authorization=self.grant,
            is_lab=False, created_at=now,
        )
        self.canonical = ExecutionPolicy()

    def _handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("synthetic", "test", b"test")

    def _rows(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _executor(self):
        return ToolExecutor(
            self.registry, self.state, policy=self.canonical,
            authorization_resolver=lambda grant: grant,
        )

    def _assert_cannot_replace(self, attempt):
        executor = self._executor()
        before = self._rows()
        try:
            attempt(executor)
        except (AttributeError, TypeError, KeyError):
            pass
        self.assertIs(executor.policy, self.canonical,
                      "constructor-selected policy must never be replaced")
        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context, ToolCall("inert-active-942", "outside.invalid"),
            )
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._rows(), before)

    @unittest.expectedFailure  # source-owner #107 policy field writable
    def test_direct_duck_policy_reassignment_cannot_bypass_denial(self):
        self._assert_cannot_replace(
            lambda executor: setattr(executor, "policy", AllowEverything()),
        )

    @unittest.expectedFailure  # subclass allows policy method override
    def test_direct_subclass_policy_reassignment_cannot_bypass_denial(self):
        self._assert_cannot_replace(
            lambda executor: setattr(executor, "policy", AllowEverythingSubclass()),
        )

    @unittest.expectedFailure  # object setter must not replace lifetime policy
    def test_object_setattr_cannot_replace_policy(self):
        self._assert_cannot_replace(
            lambda executor:
            object.__setattr__(executor, "policy", AllowEverything()),
        )

    @unittest.expectedFailure  # dictionary shadow forbidden
    def test_instance_dictionary_cannot_shadow_policy(self):
        self._assert_cannot_replace(
            lambda executor:
            vars(executor).__setitem__("policy", AllowEverything()),
        )

    @unittest.expectedFailure  # deletion must not erase original policy
    def test_policy_deletion_must_fail_closed_without_effect(self):
        self._assert_cannot_replace(
            lambda executor: delattr(executor, "policy"),
        )

    def test_canonical_policy_denies_out_of_scope_target(self):
        executor = self._executor()
        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context, ToolCall("inert-active-942", "outside.invalid"),
            )
        self.assertIs(executor.policy, self.canonical)
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._rows(), 0)

    def test_canonical_policy_can_authorize_inert_in_scope_control(self):
        executor = self._executor()
        result = executor.execute(
            self.context, ToolCall("inert-active-942", "allowed.invalid"),
        )
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._rows(), 1)

    def test_missing_authorization_rejected_before_handler(self):
        bad_context = RunContext(
            run_id=self.run_id, client_id="client-942",
            engagement_id="engagement-942",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT, authorization=None,
            is_lab=False, created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ToolDenied):
            self._executor().execute(
                bad_context, ToolCall("inert-active-942", "allowed.invalid"),
            )
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._rows(), 0)

    def test_passive_mode_cannot_invoke_active_even_with_grant(self):
        passive = RunContext(
            run_id=self.run_id, client_id="client-942",
            engagement_id="engagement-942",
            mode=AssessmentMode.PASSIVE_DISCOVERY,
            approved_risk=RiskLevel.PASSIVE,
            authorization=self.grant,
            is_lab=False, created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ToolDenied):
            self._executor().execute(
                passive, ToolCall("inert-active-942", "allowed.invalid"),
            )
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._rows(), 0)


if __name__ == "__main__":
    unittest.main()
