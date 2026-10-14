"""Expected-RED demonstration of UNMODIFIED installed policy and ToolExecutor.

All observations use synthetic in-process tools and disposable SQLite only.
Expected failure == unfixed default producer, NOT security acceptance. Do not
remove expectedFailure until original policy/executor owners land the repair.
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from lightup.state import StateStore


def _grant():
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="synthetic-red-grant",
        client_id="synthetic-client",
        engagement_id="synthetic-engagement",
        approved_by="synthetic-reviewer",
        reference="synthetic-grant-no-real-target",
        scope=ScopeDefinition(
            assets=("owned.example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=now - timedelta(minutes=10),
        valid_until=now + timedelta(minutes=10),
    )


def _req(interaction, risk, grant=None):
    return ExecutionRequest(
        interaction=interaction,
        asset="owned.example.test",
        capability_id="web-baseline",
        requested_risk=risk,
        authorization=grant,
    )


class LegacyPolicyExpectedRed(unittest.TestCase):
    @unittest.expectedFailure
    def test_original_policy_must_reject_foreign_active_mode(self):
        # CURRENT BUG: the original policy can reach active-grant evaluation.
        decision = ExecutionPolicy().decide(_req("target_active", RiskLevel.LOW_IMPACT, _grant()))
        self.assertFalse(decision.allowed, "unknown interaction inherited TARGET_ACTIVE")

    @unittest.expectedFailure
    def test_original_policy_must_reject_passive_numeric_risk(self):
        # CURRENT BUG: bool is an int subclass and compares as <= PASSIVE.
        decision = ExecutionPolicy().decide(_req(InteractionKind.PASSIVE_PUBLIC, True))
        self.assertFalse(decision.allowed, "numeric lookalike was treated as RiskLevel")

    def test_original_canonical_unauthorized_active_control_denied(self):
        self.assertFalse(
            ExecutionPolicy().decide(
                _req(InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT)
            ).allowed
        )


class LegacyExecutorExpectedRed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "synthetic.db")
        self.calls = 0
        self.registry = ToolRegistry()

    def _handler(self, context, arguments):
        self.calls += 1
        # Pure bytes; never issues network calls or assessments.
        return ToolOutput("synthetic", "synthetic", b"offline-only")

    def _register(self, interaction, risk, tool_id):
        self.registry.register(
            ToolDefinition(
                tool_id=tool_id,
                capability_id="web-baseline",
                interaction=interaction,
                min_risk=risk,
                description="synthetic expected-RED only",
            ),
            self._handler,
        )

    def _context(self, mode, risk, grant=None):
        return RunContext(
            run_id=str(uuid4()),
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=mode,
            approved_risk=risk,
            authorization=grant,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _count_evidence(self):
        with self.state.connect() as db:
            return db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    @unittest.expectedFailure
    def test_original_executor_must_stop_foreign_mode_before_handler_and_evidence(self):
        self._register("target_active", RiskLevel.LOW_IMPACT, "red-foreign-mode")
        executor = ToolExecutor(self.registry, self.state)
        # Only string test identity and a fake handler: no TARGET_ACTIVE scanning.
        executor.execute(
            self._context(AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD, _grant()),
            ToolCall("red-foreign-mode", "owned.example.test"),
        )
        self.assertEqual(self.calls, 0, "malformed interaction reached handler")
        self.assertEqual(self._count_evidence(), 0, "malformed interaction wrote evidence")

    @unittest.expectedFailure
    def test_original_executor_must_stop_passive_bool_before_handler_and_evidence(self):
        self._register(InteractionKind.PASSIVE_PUBLIC, True, "red-passive-bool")
        executor = ToolExecutor(self.registry, self.state)
        executor.execute(
            self._context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE),
            ToolCall("red-passive-bool", "owned.example.test"),
        )
        self.assertEqual(self.calls, 0, "malformed risk reached handler")
        self.assertEqual(self._count_evidence(), 0, "malformed risk wrote evidence")

    def test_original_executor_canonical_passive_control_remains_successful(self):
        self._register(InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE, "good-passive")
        executor = ToolExecutor(self.registry, self.state)
        result = executor.execute(
            self._context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE),
            ToolCall("good-passive", "owned.example.test"),
        )
        self.assertEqual(result.policy_reason, "public passive discovery")
        self.assertEqual(self.calls, 1)
        self.assertEqual(self._count_evidence(), 1)


if __name__ == "__main__":
    unittest.main()
