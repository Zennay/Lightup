from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    OrchestrationError,
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class _RunContextSubclass(RunContext):
    pass


class _DuckRunContext:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.client_id = "client-1"
        self.engagement_id = "engagement-1"
        self.mode = AssessmentMode.ANALYSIS_ONLY
        self.approved_risk = RiskLevel.ANALYSIS_ONLY
        self.authorization = None
        self.is_lab = False
        self.created_at = datetime.now(timezone.utc)


class ToolExecutorRunContextIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "context-identity-probe",
                "external-attack-surface",
                InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY,
                "offline test-only context identity probe",
            ),
            lambda context, arguments: (
                self.calls.append("ran")
                or ToolOutput("ran", "test", b"offline")
            ),
        )
        self.executor = ToolExecutor(self.registry, self.state)

    def exact_context(self, run_id: str) -> RunContext:
        return RunContext(
            run_id=run_id,
            client_id="client-1",
            engagement_id="engagement-1",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_exact_run_context_remains_accepted(self):
        result = self.executor.execute(
            self.exact_context("run-context-exact"),
            ToolCall("context-identity-probe", "offline.test"),
        )

        self.assertEqual(result.run_id, "run-context-exact")
        self.assertEqual(self.calls, ["ran"])

    def test_run_context_subclass_is_rejected_before_handler(self):
        exact = self.exact_context("run-context-subclass")
        context = _RunContextSubclass(
            run_id=exact.run_id,
            client_id=exact.client_id,
            engagement_id=exact.engagement_id,
            mode=exact.mode,
            approved_risk=exact.approved_risk,
            authorization=exact.authorization,
            is_lab=exact.is_lab,
            created_at=exact.created_at,
        )

        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                context,
                ToolCall("context-identity-probe", "offline.test"),
            )

        self.assertEqual(self.calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-context-subclass",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)

    def test_duck_run_context_is_rejected_before_handler(self):
        context = _DuckRunContext("run-context-duck")

        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                context,
                ToolCall("context-identity-probe", "offline.test"),
            )

        self.assertEqual(self.calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-context-duck",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)


if __name__ == "__main__":
    unittest.main()
