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


class _ToolCallSubclass(ToolCall):
    pass


class _DuckToolCall:
    def __init__(self):
        self.tool_id = "call-identity-probe"
        self.asset = "offline.test"

    def arguments_dict(self):
        return {}


class ToolExecutorToolCallIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "call-identity-probe",
                "external-attack-surface",
                InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY,
                "offline test-only call identity probe",
            ),
            lambda context, arguments: (
                self.calls.append("ran")
                or ToolOutput("ran", "test", b"offline")
            ),
        )
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext(
            run_id="run-call-identity",
            client_id="client-1",
            engagement_id="engagement-1",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_exact_tool_call_remains_accepted(self):
        result = self.executor.execute(
            self.context,
            ToolCall("call-identity-probe", "offline.test"),
        )

        self.assertEqual(result.tool_id, "call-identity-probe")
        self.assertEqual(self.calls, ["ran"])

    def test_tool_call_subclass_is_rejected_before_handler(self):
        call = _ToolCallSubclass("call-identity-probe", "offline.test")

        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, call)

        self.assertEqual(self.calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-call-identity",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)

    def test_duck_tool_call_is_rejected_before_handler(self):
        call = _DuckToolCall()

        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, call)

        self.assertEqual(self.calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-call-identity",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)


if __name__ == "__main__":
    unittest.main()
