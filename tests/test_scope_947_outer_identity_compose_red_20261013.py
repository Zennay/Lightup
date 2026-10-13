"""Issue #947: compose exact outer RunContext and ToolCall gates.

All calls are inert ANALYSIS-only with disposable SQLite and a reserved
.invalid asset; intentionally expected REDs remain release blockers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, RunContext, ToolCall, ToolDefinition, ToolDenied,
    ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class UntrustedContext:
    """Probe must never be accessed by executor authorization code."""
    def __init__(self):
        self.reads = []

    def __getattr__(self, name):
        self.reads.append(name)
        raise AssertionError("noncanonical RunContext getter executed")


class UntrustedCall:
    """Probe must never be accessed ahead of exact ToolCall validation."""
    def __init__(self):
        self.reads = []

    def __getattr__(self, name):
        self.reads.append(name)
        raise AssertionError("noncanonical ToolCall getter executed")


class ContextSubclass(RunContext):
    pass


class CallSubclass(ToolCall):
    pass


class ComposedOuterObjectIdentity947(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-947-")
        self.addCleanup(tmp.cleanup)
        self.state = StateStore(Path(tmp.name) / "test.sqlite")
        run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        self.registry = ToolRegistry()
        self.handler_calls = 0
        self.registry.register(
            ToolDefinition(
                "inert-composed-947", "network-services",
                InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                "pure in-memory test", (),
            ),
            self._handler,
        )
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext(
            run_id=run_id, client_id="synthetic", engagement_id="synthetic",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        self.call = ToolCall("inert-composed-947", "synthetic.invalid")

    def _handler(self, _context, _arguments):
        self.handler_calls += 1
        return ToolOutput("synthetic", "test", b"inert")

    def _evidence(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    @unittest.expectedFailure  # source owner must reject both before any field read
    def test_double_duck_denied_without_reading_either_probe(self):
        context = UntrustedContext()
        call = UntrustedCall()
        before = self._evidence()
        with patch.object(self.registry, "get", wraps=self.registry.get) as registry_get:
            with self.assertRaises((ToolDenied, OrchestrationError)):
                self.executor.execute(context, call)
            registry_get.assert_not_called()
        self.assertEqual(context.reads, [])
        self.assertEqual(call.reads, [])
        self.assertEqual(self.handler_calls, 0)
        self.assertEqual(self._evidence(), before)

    @unittest.expectedFailure  # frozen dataclass subclasses are not exact authority
    def test_two_subclasses_denied_before_registry_or_evidence(self):
        context = ContextSubclass(**vars(self.context))
        call = CallSubclass(**vars(self.call))
        before = self._evidence()
        with patch.object(self.registry, "get", wraps=self.registry.get) as registry_get:
            with self.assertRaises((ToolDenied, OrchestrationError)):
                self.executor.execute(context, call)
            registry_get.assert_not_called()
        self.assertEqual(self.handler_calls, 0)
        self.assertEqual(self._evidence(), before)

    def test_exact_context_and_call_still_run_analysis_once(self):
        before = self._evidence()
        result = self.executor.execute(self.context, self.call)
        self.assertEqual(result.run_id, self.context.run_id)
        self.assertEqual(self.handler_calls, 1)
        self.assertEqual(self._evidence(), before + 1)


if __name__ == "__main__":
    unittest.main()
