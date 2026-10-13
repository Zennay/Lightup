"""Issue #946 — real executor rejects untrusted outer ToolCall objects.

No network: registered ANALYSIS handler only, reserved .invalid asset,
disposable SQLite. Intentionally expected RED are source-owner defects.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolDenied, ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class DuckToolCall:
    def __init__(self):
        self.fields_read = []
        self.arguments_extracted = 0

    def __getattr__(self, field):
        self.fields_read.append(field)
        if field == "tool_id":
            return "inert-analysis-946"
        if field == "asset":
            return "synthetic.invalid"
        raise AttributeError(field)

    def arguments_dict(self):
        self.arguments_extracted += 1
        return {"query": "offline"}


class ToolCallSubclass(ToolCall):
    pass


class OverridingToolCall(ToolCall):
    def arguments_dict(self):
        return {"query": "altered-by-subclass"}


class CanaryToolCall:
    def __getattr__(self, name):
        raise AssertionError("untrusted ToolCall getter accessed")


class CanonicalToolCall946(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-946-")
        self.addCleanup(temp.cleanup)
        self.state = StateStore(Path(temp.name) / "evidence.sqlite")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        self.registry = ToolRegistry()
        self.calls = []
        self.registry.register(
            ToolDefinition(
                "inert-analysis-946", "network-services",
                InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                "inert test-only analysis",
                (ToolParameter("query", ParamKind.STRING),),
            ),
            self._handler,
        )
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext(
            run_id=self.run_id,
            client_id="synthetic-client", engagement_id="synthetic-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        self.canonical = ToolCall(
            "inert-analysis-946", "synthetic.invalid",
            arguments=(("query", "offline"),),
        )

    def _handler(self, context, arguments):
        self.calls.append(arguments.copy())
        return ToolOutput("offline", "test", b"test-only")

    def _count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _require_early_rejection(self, untrusted):
        before = self._count()
        with patch.object(self.registry, "get", wraps=self.registry.get) as get_tool:
            with self.assertRaises(ToolDenied):
                self.executor.execute(self.context, untrusted)
            get_tool.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), before)

    @unittest.expectedFailure  # #946 untrusted duck accepted by source owner
    def test_duck_toolcall_is_denied_before_registry_lookup(self):
        duck = DuckToolCall()
        self._require_early_rejection(duck)
        self.assertEqual(duck.fields_read, [])
        self.assertEqual(duck.arguments_extracted, 0)

    @unittest.expectedFailure  # frozen RunContext does not imply ToolCall subclasses canonical
    def test_toolcall_subclass_is_denied_before_registry_lookup(self):
        subclass = ToolCallSubclass(
            "inert-analysis-946", "synthetic.invalid",
            arguments=(("query", "offline"),),
        )
        self._require_early_rejection(subclass)

    @unittest.expectedFailure  # subclass method can replace argument extraction
    def test_toolcall_subclass_overriding_arguments_dict_is_denied(self):
        subclass = OverridingToolCall(
            "inert-analysis-946", "synthetic.invalid",
            arguments=(("query", "offline"),),
        )
        self._require_early_rejection(subclass)

    @unittest.expectedFailure  # do not even touch attacker-owned getter before denial
    def test_canary_denied_without_invoking_getter(self):
        self._require_early_rejection(CanaryToolCall())

    def test_canonical_toolcall_executes_once_with_exact_arguments(self):
        result = self.executor.execute(self.context, self.canonical)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.calls, [{"query": "offline"}])
        self.assertEqual(self._count(), 1)

    def test_unknown_exact_toolcall_is_denied_before_handler(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("unknown-synthetic-946", "synthetic.invalid"),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), 0)

    def test_missing_exact_arguments_denied_before_handler(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("inert-analysis-946", "synthetic.invalid"),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), 0)

    def test_invalid_exact_argument_type_denied_before_handler(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("inert-analysis-946", "synthetic.invalid",
                         arguments=(("query", 42),)),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), 0)

    def test_unregistered_tool_never_creates_evidence(self):
        before = self._count()
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("never-registered-946", "synthetic.invalid",
                         arguments=(("query", "offline"),)),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self._count(), before)


if __name__ == "__main__":
    unittest.main()
