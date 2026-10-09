"""Real ToolExecutor finite-number tripwire on a synthetic local lab."""
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class OfflineExecutorNumberTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "lab.sqlite3")
        self.calls = []
        self.registry = ToolRegistry()
        definition = ToolDefinition(
            "number-lab-only", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "Offline fixture",
            (ToolParameter("value", ParamKind.NUMBER),),
        )

        def handler(context, arguments):
            self.calls.append(arguments["value"])
            return ToolOutput("local fixture", "fixture", b"local-evidence")

        self.registry.register(definition, handler)
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext.for_lab(run_id="number-only-lab")

    def invoke(self, value):
        return self.executor.execute(
            self.context,
            ToolCall("number-lab-only", "127.0.0.1", (("value", value),)),
        )

    def evidence_count(self):
        with self.state.connect() as db:
            return db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def test_finite_control_dispatches_once_with_evidence(self):
        result = self.invoke(2.5)
        self.assertEqual(self.calls, [2.5])
        self.assertEqual(self.evidence_count(), 1)
        self.assertTrue(result.evidence_id)

    def test_boolean_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_missing_number_argument_does_not_dispatch_or_write_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context, ToolCall("number-lab-only", "127.0.0.1")
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_unknown_argument_does_not_dispatch_or_write_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1",
                         (("value", 1.0), ("untrusted_extra", 1))),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_denial_after_success_does_not_add_evidence(self):
        self.invoke(1.5)
        before_calls, before_evidence = len(self.calls), self.evidence_count()
        with self.assertRaises(OrchestrationError):
            self.invoke(False)
        self.assertEqual(len(self.calls), before_calls)
        self.assertEqual(self.evidence_count(), before_evidence)

    def test_string_value_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke("2.5")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_none_value_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(None)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_optional_number_argument_cannot_be_replaced_by_unknown_key(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1", (("limit", 2.5),)),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_nan_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(float("nan"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_positive_infinity_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(float("inf"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_negative_infinity_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(float("-inf"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
