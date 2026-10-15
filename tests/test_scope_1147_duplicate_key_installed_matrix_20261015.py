"""Issue #1147: installed ToolExecutor duplicate-key characterization (offline).

Deliberately isolated, fictional ANALYSIS-only records; NO live scope, target,
networking, actual handlers, grants, production fixes, or release authority.

Two expected failures are REQUIREMENTS, not remediations. Ordinary PASS
witnesses must verify the *specific* unsafe last-value-wins behavior; this
prevents an unrelated crash from silently masquerading as a meaningful RED.
When source owners fix #1147, invert/remove unsafe witnesses and replace
expected failures with ordinary explicit deny/no-handler/no-evidence PASS.
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    OrchestrationError,
    ParamKind,
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolExecutor,
    ToolOutput,
    ToolParameter,
    ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class DuplicateArgumentKeysInstalledSource1147(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.state = StateStore(Path(self.tempdir.name) / "fictional-only.sqlite3")
        self.run_id = self.state.create_run(
            target="fixture-only.invalid", activation_mode="plan_only"
        )
        self.context = RunContext(
            run_id=self.run_id,
            client_id="fixture-client",
            engagement_id="fixture-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        self.calls: list[dict[str, object]] = []

        def inert_handler(_context: RunContext, args: dict[str, object]) -> ToolOutput:
            self.calls.append(dict(args))
            return ToolOutput(
                summary="fixture-only analysis",
                evidence_kind="note",
                evidence_payload=b"fixture-no-target-no-execution",
            )

        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                tool_id="fixture-analysis",
                capability_id="web-baseline",
                interaction=InteractionKind.ANALYSIS,
                min_risk=RiskLevel.ANALYSIS_ONLY,
                description="inert local fixture: no network, no execution",
                parameters=(
                    ToolParameter("selector", ParamKind.STRING),
                    ToolParameter("note", ParamKind.STRING, required=False),
                ),
            ),
            inert_handler,
        )
        self.executor = ToolExecutor(registry, self.state)

    def evidence_count(self) -> int:
        with self.state.connect() as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id = ?", (self.run_id,)
            ).fetchone()[0]

    def call(self, *pairs: tuple[str, object]) -> ToolCall:
        return ToolCall(
            tool_id="fixture-analysis",
            asset="fixture-only.invalid",
            arguments=tuple(pairs),
        )

    def test_unique_names_permit_exact_once_with_durable_evidence(self):
        result = self.executor.execute(
            self.context, self.call(("selector", "a"), ("note", "b"))
        )
        self.assertEqual(self.calls, [{"selector": "a", "note": "b"}])
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.state.get_evidence(result.evidence_id).run_id, self.run_id)

    def test_unknown_name_is_rejected_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context, self.call(("selector", "safe"), ("other", "unknown"))
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_wrong_type_is_rejected_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, self.call(("selector", 17))
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_current_source_duplicate_string_uses_last_value_not_first(self):
        # A POSITIVE witness for the current unsafe source, not safe behavior.
        result = self.executor.execute(
            self.context, self.call(("selector", "first"), ("selector", "last"))
        )
        self.assertEqual(self.calls, [{"selector": "last"}])
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.state.get_evidence(result.evidence_id).source, "fixture-analysis")

    def test_current_source_invalid_first_value_evades_schema_via_last_value(self):
        # Specifically proves validation sees dict()-collapsed data, not both values.
        result = self.executor.execute(
            self.context, self.call(("selector", 17), ("selector", "valid-last"))
        )
        self.assertEqual(self.calls, [{"selector": "valid-last"}])
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.state.get_evidence(result.evidence_id).run_id, self.run_id)

    def test_current_source_duplicate_optional_parameter_is_silently_collapsed(self):
        self.executor.execute(
            self.context,
            self.call(("selector", "unique"), ("note", "old"), ("note", "new")),
        )
        self.assertEqual(self.calls, [{"selector": "unique", "note": "new"}])
        self.assertEqual(self.evidence_count(), 1)

    def test_current_source_equal_duplicate_values_still_invoke_handler(self):
        # Even equal repeated keys are structurally ambiguous and must be denied.
        result = self.executor.execute(
            self.context, self.call(("selector", "same"), ("selector", "same"))
        )
        self.assertEqual(self.calls, [{"selector": "same"}])
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.state.get_evidence(result.evidence_id).run_id, self.run_id)

    def test_current_source_interleaved_triple_duplicate_uses_last(self):
        result = self.executor.execute(
            self.context,
            self.call(
                ("selector", "first"), ("note", "distinct"),
                ("selector", "middle"), ("selector", "last"),
            ),
        )
        self.assertEqual(self.calls, [{"selector": "last", "note": "distinct"}])
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.state.get_evidence(result.evidence_id).run_id, self.run_id)

    @unittest.expectedFailure
    def test_required_denial_of_identical_duplicate_keys_before_any_effect(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context, self.call(("selector", "same"), ("selector", "same"))
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_required_denial_of_interleaved_triple_keys_before_any_effect(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                self.call(
                    ("selector", "first"), ("note", "distinct"),
                    ("selector", "middle"), ("selector", "last"),
                ),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_required_denial_of_duplicate_valid_keys_before_any_effect(self):
        # Expected source RED. On a fixed source: ordinary PASS, never XFAIL.
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context, self.call(("selector", "first"), ("selector", "last"))
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_required_denial_of_duplicate_type_confusion_before_any_effect(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context, self.call(("selector", 17), ("selector", "valid-last"))
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_required_denial_of_duplicate_optional_keys_before_any_effect(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                self.call(("selector", "unique"), ("note", "old"), ("note", "new")),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
