"""#944 — ToolExecutor rejects noncanonical outer RunContext identity.

Uses actual source-owner PR #107 ToolExecutor with inert ANALYSIS/LAB handlers.
Synthetic-only; expected RED cases document unresolved source-owner gap.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class DuckContext:
    def __init__(self, canonical):
        self.canonical = canonical
        self.sensitive_reads = []

    def __getattr__(self, name):
        self.sensitive_reads.append(name)
        return getattr(self.canonical, name)


class RunContextSubclass(RunContext):
    pass


class ActiveLabImpersonatingContext:
    """Unknown caller-owned shape impersonating an elevated lab context."""
    def __init__(self, canonical):
        self.original = canonical

    def __getattr__(self, name):
        if name == "is_lab":
            return True
        if name == "mode":
            return AssessmentMode.LAB_AUTONOMOUS
        if name == "approved_risk":
            return RiskLevel.DESTRUCTIVE_LAB_ONLY
        return getattr(self.original, name)


class RunContextIdentity944(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-944-")
        self.addCleanup(temp.cleanup)
        self.state = StateStore(Path(temp.name) / "authentic.sqlite")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only",
        )
        self.registry = ToolRegistry()
        self.invocations = []
        self.registry.register(
            ToolDefinition(
                "synthetic-analysis-944", "network-services",
                InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                "never network, only memory",
            ),
            self._handler,
        )
        self.registry.register(
            ToolDefinition(
                "synthetic-lab-944", "web-baseline",
                InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                "never network, only memory",
            ),
            self._handler,
        )
        self.executor = ToolExecutor(self.registry, self.state)

        self.canonical = RunContext(
            run_id=self.run_id, client_id="client-synthetic",
            engagement_id="engagement-synthetic",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _handler(self, context, args):
        self.invocations.append(context)
        return ToolOutput("offline", "synthetic", b"offline")

    def _rows(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _deny_before_effects(self, context, tool="synthetic-analysis-944"):
        before = self._rows()
        with self.assertRaises(ToolDenied):
            self.executor.execute(context, ToolCall(tool, "synthetic.invalid"))
        self.assertEqual(self.invocations, [])
        self.assertEqual(self._rows(), before)

    @unittest.expectedFailure  # #944 original accepts structurally similar duck
    def test_duck_runcontext_must_be_rejected_before_sensitive_reads(self):
        duck = DuckContext(self.canonical)
        self._deny_before_effects(duck)
        self.assertEqual(duck.sensitive_reads, [])

    @unittest.expectedFailure  # frozen dataclass subclasses are still not exact
    def test_runcontext_subclass_must_be_rejected(self):
        subclass = RunContextSubclass(**vars(self.canonical))
        self._deny_before_effects(subclass)

    @unittest.expectedFailure  # duck can impersonate lab mode/risk
    def test_duck_context_cannot_claim_elevated_lab_authority(self):
        duck = ActiveLabImpersonatingContext(self.canonical)
        self._deny_before_effects(duck, "synthetic-lab-944")

    @unittest.expectedFailure  # a subclass can carry altered mode attributes
    def test_subclass_claiming_lab_permission_must_be_rejected(self):
        lab = replace(
            self.canonical, mode=AssessmentMode.LAB_AUTONOMOUS,
            approved_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY, is_lab=True,
        )
        subclass = RunContextSubclass(**vars(lab))
        self._deny_before_effects(subclass, "synthetic-lab-944")

    @unittest.expectedFailure  # rejection must precede even a failing duck getter
    def test_duck_canary_rejects_before_attribute_resolution(self):
        class Canary:
            def __getattr__(self, key):
                raise AssertionError("untrusted RunContext attribute was evaluated")
        self._deny_before_effects(Canary())

    def test_exact_analysis_run_context_allows_inert_execution(self):
        result = self.executor.execute(
            self.canonical, ToolCall("synthetic-analysis-944", "synthetic.invalid")
        )
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.invocations, [self.canonical])
        self.assertEqual(self._rows(), 1)

    def test_exact_lab_context_allows_inert_lab_tool(self):
        lab = RunContext.for_lab(run_id=self.run_id)
        result = self.executor.execute(
            lab, ToolCall("synthetic-lab-944", "synthetic.invalid")
        )
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.invocations, [lab])
        self.assertEqual(self._rows(), 1)

    def test_canonical_analysis_context_cannot_run_lab_tool(self):
        self._deny_before_effects(self.canonical, "synthetic-lab-944")

    def test_exact_low_risk_context_cannot_run_lab_tool(self):
        low = replace(
            self.canonical, mode=AssessmentMode.LAB_AUTONOMOUS,
            approved_risk=RiskLevel.PASSIVE, is_lab=True,
        )
        before = self._rows()
        from lightup.ai.orchestration import RiskElevationRequired
        with self.assertRaises(RiskElevationRequired):
            self.executor.execute(low, ToolCall("synthetic-lab-944", "synthetic.invalid"))
        self.assertEqual(self.invocations, [])
        self.assertEqual(self._rows(), before)


if __name__ == "__main__":
    unittest.main()
