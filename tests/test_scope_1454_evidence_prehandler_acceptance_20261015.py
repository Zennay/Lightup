"""Installed-source, entirely inert evidence-before-handler acceptance for #1454.

Expected RED means the production executor still lacks a durable pre-handler
evidence reservation. It is not proof of a real-world target vulnerability.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


_ASSET = "fixture-only.invalid"
_TOOL = "synthetic-evidence-failure"


class EvidenceBeforeHandlerAcceptance(unittest.TestCase):
    """Only mock handler calls and throwaway SQLite; no network or scanning."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-scope-1454-")
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "fixture.db")
        self.run_id = self.state.create_run(
            _ASSET, activation_mode="authorized_assessment",
            authorization_ref="fixture-consent-not-a-real-grant",
        )
        self.handler_calls: list[str] = []
        registry = ToolRegistry()

        def inert_handler(context: RunContext, arguments: dict) -> ToolOutput:
            self.handler_calls.append(context.run_id)
            return ToolOutput(
                summary="fabricated observation",
                evidence_kind="synthetic-observation",
                evidence_payload=b"fabricated-opaque-evidence",
            )

        registry.register(
            ToolDefinition(
                tool_id=_TOOL,
                capability_id="web-baseline",
                interaction=InteractionKind.TARGET_ACTIVE,
                min_risk=RiskLevel.LOW_IMPACT,
                description="inert in-memory handler, never I/O",
            ),
            inert_handler,
        )
        self.executor = ToolExecutor(registry, self.state)
        instant = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="fixture-grant",
            client_id="fictional-tenant",
            engagement_id="fictional-engagement",
            approved_by="fictional-reviewer",
            reference="fixture-only-consent",
            scope=ScopeDefinition(assets=(_ASSET,), max_risk=RiskLevel.LOW_IMPACT),
            valid_from=instant - timedelta(minutes=2),
            valid_until=instant + timedelta(hours=1),
        )
        self.context = RunContext(
            run_id=self.run_id,
            client_id="fictional-tenant",
            engagement_id="fictional-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=False,
            created_at=instant,
        )
        self.call = ToolCall(_TOOL, _ASSET)

    def _make_ledger_unwritable(self) -> None:
        # The schema/connection remain intact: only the insert into evidence
        # fails, after a hypothetical in-memory permitted handler invocation.
        with self.state.connect() as con:
            con.execute("""
                CREATE TRIGGER scope_1454_deny_evidence
                BEFORE INSERT ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'fixture_evidence_unavailable');
                END
            """)

    def _evidence_count(self) -> int:
        with self.state.connect() as con:
            return int(con.execute(
                "SELECT count(*) FROM evidence WHERE run_id=?", (self.run_id,)
            ).fetchone()[0])

    def test_canonical_synthetic_call_writes_exact_evidence(self) -> None:
        result = self.executor.execute(self.context, self.call)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 1)
        record = self.state.get_evidence(result.evidence_id)
        self.assertEqual(record.run_id, self.run_id)
        self.assertEqual(record.source, _TOOL)

    def test_policy_denial_still_precedes_handler_and_ledger(self) -> None:
        self._make_ledger_unwritable()
        invalid = RunContext(
            run_id=self.run_id,
            client_id="fictional-tenant",
            engagement_id="fictional-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=None,
            is_lab=False,
            created_at=self.context.created_at,
        )
        with self.assertRaises(ToolDenied):
            self.executor.execute(invalid, self.call)
        self.assertEqual(self.handler_calls, [])
        self.assertEqual(self._evidence_count(), 0)

    @unittest.expectedFailure
    def test_required_prehandler_durable_attempt_gate_is_still_red(self) -> None:
        """Promote to ordinary PASS only after owner fixes actual admission."""
        self._make_ledger_unwritable()
        with self.assertRaises(ToolDenied):
            self.executor.execute(self.context, self.call)
        self.assertEqual(self.handler_calls, [],
                         "handler must not run after failed ledger admission")
        self.assertEqual(self._evidence_count(), 0)

    def test_actual_sqlite_failure_witness_excludes_false_red(self) -> None:
        """Validate the RED is a real post-handler persistence failure."""
        self._make_ledger_unwritable()
        with self.assertRaisesRegex(sqlite3.IntegrityError,
                                    "^fixture_evidence_unavailable$"):
            self.executor.execute(self.context, self.call)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 0)

    def test_inert_handler_exception_has_no_durable_attempt(self) -> None:
        """Handler-side exceptions also occur after an unlogged invocation."""
        def failing_handler(context: RunContext, arguments: dict) -> ToolOutput:
            self.handler_calls.append(context.run_id)
            raise RuntimeError("fixture_only_handler_exception")

        self.executor.registry.register(
            ToolDefinition(
                "fixture-raising-handler", "web-baseline",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "inert exception witness",
            ),
            failing_handler,
        )
        with self.assertRaisesRegex(RuntimeError,
                                    "^fixture_only_handler_exception$"):
            self.executor.execute(
                self.context, ToolCall("fixture-raising-handler", _ASSET))
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 0)

    def test_malformed_output_is_detected_after_inert_handler(self) -> None:
        """A handler return-type failure cannot create a durable attempt."""
        from lightup.ai.orchestration import OrchestrationError

        def invalid_handler(context: RunContext, arguments: dict):
            self.handler_calls.append(context.run_id)
            return {"not": "a ToolOutput"}

        self.executor.registry.register(
            ToolDefinition(
                "fixture-invalid-output", "web-baseline",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "inert invalid-return witness",
            ),
            invalid_handler,
        )
        with self.assertRaisesRegex(OrchestrationError,
                                    "violated the evidence contract"):
            self.executor.execute(
                self.context, ToolCall("fixture-invalid-output", _ASSET))
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 0)

    def test_evidence_failure_is_not_missing_run_provenance(self) -> None:
        """The rejected insert has an actual persisted matching run parent."""
        with self.state.connect() as con:
            row = con.execute(
                "SELECT run_id, authorization_ref, activation_mode FROM runs "
                "WHERE run_id=?", (self.run_id,)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["run_id"], self.run_id)
        self.assertEqual(
            row["authorization_ref"], "fixture-consent-not-a-real-grant")
        self.assertEqual(row["activation_mode"], "authorized_assessment")
        self._make_ledger_unwritable()
        with self.assertRaisesRegex(sqlite3.IntegrityError,
                                    "^fixture_evidence_unavailable$"):
            self.executor.execute(self.context, self.call)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self._evidence_count(), 0)

    def test_retries_repeat_inert_handler_without_evidence(self) -> None:
        """Characterize replay exposure; no external effects or target I/O."""
        self._make_ledger_unwritable()
        for _ in range(2):
            with self.assertRaisesRegex(sqlite3.IntegrityError,
                                        "^fixture_evidence_unavailable$"):
                self.executor.execute(self.context, self.call)
        self.assertEqual(self.handler_calls, [self.run_id, self.run_id])
        self.assertEqual(self._evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
