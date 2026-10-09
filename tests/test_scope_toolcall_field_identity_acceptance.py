from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

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
from lightup.engagements import (
    AssessmentMode,
    AuthorizationGrant,
    RiskLevel,
    ScopeDefinition,
)
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class _StringSubclass(str):
    pass


def _grant(asset: str) -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="field-id-grant",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-FIELD-ID",
        scope=ScopeDefinition(
            assets=(asset,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("network-services",),
        ),
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(hours=1),
    )


def _context(asset: str) -> RunContext:
    return RunContext(
        run_id=str(uuid4()),
        client_id="client-1",
        engagement_id="engagement-1",
        mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
        approved_risk=RiskLevel.STANDARD,
        authorization=_grant(asset),
        is_lab=False,
        created_at=datetime.now(timezone.utc),
    )


class ToolCallFieldIdentityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.calls: list[dict[str, object]] = []
        self.registry = ToolRegistry()

        def handler(context, arguments):
            self.calls.append(dict(arguments))
            return ToolOutput(
                summary=f"received:{arguments['target']}",
                evidence_kind="acceptance",
                evidence_payload=b"field-identity",
            )

        self.registry.register(
            ToolDefinition(
                tool_id="parameterized-probe",
                capability_id="network-services",
                interaction=InteractionKind.TARGET_ACTIVE,
                min_risk=RiskLevel.STANDARD,
                description="Inert field-identity acceptance handler",
                parameters=(
                    ToolParameter("target", ParamKind.STRING, required=True),
                ),
            ),
            handler,
        )
        self.executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=lambda grant: grant,
        )
        self.context = _context("allowed.test")

    def tearDown(self):
        self.tmp.cleanup()

    def _evidence_count(self) -> int:
        with self.state.connect() as con:
            row = con.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()
        return int(row["n"])

    def test_canonical_exact_string_fields_preserve_current_behavior(self):
        result = self.executor.execute(
            self.context,
            ToolCall(
                "parameterized-probe",
                "allowed.test",
                arguments=(("target", "allowed.test"),),
            ),
        )
        self.assertEqual(result.tool_id, "parameterized-probe")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self._evidence_count(), 1)

    def test_tool_id_string_subclass_fails_before_registry_or_handler_effects(self):
        call = ToolCall(
            _StringSubclass("parameterized-probe"),
            "allowed.test",
            arguments=(("target", "allowed.test"),),
        )

        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, call)

        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence_count(), 0)

    def test_argument_key_string_subclass_fails_before_handler_and_evidence(self):
        call = ToolCall(
            "parameterized-probe",
            "allowed.test",
            arguments=((_StringSubclass("target"), "allowed.test"),),
        )

        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, call)

        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
