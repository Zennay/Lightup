from __future__ import annotations

import dataclasses
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolDenied,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel, ScopeDefinition
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class _AdaptiveGrantId:
    def __init__(self, durable_id: str) -> None:
        self.durable_id = durable_id

    def __conform__(self, protocol):
        if protocol is sqlite3.PrepareProtocol:
            return self.durable_id
        return None

    def __eq__(self, other: object) -> bool:
        return other == self.durable_id

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class _GrantIdSubclass(str):
    pass


class LiveGrantIdentifierIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.domain = DomainStore(root / "domain.db")
        self.state = StateStore(root / "state.db")
        self.operator = AccessContext("grant-id-operator", Role.OPERATOR)
        client = self.domain.create_client(self.operator, "Grant ID Client")
        self.engagement = self.domain.create_engagement(
            self.operator, client.client_id, "Grant ID Engagement"
        )
        now = datetime.now(timezone.utc)
        self.grant = self.domain.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            approved_by="client signatory",
            reference="AUTH-GRANT-ID",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        self.context = RunContext(
            run_id=str(uuid4()),
            client_id=client.client_id,
            engagement_id=self.engagement.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=self.grant,
            is_lab=False,
            created_at=now,
        )
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "grant-id-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "test-only target-active handler",
            ),
            lambda context, arguments: (
                self.calls.append("ran")
                or ToolOutput("ran", "probe", b"evidence")
            ),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _evidence_count(self) -> int:
        with self.state.connect() as con:
            return int(con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])

    def test_canonical_exact_grant_id_remains_executable(self) -> None:
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=self.domain.resolve_authorization_for_execution,
        )

        executor.execute(
            self.context,
            ToolCall("grant-id-probe", "allowed.test"),
        )

        self.assertEqual(self.calls, ["ran"])
        self.assertEqual(self._evidence_count(), 1)

    def test_sqlite_adaptable_grant_id_cannot_cross_live_resolution(self) -> None:
        forged = dataclasses.replace(
            self.grant,
            grant_id=_AdaptiveGrantId(self.grant.grant_id),  # type: ignore[arg-type]
        )
        forged_context = dataclasses.replace(self.context, authorization=forged)
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=self.domain.resolve_authorization_for_execution,
        )

        with self.assertRaises((TypeError, ValueError, ToolDenied)):
            executor.execute(
                forged_context,
                ToolCall("grant-id-probe", "allowed.test"),
            )

        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence_count(), 0)

    def test_matching_text_str_subclass_is_noncanonical(self) -> None:
        forged = dataclasses.replace(
            self.grant,
            grant_id=_GrantIdSubclass(self.grant.grant_id),
        )
        forged_context = dataclasses.replace(self.context, authorization=forged)
        executor = ToolExecutor(
            self.registry,
            self.state,
            authorization_resolver=self.domain.resolve_authorization_for_execution,
        )

        with self.assertRaises((TypeError, ValueError, ToolDenied)):
            executor.execute(
                forged_context,
                ToolCall("grant-id-probe", "allowed.test"),
            )

        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
