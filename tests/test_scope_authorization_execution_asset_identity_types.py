from __future__ import annotations

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


class CanonicalizationSpoof(str):
    """Foreign underlying asset that lies during scope canonicalization."""

    def strip(self, chars: str | None = None) -> str:
        return "allowed.test"


class MatchingAssetSubclass(str):
    """Textually canonical but still a non-canonical runtime identity type."""


class ExecutionAssetIdentityTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.domain = DomainStore(root / "domain.db")
        self.state = StateStore(root / "state.db")
        self.operator = AccessContext("op-asset-type", Role.OPERATOR)
        self.client = self.domain.create_client(
            self.operator, "Execution Asset Type Client"
        )
        self.engagement = self.domain.create_engagement(
            self.operator,
            self.client.client_id,
            "Execution asset identity type",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.domain.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Asset Type",
            "AUTH-ASSET-TYPE-001",
            ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            now - timedelta(minutes=5),
            now + timedelta(hours=1),
        )

        self.observed: list[str] = []
        registry = ToolRegistry()

        def handler(context: RunContext, arguments: dict[str, object]) -> ToolOutput:
            self.observed.append(context.authorization.grant_id if context.authorization else "")
            return ToolOutput("ran", "probe", b"asset-type-evidence")

        registry.register(
            ToolDefinition(
                "asset-type-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "inert target-active asset identity regression",
            ),
            handler,
        )
        self.executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=self.domain.resolve_authorization_for_execution,
        )
        self.context = RunContext(
            run_id=str(uuid4()),
            client_id=self.client.client_id,
            engagement_id=self.engagement.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=self.grant,
            is_lab=False,
            created_at=now,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _state_counts(self) -> tuple[int, int, int]:
        with self.state.connect() as con:
            return tuple(
                con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("runs", "capability_leases", "evidence")
            )

    def _execute(self, asset: str) -> None:
        self.executor.execute(
            self.context,
            ToolCall("asset-type-probe", asset),
        )

    def _assert_denied_without_state_write(self, asset: str) -> None:
        before = self._state_counts()
        with self.assertRaises(ToolDenied):
            self._execute(asset)
        self.assertEqual(self.observed, [])
        self.assertEqual(self._state_counts(), before)

    def test_canonical_exact_asset_remains_executable(self) -> None:
        self._execute("allowed.test")
        self.assertEqual(self.observed, [self.grant.grant_id])

    def test_plain_foreign_asset_remains_denied(self) -> None:
        self._assert_denied_without_state_write("foreign.test")

    def test_polymorphic_foreign_asset_cannot_spoof_canonicalization(self) -> None:
        forged = CanonicalizationSpoof("foreign.test")
        self.assertEqual(str(forged), "foreign.test")
        self.assertEqual(forged.strip(), "allowed.test")
        self.assertIsNot(type(forged), str)
        self._assert_denied_without_state_write(forged)

    def test_polymorphic_matching_asset_is_still_denied(self) -> None:
        forged = MatchingAssetSubclass("allowed.test")
        self.assertEqual(str(forged), "allowed.test")
        self.assertIsNot(type(forged), str)
        self._assert_denied_without_state_write(forged)


if __name__ == "__main__":
    unittest.main()
