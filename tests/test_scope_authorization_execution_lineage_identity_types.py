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


class EqualitySpoof(str):
    """Different underlying identity that lies about equality."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    __hash__ = str.__hash__


class ExecutionLineageIdentityTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.domain = DomainStore(root / "domain.db")
        self.state = StateStore(root / "state.db")
        self.operator = AccessContext("op-lineage-type", Role.OPERATOR)
        self.client = self.domain.create_client(
            self.operator, "Execution Lineage Type Client"
        )
        self.engagement = self.domain.create_engagement(
            self.operator,
            self.client.client_id,
            "Execution lineage identity type",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.domain.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Lineage",
            "AUTH-LINEAGE-TYPE-001",
            ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            now - timedelta(minutes=5),
            now + timedelta(hours=1),
        )

        self.observed: list[tuple[str, str]] = []
        registry = ToolRegistry()

        def handler(context: RunContext, arguments: dict[str, object]) -> ToolOutput:
            self.observed.append((context.client_id, context.engagement_id))
            return ToolOutput("ran", "probe", b"lineage-type-evidence")

        registry.register(
            ToolDefinition(
                "lineage-type-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "inert target-active lineage binding regression",
            ),
            handler,
        )
        self.executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=self.domain.resolve_authorization_for_execution,
        )
        self.now = now

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _context(
        self,
        *,
        client_id: str | None = None,
        engagement_id: str | None = None,
    ) -> RunContext:
        return RunContext(
            run_id=str(uuid4()),
            client_id=self.client.client_id if client_id is None else client_id,
            engagement_id=(
                self.engagement.engagement_id
                if engagement_id is None
                else engagement_id
            ),
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=self.grant,
            is_lab=False,
            created_at=self.now,
        )

    def _execute(self, context: RunContext) -> None:
        self.executor.execute(
            context,
            ToolCall("lineage-type-probe", "allowed.test"),
        )

    def test_canonical_exact_lineage_remains_executable(self) -> None:
        self._execute(self._context())
        self.assertEqual(
            self.observed,
            [(self.client.client_id, self.engagement.engagement_id)],
        )

    def test_plain_cross_client_identity_remains_denied(self) -> None:
        with self.assertRaises(ToolDenied):
            self._execute(self._context(client_id="foreign-client"))
        self.assertEqual(self.observed, [])

    def test_plain_cross_engagement_identity_remains_denied(self) -> None:
        with self.assertRaises(ToolDenied):
            self._execute(self._context(engagement_id="foreign-engagement"))
        self.assertEqual(self.observed, [])

    def test_polymorphic_client_identity_cannot_equality_spoof_binding(self) -> None:
        forged = EqualitySpoof("foreign-client")
        self.assertNotEqual(str(forged), self.client.client_id)

        try:
            self._execute(self._context(client_id=forged))
        except ToolDenied:
            pass
        else:
            self.fail(
                "polymorphic foreign client_id crossed TARGET_ACTIVE binding; "
                f"handler observed {self.observed!r}"
            )

        self.assertEqual(self.observed, [])

    def test_polymorphic_engagement_identity_cannot_equality_spoof_binding(self) -> None:
        forged = EqualitySpoof("foreign-engagement")
        self.assertNotEqual(str(forged), self.engagement.engagement_id)

        try:
            self._execute(self._context(engagement_id=forged))
        except ToolDenied:
            pass
        else:
            self.fail(
                "polymorphic foreign engagement_id crossed TARGET_ACTIVE binding; "
                f"handler observed {self.observed!r}"
            )

        self.assertEqual(self.observed, [])

    def test_polymorphic_matching_client_identity_is_still_denied(self) -> None:
        forged = EqualitySpoof(self.client.client_id)
        self.assertEqual(str(forged), self.client.client_id)
        self.assertIsNot(type(forged), str)

        try:
            self._execute(self._context(client_id=forged))
        except ToolDenied:
            pass
        else:
            self.fail(
                "polymorphic matching client_id crossed TARGET_ACTIVE type boundary; "
                f"handler observed {self.observed!r}"
            )

        self.assertEqual(self.observed, [])

    def test_polymorphic_matching_engagement_identity_is_still_denied(self) -> None:
        forged = EqualitySpoof(self.engagement.engagement_id)
        self.assertEqual(str(forged), self.engagement.engagement_id)
        self.assertIsNot(type(forged), str)

        try:
            self._execute(self._context(engagement_id=forged))
        except ToolDenied:
            pass
        else:
            self.fail(
                "polymorphic matching engagement_id crossed TARGET_ACTIVE type boundary; "
                f"handler observed {self.observed!r}"
            )

        self.assertEqual(self.observed, [])


if __name__ == "__main__":
    unittest.main()
