from __future__ import annotations

import dataclasses
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    OrchestrationError,
    ParamKind,
    RiskElevationRequired,
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolDenied,
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


def _passive_tool(context, arguments):
    return ToolOutput("looked at public records", "note",
                      f"passive:{arguments['query']}".encode())


def _active_tool(context, arguments):
    return ToolOutput("probed service", "probe", b"active-evidence")


def _grant(asset: str, max_risk: RiskLevel = RiskLevel.STANDARD) -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="g1", client_id="c1", engagement_id="e1",
        approved_by="op", reference="AUTH-1",
        scope=ScopeDefinition(
            assets=(asset,),
            max_risk=max_risk,
            allowed_capabilities=("network-services", "identity-access", "web-baseline"),
        ),
        valid_from=now - timedelta(hours=1), valid_until=now + timedelta(days=1),
    )


def _context(mode: AssessmentMode, risk: RiskLevel, authorization=None,
             is_lab: bool = False) -> RunContext:
    return RunContext(
        run_id=str(uuid4()), client_id="c1", engagement_id="e1", mode=mode,
        approved_risk=risk, authorization=authorization, is_lab=is_lab,
        created_at=datetime.now(timezone.utc),
    )


class OrchestrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "public-records", "external-attack-surface",
                InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE,
                "Public, non-intrusive records lookup",
                (ToolParameter("query", ParamKind.STRING),),
            ),
            _passive_tool,
        )
        self.registry.register(
            ToolDefinition(
                "service-probe", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.STANDARD,
                "Active service probe (authorized targets only)",
            ),
            _active_tool,
        )
        self.registry.register(
            ToolDefinition(
                "lab-exploit-sim", "web-baseline",
                InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                "Destructive simulation, isolated lab only",
            ),
            _active_tool,
        )
        self.executor = ToolExecutor(self.registry, self.state)

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_context_is_immutable(self):
        context = _context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            context.approved_risk = RiskLevel.ELEVATED  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            context.is_lab = True  # type: ignore[misc]

    def test_passive_discovery_cannot_invoke_active_tool(self):
        # Even with a (stolen/misattached) authorization, a passive run may not
        # reach an active tool.
        context = _context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE,
                           authorization=_grant("example.test"))
        with self.assertRaises(ToolDenied):
            self.executor.execute(context, ToolCall("service-probe", "example.test"))
        # Passive tools work.
        result = self.executor.execute(
            context, ToolCall("public-records", "example.test",
                              arguments=(("query", "dns"),)))
        self.assertEqual(result.capability_id, "external-attack-surface")

    def test_unauthorized_active_execution_is_impossible(self):
        context = _context(AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
                           authorization=None)
        with self.assertRaises(ToolDenied):
            self.executor.execute(context, ToolCall("service-probe", "example.test"))

    def test_cross_tenant_authorization_grant_is_denied(self):
        context = _context(
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
            authorization=_grant("allowed.test"),
        )
        context = dataclasses.replace(context, client_id="c2")
        with self.assertRaises(ToolDenied) as caught:
            self.executor.execute(
                context, ToolCall("service-probe", "allowed.test")
            )
        self.assertIn(
            "authorization client does not match execution client",
            str(caught.exception),
        )

    def test_cross_engagement_authorization_grant_is_denied(self):
        context = _context(
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
            authorization=_grant("allowed.test"),
        )
        context = dataclasses.replace(context, engagement_id="e2")
        with self.assertRaises(ToolDenied) as caught:
            self.executor.execute(
                context, ToolCall("service-probe", "allowed.test")
            )
        self.assertIn(
            "authorization engagement does not match execution engagement",
            str(caught.exception),
        )

    def test_out_of_scope_asset_denied(self):
        context = _context(AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
                           authorization=_grant("allowed.test"))
        with self.assertRaises(ToolDenied):
            self.executor.execute(context, ToolCall("service-probe", "other.test"))

    def test_risk_escalation_is_blocked_without_new_approval(self):
        calls: list[str] = []

        def tracking_tool(context, arguments):
            calls.append("ran")
            return ToolOutput("x", "note", b"x")

        self.registry.register(
            ToolDefinition("elevated-probe", "identity-access",
                           InteractionKind.TARGET_ACTIVE, RiskLevel.ELEVATED,
                           "Elevated-impact probe"),
            tracking_tool,
        )
        context = _context(AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
                           authorization=_grant("allowed.test", RiskLevel.ELEVATED))
        with self.assertRaises(RiskElevationRequired) as caught:
            self.executor.execute(context, ToolCall("elevated-probe", "allowed.test"))
        self.assertEqual(caught.exception.required, RiskLevel.ELEVATED)
        self.assertEqual(calls, [], "handler must not run before elevation approval")

    def test_authorized_active_call_records_evidence(self):
        context = _context(AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
                           authorization=_grant("allowed.test"))
        result = self.executor.execute(context, ToolCall("service-probe", "allowed.test"))
        self.assertNotEqual(result.evidence_id, "")
        with self.state.connect() as con:
            row = con.execute(
                "SELECT * FROM evidence WHERE evidence_id=?", (result.evidence_id,)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["run_id"], context.run_id)
        self.assertEqual(row["source"], "service-probe")

    def test_lab_tools_only_run_in_lab_context(self):
        real = _context(AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                        authorization=_grant("allowed.test", RiskLevel.DESTRUCTIVE_LAB_ONLY))
        with self.assertRaises(ToolDenied):
            self.executor.execute(real, ToolCall("lab-exploit-sim", "allowed.test"))
        lab = RunContext.for_lab(run_id=str(uuid4()))
        result = self.executor.execute(lab, ToolCall("lab-exploit-sim", "127.0.0.1"))
        self.assertEqual(result.capability_id, "web-baseline")
        # And the reverse: lab runs cannot reach real-target tools.
        with self.assertRaises(ToolDenied):
            self.executor.execute(lab, ToolCall("service-probe", "allowed.test"))

    def test_typed_argument_validation(self):
        context = _context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE)
        with self.assertRaises(OrchestrationError):
            self.executor.execute(context, ToolCall("public-records", "example.test"))
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                context, ToolCall("public-records", "example.test",
                                  arguments=(("query", 42),)))
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                context, ToolCall("public-records", "example.test",
                                  arguments=(("query", "dns"), ("extra", "x"))))

    def test_unknown_tool_and_capability_fail(self):
        context = _context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE)
        with self.assertRaises(OrchestrationError):
            self.executor.execute(context, ToolCall("nope", "example.test"))
        with self.assertRaises(OrchestrationError):
            self.registry.register(
                ToolDefinition("bad", "no-such-capability",
                               InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY, "x"),
                _passive_tool,
            )

    def test_evidence_contract_is_enforced(self):
        self.registry.register(
            ToolDefinition("rogue", "web-baseline", InteractionKind.ANALYSIS,
                           RiskLevel.ANALYSIS_ONLY, "returns wrong type"),
            lambda context, arguments: {"not": "a ToolOutput"},
        )
        context = _context(AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY)
        with self.assertRaises(OrchestrationError):
            self.executor.execute(context, ToolCall("rogue", "example.test"))


if __name__ == "__main__":
    unittest.main()
