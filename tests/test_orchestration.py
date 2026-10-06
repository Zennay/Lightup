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
from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import (
    AssessmentMode,
    AuthorizationGrant,
    EngagementStatus,
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
        self.executor = ToolExecutor(
            self.registry, self.state, authorization_resolver=lambda grant: grant
        )

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

    def test_target_active_requires_live_authorization_resolver(self):
        executor = ToolExecutor(self.registry, self.state)
        context = _context(
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
            authorization=_grant("allowed.test"),
        )
        with self.assertRaises(ToolDenied) as caught:
            executor.execute(context, ToolCall("service-probe", "allowed.test"))
        self.assertIn("live authorization revalidation", str(caught.exception))

    def test_live_resolver_cannot_substitute_a_different_grant(self):
        calls: list[str] = []
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                "grant-substitution-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "test-only target-active handler",
            ),
            lambda context, arguments: (
                calls.append("ran")
                or ToolOutput("ran", "probe", b"evidence")
            ),
        )
        snapshot = _grant("allowed.test")
        replacement = dataclasses.replace(snapshot, grant_id="g2")
        executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=lambda grant: replacement,
        )
        context = _context(
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
            authorization=snapshot,
        )

        with self.assertRaises(ToolDenied) as caught:
            executor.execute(
                context, ToolCall("grant-substitution-probe", "allowed.test")
            )
        self.assertIn("different grant", str(caught.exception))
        self.assertEqual(calls, [])

    def test_revocation_after_run_start_denies_before_handler(self):
        domain = DomainStore(Path(self.tmp.name) / "authorization.db")
        operator = AccessContext("operator", Role.OPERATOR)
        client = domain.create_client(operator, "Runtime revocation client")
        engagement = domain.create_engagement(
            operator, client.client_id, "Runtime revocation engagement"
        )
        now = datetime.now(timezone.utc)
        grant = domain.record_authorization_grant(
            operator,
            engagement.engagement_id,
            approved_by="client signatory",
            reference="AUTH-RUNTIME-1",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        context = RunContext(
            run_id=str(uuid4()),
            client_id=client.client_id,
            engagement_id=engagement.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False,
            created_at=now,
        )
        calls: list[str] = []
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                "runtime-revocation-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "test-only target-active handler",
            ),
            lambda context, arguments: (
                calls.append("ran")
                or ToolOutput("ran", "probe", b"evidence")
            ),
        )
        executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=domain.resolve_authorization_for_execution,
        )

        executor.execute(
            context, ToolCall("runtime-revocation-probe", "allowed.test")
        )
        self.assertEqual(calls, ["ran"])

        domain.revoke_engagement_authorization(
            operator,
            engagement.engagement_id,
            "client withdrew authorization while run was active",
        )

        with self.assertRaises(ToolDenied) as caught:
            executor.execute(
                context, ToolCall("runtime-revocation-probe", "allowed.test")
            )
        self.assertIn("not live in authoritative state", str(caught.exception))
        self.assertEqual(
            calls,
            ["ran"],
            "revoked stale RunContext must be denied before handler invocation",
        )

    def test_closed_engagement_denies_stale_run_before_handler(self):
        domain = DomainStore(Path(self.tmp.name) / "closed-engagement.db")
        operator = AccessContext("closed-operator", Role.OPERATOR)
        client = domain.create_client(operator, "Closed engagement client")
        engagement = domain.create_engagement(
            operator, client.client_id, "Close while run is active"
        )
        now = datetime.now(timezone.utc)
        grant = domain.record_authorization_grant(
            operator,
            engagement.engagement_id,
            approved_by="client signatory",
            reference="AUTH-CLOSE-RUNTIME",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        context = RunContext(
            run_id=str(uuid4()),
            client_id=client.client_id,
            engagement_id=engagement.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False,
            created_at=now,
        )
        calls: list[str] = []
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                "closed-engagement-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "test-only target-active handler",
            ),
            lambda context, arguments: (
                calls.append("ran")
                or ToolOutput("ran", "probe", b"evidence")
            ),
        )
        executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=domain.resolve_authorization_for_execution,
        )
        executor.execute(
            context, ToolCall("closed-engagement-probe", "allowed.test")
        )
        self.assertEqual(calls, ["ran"])

        domain.set_engagement_status(
            operator, engagement.engagement_id, EngagementStatus.CLOSED
        )

        with self.assertRaises(ToolDenied) as caught:
            executor.execute(
                context, ToolCall("closed-engagement-probe", "allowed.test")
            )
        self.assertIn("not live in authoritative state", str(caught.exception))
        self.assertEqual(calls, ["ran"])

        domain.set_engagement_status(
            operator, engagement.engagement_id, EngagementStatus.DRAFT
        )
        with self.assertRaises(ToolDenied):
            executor.execute(
                context, ToolCall("closed-engagement-probe", "allowed.test")
            )
        self.assertEqual(
            calls,
            ["ran"],
            "reopening must not revive the historical authorization snapshot",
        )

    def test_live_resolver_overrides_broader_stale_snapshot_scope(self):
        domain = DomainStore(Path(self.tmp.name) / "scope-authority.db")
        operator = AccessContext("scope-operator", Role.OPERATOR)
        client = domain.create_client(operator, "Scope authority client")
        engagement = domain.create_engagement(
            operator, client.client_id, "Scope authority engagement"
        )
        now = datetime.now(timezone.utc)
        persisted = domain.record_authorization_grant(
            operator,
            engagement.engagement_id,
            approved_by="client signatory",
            reference="AUTH-SCOPE-AUTHORITY",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        stale_broader_snapshot = dataclasses.replace(
            persisted,
            scope=ScopeDefinition(
                assets=("allowed.test", "outside.test"),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
        )
        context = RunContext(
            run_id=str(uuid4()),
            client_id=client.client_id,
            engagement_id=engagement.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=stale_broader_snapshot,
            is_lab=False,
            created_at=now,
        )
        calls: list[str] = []
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                "scope-authority-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "test-only target-active handler",
            ),
            lambda context, arguments: (
                calls.append("ran")
                or ToolOutput("ran", "probe", b"evidence")
            ),
        )
        executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=domain.resolve_authorization_for_execution,
        )

        with self.assertRaises(ToolDenied) as caught:
            executor.execute(
                context, ToolCall("scope-authority-probe", "outside.test")
            )
        self.assertIn("asset is outside the authorized scope", str(caught.exception))
        self.assertEqual(calls, [])

    def test_target_active_handler_receives_live_persisted_authorization(self):
        domain = DomainStore(Path(self.tmp.name) / "handler-authority.db")
        operator = AccessContext("handler-operator", Role.OPERATOR)
        client = domain.create_client(operator, "Handler authority client")
        engagement = domain.create_engagement(
            operator, client.client_id, "Handler authority engagement"
        )
        now = datetime.now(timezone.utc)
        persisted = domain.record_authorization_grant(
            operator,
            engagement.engagement_id,
            approved_by="client signatory",
            reference="AUTH-HANDLER-AUTHORITY",
            scope=ScopeDefinition(
                assets=("allowed.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("network-services",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        stale_broader_snapshot = dataclasses.replace(
            persisted,
            scope=ScopeDefinition(
                assets=("allowed.test", "outside.test"),
                max_risk=RiskLevel.ELEVATED,
                allowed_capabilities=("network-services", "identity-access"),
            ),
        )
        context = RunContext(
            run_id=str(uuid4()),
            client_id=client.client_id,
            engagement_id=engagement.engagement_id,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=stale_broader_snapshot,
            is_lab=False,
            created_at=now,
        )
        observed_authorizations: list[AuthorizationGrant | None] = []
        registry = ToolRegistry()

        def capture_live_authority(handler_context, arguments):
            observed_authorizations.append(handler_context.authorization)
            return ToolOutput("ran", "probe", b"evidence")

        registry.register(
            ToolDefinition(
                "handler-authority-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "test-only target-active handler",
            ),
            capture_live_authority,
        )
        executor = ToolExecutor(
            registry,
            self.state,
            authorization_resolver=domain.resolve_authorization_for_execution,
        )

        executor.execute(
            context, ToolCall("handler-authority-probe", "allowed.test")
        )

        self.assertEqual(observed_authorizations, [persisted])
        self.assertEqual(context.authorization, stale_broader_snapshot)
        self.assertNotEqual(
            observed_authorizations[0].scope,
            stale_broader_snapshot.scope,
            "handler must not inherit stale broader authorization metadata",
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
