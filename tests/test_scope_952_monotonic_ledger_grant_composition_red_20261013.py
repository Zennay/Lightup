"""#952: in-process composed ledger, live-grant identity and monotonic scope contract.

Only synthetic .invalid asset strings, disposable local SQLite and inert handlers.
The five expected RED cases are unimplemented source-owner security obligations.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, RunContext, ToolCall, ToolDefinition, ToolDenied,
    ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.state import StateStore


class FakeLedger952:
    def __init__(self):
        self.writes = []

    def add_evidence(self, **values):
        self.writes.append(values)
        return "fabricated-evidence-id"


class ForgedSameIdGrant952:
    def __init__(self, snapshot, wide_scope):
        self.snapshot = snapshot
        self.grant_id = snapshot.grant_id
        self.scope = wide_scope

    def __getattr__(self, key):
        return getattr(self.snapshot, key)


class PolicyObserver952(ExecutionPolicy):
    def __init__(self):
        self.seen = []

    def decide(self, request):
        self.seen.append(request)
        return super().decide(request)


class ComposedMonotonicAuthority952(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lightup-scope-952-")
        self.addCleanup(temporary.cleanup)
        self.store = StateStore(Path(temporary.name) / "synthetic.sqlite")
        self.run_id = self.store.create_run(
            target="base.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-952",
        )
        self.now = datetime.now(timezone.utc)
        self.base_scope = ScopeDefinition(
            assets=("base.invalid", "excluded.invalid"),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("network-services",),
            excluded_assets=("excluded.invalid",),
        )
        self.snapshot = AuthorizationGrant(
            grant_id="synthetic-952", client_id="client-952",
            engagement_id="engagement-952", approved_by="synthetic",
            reference="SYNTHETIC-952", scope=self.base_scope,
            valid_from=self.now - timedelta(days=1),
            valid_until=self.now + timedelta(days=1),
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="client-952",
            engagement_id="engagement-952",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=self.snapshot, is_lab=False, created_at=self.now,
        )
        self.registry = ToolRegistry()
        self.handler_calls = []
        for tool_id, capability, risk in (
            ("network-low-952", "network-services", RiskLevel.LOW_IMPACT),
            ("web-low-952", "web-baseline", RiskLevel.LOW_IMPACT),
            ("network-standard-952", "network-services", RiskLevel.STANDARD),
        ):
            self.registry.register(
                ToolDefinition(
                    tool_id, capability, InteractionKind.TARGET_ACTIVE,
                    risk, "inert synthetic handler (no target IO)"
                ),
                self._handler,
            )
        self.policy = PolicyObserver952()
        self.resolver_calls = []

    def _handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("inert", "synthetic", b"offline-evidence-only")

    def _count(self):
        with self.store.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _run(self, live, *, asset="base.invalid", tool="network-low-952",
             ledger=None):
        def resolver(snapshot):
            self.resolver_calls.append(snapshot)
            return live
        executor = ToolExecutor(
            self.registry, self.store if ledger is None else ledger,
            policy=self.policy, authorization_resolver=resolver,
        )
        return executor.execute(self.context, ToolCall(tool, asset))

    def _assert_no_effect(self, fake=None):
        self.assertEqual(self.handler_calls, [], "denial precedes handler")
        self.assertEqual(self._count(), 0, "denial cannot persist evidence")
        if fake is not None:
            self.assertEqual(fake.writes, [], "denial cannot forge evidence")

    def _expect_denied_prepolicy(self, live, **kwargs):
        with self.assertRaises((ToolDenied, OrchestrationError, TypeError)):
            self._run(live, **kwargs)
        self.assertEqual(self.policy.seen, [], "reject before policy")
        self._assert_no_effect()

    @unittest.expectedFailure  # #951 widened asset must not use same grant ID
    def test_live_asset_expansion_denied_before_handler(self):
        live = replace(self.snapshot, scope=replace(
            self.base_scope, assets=("base.invalid", "excluded.invalid",
                                     "new.invalid")))
        with self.assertRaises(ToolDenied):
            self._run(live, asset="new.invalid")
        self._assert_no_effect()

    @unittest.expectedFailure  # #951 widened capability must not mint authority
    def test_live_capability_expansion_denied_before_handler(self):
        live = replace(self.snapshot, scope=replace(
            self.base_scope,
            allowed_capabilities=("network-services", "web-baseline")))
        with self.assertRaises(ToolDenied):
            self._run(live, tool="web-low-952")
        self._assert_no_effect()

    @unittest.expectedFailure  # #951 raising risk after snapshot is forbidden
    def test_live_risk_ceiling_expansion_denied_before_handler(self):
        live = replace(self.snapshot, scope=replace(
            self.base_scope, max_risk=RiskLevel.STANDARD))
        with self.assertRaises(ToolDenied):
            self._run(live, tool="network-standard-952")
        self._assert_no_effect()

    @unittest.expectedFailure  # #951 dropping excluded assets widens consent
    def test_live_exclusion_removal_denied_before_handler(self):
        live = replace(self.snapshot, scope=replace(
            self.base_scope, excluded_assets=()))
        with self.assertRaises(ToolDenied):
            self._run(live, asset="excluded.invalid")
        self._assert_no_effect()

    @unittest.expectedFailure  # #948/#949/#951 must compose, not bypass each other
    def test_duck_live_grant_and_fake_ledger_cannot_bypass_monotonic_gate(self):
        wide = replace(self.base_scope,
                       assets=("base.invalid", "excluded.invalid",
                               "new.invalid"))
        forged = ForgedSameIdGrant952(self.snapshot, wide)
        fake_ledger = FakeLedger952()
        with self.assertRaises((ToolDenied, OrchestrationError, TypeError)):
            self._run(forged, asset="new.invalid", ledger=fake_ledger)
        self.assertEqual(self.policy.seen, [], "noncanonical grant prepolicy")
        self._assert_no_effect(fake_ledger)

    def test_exact_same_id_unchanged_scope_is_allowed_and_evidenced(self):
        result = self._run(self.snapshot)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self.resolver_calls, [self.snapshot])
        self.assertEqual(self._count(), 1)
        self.assertEqual(self.store.get_evidence(result.evidence_id).run_id,
                         self.run_id)

    def test_genuine_live_exclusion_narrowing_keeps_allowed_asset(self):
        narrower = replace(self.snapshot, scope=replace(
            self.base_scope, excluded_assets=("excluded.invalid", "new.invalid")))
        self._run(narrower)
        self.assertEqual(self._count(), 1)
        self.assertEqual(self.handler_calls, [self.run_id])

    def test_genuine_live_asset_narrowing_denies_removed_asset(self):
        narrower = replace(self.snapshot, scope=replace(
            self.base_scope, assets=("excluded.invalid",)))
        with self.assertRaises(ToolDenied):
            self._run(narrower)
        self._assert_no_effect()

    def test_genuine_live_capability_narrowing_denies_removed_capability(self):
        narrower = replace(self.snapshot, scope=replace(
            self.base_scope, allowed_capabilities=()))
        with self.assertRaises(ToolDenied):
            self._run(narrower)
        self._assert_no_effect()

    def test_genuine_live_risk_narrowing_denies_original_low_risk_tool(self):
        narrower = replace(self.snapshot, scope=replace(
            self.base_scope, max_risk=RiskLevel.PASSIVE))
        with self.assertRaises(ToolDenied):
            self._run(narrower)
        self._assert_no_effect()

    def test_missing_live_grant_is_rejected_prepolicy(self):
        self._expect_denied_prepolicy(None)

    def test_different_live_grant_id_is_rejected_prepolicy(self):
        self._expect_denied_prepolicy(
            replace(self.snapshot, grant_id="other-grant"))

    def test_expired_live_grant_denied_by_policy(self):
        expired = replace(
            self.snapshot,
            valid_from=self.now - timedelta(days=4),
            valid_until=self.now - timedelta(days=2),
        )
        with self.assertRaises(ToolDenied):
            self._run(expired)
        self._assert_no_effect()


if __name__ == "__main__":
    unittest.main()
