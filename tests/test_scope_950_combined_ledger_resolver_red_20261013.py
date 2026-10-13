"""#950: combined live-grant / evidence-ledger trust-boundary acceptance.

Real #107 ToolExecutor, inert handler, reserved synthetic .invalid assets and
disposable SQLite only. expectedFailure marks UNRESOLVED source-owner debt:
this file does not repair production or authorize target interaction.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry, OrchestrationError,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.state import StateStore


class ForgedLedger:
    """Untrusted object that can acknowledge evidence without persistence."""

    def __init__(self):
        self.writes = []

    def add_evidence(self, **kwargs):
        self.writes.append(kwargs)
        return "not-a-persisted-evidence-id"


class SameIdDuckGrant:
    """Untrusted live resolver return, carrying a wider scope under same ID."""

    def __init__(self, original, wide_scope):
        self.original = original
        self.grant_id = original.grant_id
        self.scope = wide_scope

    def __getattr__(self, name):
        return getattr(self.original, name)


class ObservingPolicy(ExecutionPolicy):
    def __init__(self):
        self.seen = []

    def decide(self, request):
        self.seen.append(request)
        return super().decide(request)


class CombinedLedgerAndResolver950(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lightup-950-")
        self.addCleanup(directory.cleanup)
        self.ledger = StateStore(Path(directory.name) / "synthetic.sqlite")
        self.run_id = self.ledger.create_run(
            target="inside.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-950",
        )
        self.now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="synthetic-grant-950",
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="synthetic-operator",
            reference="SYNTHETIC-950",
            scope=ScopeDefinition(
                assets=("inside.invalid",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("network-services",),
            ),
            valid_from=self.now - timedelta(days=1),
            valid_until=self.now + timedelta(days=1),
        )
        self.context = RunContext(
            run_id=self.run_id,
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=False,
            created_at=self.now,
        )
        self.handler_calls = []
        self.resolver_calls = []
        self.policy = ObservingPolicy()
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                tool_id="synthetic-tool-950",
                capability_id="network-services",
                interaction=InteractionKind.TARGET_ACTIVE,
                min_risk=RiskLevel.LOW_IMPACT,
                description="inert test handler; never contacts assets",
            ),
            self._inert_handler,
        )

    def _inert_handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput(
            summary="offline-only", evidence_kind="synthetic",
            evidence_payload=b"synthetic-no-target-interaction",
        )

    def _count_rows(self):
        with self.ledger.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _executor(self, ledger, resolved):
        def resolver(snapshot):
            self.resolver_calls.append(snapshot)
            return resolved
        return ToolExecutor(
            self.registry, ledger, policy=self.policy,
            authorization_resolver=resolver,
        )

    def _run(self, ledger, resolved, asset="inside.invalid", executor=None):
        executor = executor or self._executor(ledger, resolved)
        return executor.execute(
            self.context, ToolCall("synthetic-tool-950", asset),
        )

    def _untrusted_widening(self):
        widened = ScopeDefinition(
            assets=("inside.invalid", "outside.invalid"),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("network-services",),
        )
        return SameIdDuckGrant(self.grant, widened)

    def _assert_zero_effect(self, forgery=None):
        self.assertEqual(self.handler_calls, [], "no untrusted handler dispatch")
        self.assertEqual(self._count_rows(), 0, "no durable evidence on denial")
        if forgery is not None:
            self.assertEqual(forgery.writes, [], "no forged evidence side effects")

    @unittest.expectedFailure  # #948 constructor currently trusts a duck ledger
    def test_fake_ledger_plus_valid_grant_denied_before_handler(self):
        fake = ForgedLedger()
        with self.assertRaises((OrchestrationError, ToolDenied, TypeError)):
            self._run(fake, self.grant)
        self.assertEqual(self.policy.seen, [])
        self._assert_zero_effect(fake)

    @unittest.expectedFailure  # #949 live resolver currently trusts a duck grant
    def test_widened_duck_grant_denied_before_policy_and_ledger(self):
        with self.assertRaises(ToolDenied):
            self._run(self.ledger, self._untrusted_widening(), "outside.invalid")
        self.assertEqual(self.policy.seen, [])
        self._assert_zero_effect()

    @unittest.expectedFailure  # composed #948 + #949 must deny both, not either
    def test_dual_forgery_cannot_mint_unbacked_out_of_scope_evidence(self):
        fake = ForgedLedger()
        with self.assertRaises((OrchestrationError, ToolDenied, TypeError)):
            self._run(fake, self._untrusted_widening(), "outside.invalid")
        self.assertEqual(self.policy.seen, [])
        self._assert_zero_effect(fake)

    @unittest.expectedFailure  # retained ledger binding is currently writable
    def test_postconstruction_ledger_swap_never_changes_evidence_sink(self):
        fake = ForgedLedger()
        executor = self._executor(self.ledger, self.grant)
        try:
            setattr(executor, "state", fake)
        except (AttributeError, TypeError):
            pass
        self.assertIs(executor.state, self.ledger)
        self.assertEqual(self.policy.seen, [])
        self._assert_zero_effect(fake)

    def test_canonical_grant_and_ledger_record_real_sqlite_evidence(self):
        result = self._run(self.ledger, self.grant)
        self.assertEqual(self.handler_calls, [self.run_id])
        self.assertEqual(self.resolver_calls, [self.grant])
        self.assertEqual(len(self.policy.seen), 1)
        self.assertEqual(self._count_rows(), 1)
        record = self.ledger.get_evidence(result.evidence_id)
        self.assertEqual(record.run_id, self.run_id)
        self.assertEqual(record.source, "synthetic-tool-950")

    def test_missing_ledger_is_rejected_on_construction(self):
        with self.assertRaises(OrchestrationError):
            self._executor(None, self.grant)
        self._assert_zero_effect()

    def test_missing_live_grant_denies_before_policy_or_handler(self):
        with self.assertRaises(ToolDenied):
            self._run(self.ledger, None)
        self.assertEqual(self.policy.seen, [])
        self.assertEqual(self.resolver_calls, [self.grant])
        self._assert_zero_effect()

    def test_different_live_grant_id_denies_before_policy_or_handler(self):
        with self.assertRaises(ToolDenied):
            self._run(self.ledger, replace(self.grant, grant_id="other-id"))
        self.assertEqual(self.policy.seen, [])
        self._assert_zero_effect()

    def test_expired_canonical_live_grant_denied_by_existing_policy(self):
        expired = replace(
            self.grant,
            valid_from=self.now - timedelta(days=4),
            valid_until=self.now - timedelta(days=2),
        )
        with self.assertRaises(ToolDenied):
            self._run(self.ledger, expired)
        self.assertEqual(len(self.policy.seen), 1)
        self._assert_zero_effect()

    def test_canonical_live_scope_denies_unlisted_asset(self):
        with self.assertRaises(ToolDenied):
            self._run(self.ledger, self.grant, asset="outside.invalid")
        self.assertEqual(len(self.policy.seen), 1)
        self._assert_zero_effect()


if __name__ == "__main__":
    unittest.main()
