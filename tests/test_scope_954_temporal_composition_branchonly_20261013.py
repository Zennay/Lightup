"""#954: composed live-grant temporal narrowing with trusted evidence identity.

BRANCH-ONLY DRAFT/HOLD: offline local SQLite, inert handler, .invalid labels.
The five expected RED cases are source-owner acceptance debt, not fixes.
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


class ForgedLedger954:
    def __init__(self):
        self.receipts = []

    def add_evidence(self, **kwargs):
        self.receipts.append(kwargs)
        return "undurable-evidence-954"


class SameIdDuckGrant954:
    def __init__(self, snapshot, end):
        self.snapshot = snapshot
        self.grant_id = snapshot.grant_id
        self.valid_until = end

    def __getattr__(self, key):
        return getattr(self.snapshot, key)

    def is_current(self, now=None):
        return True


class ObservingPolicy954(ExecutionPolicy):
    def __init__(self):
        self.calls = []

    def decide(self, request):
        self.calls.append(request)
        return super().decide(request)


class TemporalAuthorityComposition954(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-temporal-954-")
        self.addCleanup(tmp.cleanup)
        self.state = StateStore(Path(tmp.name) / "offline.sqlite")
        self.run_id = self.state.create_run(
            "temporal.invalid", activation_mode="plan_only",
            authorization_ref="SYNTHETIC-954",
        )
        self.now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="synthetic-grant-954",
            client_id="client-954", engagement_id="engagement-954",
            approved_by="synthetic-only", reference="SYNTHETIC-954",
            scope=ScopeDefinition(
                assets=("temporal.invalid",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("network-services",),
            ),
            valid_from=self.now - timedelta(days=1),
            valid_until=self.now + timedelta(days=1),
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="client-954",
            engagement_id="engagement-954",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant, is_lab=False, created_at=self.now,
        )
        self.calls = []
        self.resolver_calls = []
        self.policy = ObservingPolicy954()
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "synthetic-temporal-954", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "inert synthetic only; no target IO",
            ),
            self._inert,
        )

    def _inert(self, ctx, args):
        self.calls.append(ctx.run_id)
        return ToolOutput("offline", "synthetic", b"only-offline")

    def _rows(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _run(self, live, ledger=None):
        def resolver(snapshot):
            self.resolver_calls.append(snapshot)
            return live
        executor = ToolExecutor(
            self.registry, self.state if ledger is None else ledger,
            policy=self.policy, authorization_resolver=resolver,
        )
        return executor.execute(
            self.context, ToolCall("synthetic-temporal-954", "temporal.invalid")
        )

    def _assert_no_effects(self, fake=None):
        self.assertEqual(self.calls, [], "denial must precede handler")
        self.assertEqual(self._rows(), 0, "denial must not persist evidence")
        if fake is not None:
            self.assertEqual(fake.receipts, [], "no fabricated receipt")

    @unittest.expectedFailure  # #953 forbids widening starting time
    def test_live_valid_from_must_not_move_earlier(self):
        live = replace(
            self.grant, valid_from=self.grant.valid_from - timedelta(days=1))
        with self.assertRaises(ToolDenied):
            self._run(live)
        self._assert_no_effects()

    @unittest.expectedFailure  # #953 forbids extending grant expiry
    def test_live_valid_until_must_not_move_later(self):
        live = replace(
            self.grant, valid_until=self.grant.valid_until + timedelta(days=1))
        with self.assertRaises(ToolDenied):
            self._run(live)
        self._assert_no_effects()

    @unittest.expectedFailure  # bidirectional widening is never a refresh
    def test_live_window_must_not_expand_both_bounds(self):
        live = replace(
            self.grant,
            valid_from=self.grant.valid_from - timedelta(days=1),
            valid_until=self.grant.valid_until + timedelta(days=1),
        )
        with self.assertRaises(ToolDenied):
            self._run(live)
        self._assert_no_effects()

    @unittest.expectedFailure  # #949 noncanonical same-id live object bypass
    def test_same_id_duck_expiry_override_denied_prepolicy(self):
        forged = SameIdDuckGrant954(
            self.grant, self.grant.valid_until + timedelta(days=1))
        with self.assertRaises((ToolDenied, OrchestrationError, TypeError)):
            self._run(forged)
        self.assertEqual(self.policy.calls, [], "reject duck before policy")
        self._assert_no_effects()

    @unittest.expectedFailure  # #948/#949/#953 deny combined forged provenance
    def test_expanded_window_and_fake_ledger_denied_without_receipt(self):
        fake = ForgedLedger954()
        live = replace(
            self.grant, valid_until=self.grant.valid_until + timedelta(days=1))
        with self.assertRaises((ToolDenied, OrchestrationError, TypeError)):
            self._run(live, ledger=fake)
        self._assert_no_effects(fake)

    def test_exact_valid_window_persists_authentic_sqlite_evidence(self):
        result = self._run(self.grant)
        self.assertEqual(self.calls, [self.run_id])
        self.assertEqual(self.resolver_calls, [self.grant])
        self.assertEqual(self._rows(), 1)
        self.assertEqual(self.state.get_evidence(result.evidence_id).run_id,
                         self.run_id)

    def test_valid_narrower_window_preserves_authorized_dispatch(self):
        narrower = replace(
            self.grant,
            valid_from=self.now - timedelta(hours=6),
            valid_until=self.now + timedelta(hours=6),
        )
        self._run(narrower)
        self.assertEqual(self.calls, [self.run_id])
        self.assertEqual(self._rows(), 1)

    def test_valid_narrowing_to_expired_window_denied(self):
        expired = replace(
            self.grant, valid_until=self.now - timedelta(hours=1))
        with self.assertRaises(ToolDenied):
            self._run(expired)
        self._assert_no_effects()

    def test_valid_narrowing_to_future_window_denied(self):
        future = replace(
            self.grant, valid_from=self.now + timedelta(hours=1))
        with self.assertRaises(ToolDenied):
            self._run(future)
        self._assert_no_effects()

    def test_revoked_same_id_grant_denied_by_policy(self):
        revoked = replace(
            self.grant, revoked_at=self.now, revoked_by="synthetic-operator",
            revocation_reason="synthetic-revocation",
        )
        with self.assertRaises(ToolDenied):
            self._run(revoked)
        self._assert_no_effects()

    def test_missing_live_grant_denied_before_policy(self):
        with self.assertRaises(ToolDenied):
            self._run(None)
        self.assertEqual(self.policy.calls, [])
        self._assert_no_effects()

    def test_different_live_grant_id_denied_before_policy(self):
        with self.assertRaises(ToolDenied):
            self._run(replace(self.grant, grant_id="different-id"))
        self.assertEqual(self.policy.calls, [])
        self._assert_no_effects()


if __name__ == "__main__":
    unittest.main()
