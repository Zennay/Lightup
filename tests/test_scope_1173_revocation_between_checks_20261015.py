"""Issue #1173: deterministic step-up revocation window acceptance over PR #1172.

Tests-only sidecar pinned to source owner #1172. All assertions use fictitious,
in-memory approvals and inert handler responses; there is no active adapter,
customer consent, scanning, DNS, external network, or live lab isolation proof.
"""
from __future__ import annotations

import socket
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor, ToolOutput,
    ToolRegistry,
)
from lightup.destructive_lab_step_up import (
    DestructiveLabApproval, DestructiveLabStepUpExecutor,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class RevocationBetweenApprovalAndIsolationTests(unittest.TestCase):
    """Synchronous, deterministic callbacks emulate approval changes, not threads."""

    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="lightup-1173-race-")
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "offline.sqlite")
        self.run_id = self.state.create_run("synthetic-lab-asset", "lab_only")
        now = datetime.now(timezone.utc)
        self.context = RunContext(
            run_id=self.run_id,
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=AssessmentMode.LAB_AUTONOMOUS,
            approved_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=None,
            is_lab=True,
            created_at=now - timedelta(seconds=20),
        )
        self.call = ToolCall("inert-stepup-risk-five", "synthetic-lab-asset")
        self.definition = ToolDefinition(
            tool_id=self.call.tool_id,
            capability_id="web-baseline",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            description="inert non-network marker",
        )
        self.approval = DestructiveLabApproval(
            approval_id="fictional-stepup",
            run_id=self.context.run_id,
            client_id=self.context.client_id,
            engagement_id=self.context.engagement_id,
            asset=self.call.asset,
            capability_id=self.definition.capability_id,
            tool_id=self.call.tool_id,
            approved_by="fictional-operator",
            approved_at=now - timedelta(seconds=60),
            expires_at=now + timedelta(minutes=30),
        )
        self.live_approval = self.approval
        self.events = []
        self.handler = Mock(side_effect=self._handle)
        self.registry = ToolRegistry()
        self.registry.register(self.definition, self.handler)
        self.executor = ToolExecutor(self.registry, self.state)

    def _handle(self, _context, _arguments):
        self.events.append("handler")
        return ToolOutput(
            summary="synthetic",
            evidence_kind="test-only",
            evidence_payload=b"non-network-noop",
        )

    def _resolver(self, _run_id):
        self.events.append("resolver")
        return self.live_approval

    def _count(self):
        with self.state.connect() as db:
            return db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _execute(self, callback):
        wrapped = DestructiveLabStepUpExecutor(
            self.executor,
            approval_resolver=self._resolver,
            isolation_verifier=callback,
        )
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            return wrapped.execute(self.context, self.call)

    def _assert_denied_without_effect(self, callback):
        with self.assertRaises(ToolDenied):
            self._execute(callback)
        self.handler.assert_not_called()
        self.assertEqual(0, self._count())

    @unittest.expectedFailure
    def test_revocation_during_isolation_callback_denies_before_handler(self):
        """RED: a once-valid record revoked after first read must not dispatch."""
        def revoke(_context, _call):
            self.events.append("isolation-revokes")
            self.live_approval = replace(self.approval, revoked=True)
            return True
        self._assert_denied_without_effect(revoke)

    @unittest.expectedFailure
    def test_expiration_during_isolation_callback_denies_before_handler(self):
        """RED: a valid precheck cannot outlive a newly expired approval."""
        def expire(_context, _call):
            self.events.append("isolation-expires")
            self.live_approval = replace(
                self.approval,
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
            return True
        self._assert_denied_without_effect(expire)

    @unittest.expectedFailure
    def test_scope_reassignment_during_isolation_callback_denies_before_handler(self):
        """RED: current approval may no longer match tool/asset/tenant."""
        def rescope(_context, _call):
            self.events.append("isolation-rescopes")
            self.live_approval = replace(self.approval, asset="different-synthetic-lab")
            return True
        self._assert_denied_without_effect(rescope)


    @unittest.expectedFailure
    def test_concurrent_revocation_while_isolation_waits_must_deny(self):
        """RED: a second thread may revoke after first read, before handler.

        Both threads only touch in-memory fictional approval objects; no real
        target, operator, external networking, or destructive code exists.
        Events make the schedule deterministic rather than timing-based.
        """
        entered = Event()
        resume = Event()

        def controlled_isolation(_context, _call):
            self.events.append("isolation-concurrent-revocation")
            entered.set()
            if not resume.wait(5):
                raise AssertionError("interleaving witness timeout")
            return True

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self._assert_denied_without_effect, controlled_isolation)
            try:
                self.assertTrue(entered.wait(5), "isolation callback did not start")
                self.live_approval = replace(self.approval, revoked=True)
            finally:
                resume.set()
            pending.result(timeout=10)

    def test_already_revoked_approval_denies_before_isolation_or_handler(self):
        self.live_approval = replace(self.approval, revoked=True)
        isolation = Mock(return_value=True)
        self._assert_denied_without_effect(isolation)
        isolation.assert_not_called()
        self.assertEqual(self.events, ["resolver"])

    def test_isolation_false_does_not_dispatch_even_with_valid_approval(self):
        def no_isolation(_context, _call):
            self.events.append("isolation-denies")
            return False
        self._assert_denied_without_effect(no_isolation)
        self.assertEqual(self.events, ["resolver", "isolation-denies"])

    def test_unchanged_approval_with_fixture_isolation_runs_only_inert_handler(self):
        def fixture_only(_context, _call):
            self.events.append("fixture-only")
            return True
        result = self._execute(fixture_only)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(result.capability_id, "web-baseline")
        self.assertEqual(self.events, ["resolver", "fixture-only", "handler"])
        self.handler.assert_called_once()
        self.assertEqual(1, self._count())
        saved = self.state.get_evidence(result.evidence_id)
        self.assertEqual(saved.source, self.call.tool_id)


    @unittest.expectedFailure
    def test_concurrent_registry_swap_after_final_snapshot_must_deny(self):
        """RED: checked handler identity must remain bound through raw dispatch.

        The second registered-tool lookup returns its old tuple while another
        thread swaps the mapping. The third lookup inside the raw ToolExecutor
        then finds a different inert handler. No real capability is invoked.
        """
        observed = Event()
        resume = Event()
        original_get = self.registry.get
        lookups = [0]

        def replacement(_context, _arguments):
            self.events.append("substituted-handler")
            return ToolOutput("swapped-fixture", "test-only", b"inert-replaced")

        swapped = Mock(side_effect=replacement)

        def synchronized_get(tool_id):
            lookups[0] += 1
            snapshot = original_get(tool_id)
            if lookups[0] == 2:
                self.events.append("final-snapshot-observed")
                observed.set()
                if not resume.wait(5):
                    raise AssertionError("tool snapshot interleaving timeout")
            return snapshot

        def fixture_only(_context, _call):
            self.events.append("isolation-verified")
            return True

        with patch.object(self.registry, "get", side_effect=synchronized_get):
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self._assert_denied_without_effect, fixture_only)
                try:
                    self.assertTrue(observed.wait(5), "second registry lookup missing")
                    self.registry._tools[self.call.tool_id] = (
                        self.definition, swapped,
                    )
                finally:
                    resume.set()
                pending.result(timeout=10)
        swapped.assert_not_called()
        self.assertEqual(0, self._count())

    def test_registry_swap_inside_isolation_is_already_denied(self):
        """GREEN: swapping a handler *before* the final identity check denies."""
        original, _ = self.registry.get(self.call.tool_id)

        def substituted(_context, _arguments):
            self.events.append("never-call-substitute")
            return ToolOutput("should-not-execute", "test-only", b"no-op")

        swapped = Mock(side_effect=substituted)

        def replace_before_final_get(_context, _call):
            self.registry._tools[self.call.tool_id] = (original, swapped)
            return True

        self._assert_denied_without_effect(replace_before_final_get)
        swapped.assert_not_called()
        self.assertEqual(0, self._count())

    def test_registry_swap_red_witness_requires_missing_denial(self):
        """GREEN: the registry RED may not be masked by a timeout or crash."""
        probe = type(self)("test_concurrent_registry_swap_after_final_snapshot_must_deny")
        probe.setUp()
        try:
            with self.assertRaises(AssertionError) as caught:
                probe.test_concurrent_registry_swap_after_final_snapshot_must_deny()
            self.assertIn("ToolDenied not raised", str(caught.exception))
            self.assertIn("final-snapshot-observed", probe.events)
            self.assertIn("substituted-handler", probe.events)
            self.assertEqual(probe._count(), 1)
            probe.handler.assert_not_called()
        finally:
            probe.doCleanups()


    def _assert_post_snapshot_definition_change_denied(self, changed_definition):
        """Stage an in-memory definition substitution only after final approval check."""
        observed = Event()
        resume = Event()
        initial_get = self.registry.get
        reads = [0]
        self.last_policy_request = None
        policy_decide = self.executor.policy.decide

        def audit_decide(request):
            self.last_policy_request = request
            return policy_decide(request)

        def inspected_get(tool_id):
            reads[0] += 1
            checked = initial_get(tool_id)
            if reads[0] == 2:
                self.events.append("definition-snapshot-checked")
                observed.set()
                if not resume.wait(5):
                    raise AssertionError("definition-swap barrier timeout")
            return checked

        with patch.object(self.registry, "get", side_effect=inspected_get):
            with patch.object(self.executor.policy, "decide", side_effect=audit_decide):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(
                        self._assert_denied_without_effect,
                        lambda _context, _call: True,
                    )
                    try:
                        self.assertTrue(observed.wait(5), "final definition check missing")
                        # Same handler object, but different security-relevant
                        # tool identity metadata as seen at raw dispatch.
                        self.registry._tools[self.call.tool_id] = (
                            changed_definition, self.handler,
                        )
                    finally:
                        resume.set()
                    pending.result(timeout=10)

    @unittest.expectedFailure
    def test_capability_swap_after_final_snapshot_must_not_dispatch(self):
        """RED: a trusted step-up for web-baseline is not valid for api-baseline."""
        different_capability = replace(
            self.definition, capability_id="api-baseline"
        )
        self._assert_post_snapshot_definition_change_denied(different_capability)

    @unittest.expectedFailure
    def test_risk_downgrade_after_final_snapshot_must_not_dispatch(self):
        """RED: dispatch may not silently reinterpret approved risk-5 metadata."""
        changed_risk = replace(self.definition, min_risk=RiskLevel.ELEVATED)
        self._assert_post_snapshot_definition_change_denied(changed_risk)

    def test_capability_and_risk_swap_reds_have_exact_policy_and_evidence(self):
        """GREEN witness: no expected RED hides a crash or missing interleaving."""
        examples = (
            ("test_capability_swap_after_final_snapshot_must_not_dispatch",
             "api-baseline", RiskLevel.DESTRUCTIVE_LAB_ONLY),
            ("test_risk_downgrade_after_final_snapshot_must_not_dispatch",
             "web-baseline", RiskLevel.ELEVATED),
        )
        for method, capability, risk in examples:
            with self.subTest(case=method):
                probe = type(self)(method)
                probe.setUp()
                try:
                    with self.assertRaises(AssertionError) as caught:
                        getattr(probe, method)()
                    self.assertIn("ToolDenied not raised", str(caught.exception))
                    self.assertIn("definition-snapshot-checked", probe.events)
                    probe.handler.assert_called_once()
                    self.assertEqual(1, probe._count())
                    self.assertEqual(
                        probe.last_policy_request.capability_id, capability
                    )
                    self.assertIs(probe.last_policy_request.requested_risk, risk)
                    with probe.state.connect() as connection:
                        row = connection.execute(
                            "SELECT capability_id FROM evidence LIMIT 1"
                        ).fetchone()
                    self.assertEqual(row[0], capability)
                finally:
                    probe.doCleanups()

    def test_red_witness_requires_the_exact_missing_denial_assertion(self):
        """Do not mistake setup/type/socket failures for genuine source RED."""
        matrix = (
            "test_revocation_during_isolation_callback_denies_before_handler",
            "test_expiration_during_isolation_callback_denies_before_handler",
            "test_scope_reassignment_during_isolation_callback_denies_before_handler",
            "test_concurrent_revocation_while_isolation_waits_must_deny",
        )
        for method in matrix:
            with self.subTest(method=method):
                probe = type(self)(method)
                probe.setUp()
                try:
                    with self.assertRaises(AssertionError) as caught:
                        getattr(probe, method)()
                    self.assertIn("ToolDenied not raised", str(caught.exception))
                    self.assertEqual(probe.events[0], "resolver")
                    self.assertTrue(probe.events[1].startswith("isolation-"))
                    self.assertEqual(probe.events[-1], "handler")
                    probe.handler.assert_called_once()
                    self.assertEqual(1, probe._count())
                finally:
                    probe.doCleanups()
