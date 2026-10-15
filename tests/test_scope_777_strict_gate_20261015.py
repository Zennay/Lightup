"""Actual source-backed fail-closed runner acceptance; no real grant/target."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scope_777_strict_direct_policy_gate as gate
from lightup.execution_policy import ExecutionPolicy, InteractionKind, PolicyDecision
from lightup.engagements import RiskLevel

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scope_777_strict_direct_policy_gate.py"
FALSE = ("authorization_verified", "permit_issued", "dispatch_enabled",
         "merge_approved", "deploy_approved", "release_approved")


class StrictProductionPolicyGateTests(unittest.TestCase):
    def _verify_result(self, verdict):
        self.assertEqual(verdict["invalid_examined"], 14 if verdict["invalid_allowed"] is not None else 0)
        for flag in FALSE:
            self.assertIs(verdict[flag], False)
        self.assertIn(verdict["status"], ("HOLD", "TEST_ONLY_PASS"))
        self.assertEqual(verdict["negative_controls_examined"],
                         11 if verdict["negative_controls_allowed"] is not None else 0)
        if verdict["negative_controls_allowed"] is not None:
            self.assertIs(type(verdict["negative_controls_allowed"]), int)
            self.assertGreaterEqual(verdict["negative_controls_allowed"], 0)
        if verdict["status"] == "TEST_ONLY_PASS":
            self.assertEqual(verdict["invalid_allowed"], 0)
            self.assertEqual(verdict["negative_controls_allowed"], 0)

    def test_real_process_is_fail_closed_for_unpatched_or_repaired_policy(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        proc = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True,
                              text=True, env=env, timeout=4)
        self.assertIn(proc.returncode, (0, 2))
        self.assertEqual(proc.stderr, "")
        self.assertEqual(len(proc.stdout.splitlines()), 1)
        self.assertNotIn("fictional-operator", proc.stdout)
        self.assertNotIn("ROE-FICTIONAL", proc.stdout)
        verdict = json.loads(proc.stdout)
        self._verify_result(verdict)
        self.assertEqual(proc.returncode, 0 if verdict["status"] == "TEST_ONLY_PASS" else 2)

    def test_test_only_narrowing_reaches_strict_zero_bypass(self):
        original = ExecutionPolicy.decide

        def narrowed(self, request):
            if request.interaction is InteractionKind.TARGET_ACTIVE and request.authorization:
                grant = request.authorization
                for value in (grant.approved_by, grant.reference):
                    if type(value) is not str or not value.strip() or value != value.strip():
                        return PolicyDecision(False, "noncanonical provenance")
            return original(self, request)

        with patch.object(ExecutionPolicy, "decide", narrowed):
            outcome = gate._scan_pure_local()
        self._verify_result(outcome)
        self.assertEqual(outcome["status"], "TEST_ONLY_PASS")
        self.assertEqual(outcome["invalid_allowed"], 0)
        self.assertEqual(outcome["negative_controls_examined"], 11)
        self.assertEqual(outcome["negative_controls_allowed"], 0)

    def test_invalid_uses_no_approval_flags_even_when_bypassed(self):
        result = gate._scan_pure_local()
        self._verify_result(result)
        self.assertTrue(result["invalid_allowed"] is None or result["invalid_allowed"] >= 0)


    def test_original_policy_has_eleven_independent_safe_denials(self):
        result = gate._scan_pure_local()
        self._verify_result(result)
        self.assertEqual(result["negative_controls_examined"], 11)
        self.assertEqual(result["negative_controls_allowed"], 0)

    def _narrow_then_break_one_boundary(self, broken_boundary):
        original = ExecutionPolicy.decide

        def broken(self, request):
            if request.interaction is InteractionKind.TARGET_ACTIVE:
                if request.authorization is not None:
                    grant = request.authorization
                    for value in (grant.approved_by, grant.reference):
                        if type(value) is not str or not value.strip() or value != value.strip():
                            return PolicyDecision(False, "noncanonical provenance")
            if broken_boundary(request):
                return PolicyDecision(True, "incorrectly widened authority")
            return original(self, request)

        with patch.object(ExecutionPolicy, "decide", broken):
            return gate._scan_pure_local()

    def test_narrow_provenance_but_allow_expired_still_hold(self):
        result = self._narrow_then_break_one_boundary(
            lambda request: request.interaction is InteractionKind.TARGET_ACTIVE
            and request.authorization is not None
            and request.authorization.valid_until < datetime.now(timezone.utc)
        )
        self._verify_result(result)
        self.assertEqual(result["invalid_allowed"], 0)
        self.assertEqual(result["negative_controls_allowed"], 1)
        self.assertEqual(result["status"], "HOLD")

    def test_narrow_provenance_but_allow_outside_asset_still_hold(self):
        result = self._narrow_then_break_one_boundary(
            lambda request: request.interaction is InteractionKind.TARGET_ACTIVE
            and request.asset == "other.example.test"
        )
        self._verify_result(result)
        self.assertEqual(result["invalid_allowed"], 0)
        self.assertEqual(result["negative_controls_allowed"], 1)
        self.assertEqual(result["status"], "HOLD")

    def test_policy_mutating_request_raises_not_green(self):
        original = ExecutionPolicy.decide

        def mutate(self, request):
            decision = original(self, request)
            object.__setattr__(request, "capability_id", "MUTATED")
            return decision

        with patch.object(ExecutionPolicy, "decide", mutate):
            with self.assertRaises(ValueError):
                gate._scan_pure_local()

    def test_bool_spoofed_policy_result_raises_not_green(self):
        with patch.object(ExecutionPolicy, "decide",
                          return_value=PolicyDecision(1, "forged")):
            with self.assertRaises(ValueError):
                gate._scan_pure_local()


    def test_each_negative_guard_detects_single_fail_open_mutation(self):
        cases = (
            ("missing-grant", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.authorization is None),
            ("expired", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.authorization is not None
             and r.authorization.valid_until < datetime.now(timezone.utc)),
            ("not-yet-valid", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.authorization is not None
             and r.authorization.valid_from > datetime.now(timezone.utc)),
            ("wrong-asset", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.asset == "other.example.test"),
            ("excluded-asset", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.authorization is not None
             and r.authorization.scope.excluded_assets == ("example.test",)),
            ("wrong-capability", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.capability_id == "unapproved-check"),
            ("risk-escalation", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.requested_risk is RiskLevel.ELEVATED),
            ("destructive-risk", lambda r: r.interaction is InteractionKind.TARGET_ACTIVE
             and r.requested_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY),
            ("lab-without-lab-target", lambda r: r.interaction is InteractionKind.LAB_ACTIVE
             and not r.is_lab),
            ("analysis-with-active-risk", lambda r: r.interaction is InteractionKind.ANALYSIS
             and r.requested_risk is RiskLevel.LOW_IMPACT),
            ("passive-with-active-risk", lambda r: r.interaction is InteractionKind.PASSIVE_PUBLIC
             and r.requested_risk is RiskLevel.LOW_IMPACT),
        )
        self.assertEqual(len(cases), 11)
        for label, matcher in cases:
            with self.subTest(regression=label):
                result = self._narrow_then_break_one_boundary(matcher)
                self._verify_result(result)
                self.assertEqual(result["invalid_allowed"], 0)
                self.assertEqual(result["negative_controls_allowed"], 1)
                self.assertEqual(result["status"], "HOLD")

    def test_analysis_positive_control_cannot_be_accidentally_denied(self):
        original = ExecutionPolicy.decide

        def narrow_but_forbid_analysis(self, request):
            if request.interaction is InteractionKind.TARGET_ACTIVE and request.authorization:
                g = request.authorization
                if (type(g.approved_by) is not str or not g.approved_by.strip()
                        or g.approved_by != g.approved_by.strip()
                        or type(g.reference) is not str or not g.reference.strip()
                        or g.reference != g.reference.strip()):
                    return PolicyDecision(False, "noncanonical")
            if (request.interaction is InteractionKind.ANALYSIS
                    and request.requested_risk is RiskLevel.ANALYSIS_ONLY):
                return PolicyDecision(False, "unsafe regression to legacy analysis")
            return original(self, request)

        with patch.object(ExecutionPolicy, "decide", narrow_but_forbid_analysis):
            result = gate._scan_pure_local()
        self._verify_result(result)
        self.assertEqual(result["invalid_allowed"], 0)
        self.assertEqual(result["negative_controls_allowed"], 0)
        self.assertEqual(result["status"], "HOLD")

    def test_mutating_grant_fails_closed(self):
        original = ExecutionPolicy.decide

        def mutable(self, request):
            answer = original(self, request)
            if request.authorization is not None:
                object.__setattr__(request.authorization, "reference", "MODIFIED")
            return answer

        with patch.object(ExecutionPolicy, "decide", mutable):
            with self.assertRaises(ValueError):
                gate._scan_pure_local()

    def test_policy_decision_subclass_not_treated_as_canonical(self):
        class FakeDecision(PolicyDecision):
            pass
        with patch.object(ExecutionPolicy, "decide",
                          return_value=FakeDecision(True, "forged")):
            with self.assertRaises(ValueError):
                gate._scan_pure_local()


if __name__ == "__main__":
    unittest.main()
