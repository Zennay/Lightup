"""Offline, synthetic-only source and negative controls for #1491."""
import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy, ExecutionPermit
from lightup.models import Target
from lightup.permit_decision_review_1491 import review_permit_decision
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason

FALSE = (False, False, False, False)


class PermitDecisionReview1491Tests(unittest.TestCase):
    def setUp(self):
        self.decision = ScopeDecision(True, "127.0.0.1", ScopeReason.LOOPBACK)
        self.permit = ExecutionPermit(
            permit_id="a" * 32,
            target="127.0.0.1",
            capability_id="web-baseline",
            mode=ActivationMode.LAB_ONLY,
            activation_reference="LAB-SYNTHETIC",
            issued_at=datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc),
        )

    def review(self, permit=None, decision=None, reference="LAB-SYNTHETIC"):
        return review_permit_decision(
            self.permit if permit is None else permit,
            self.decision if decision is None else decision,
            reference,
        )

    def assert_no_authority(self, result):
        self.assertIn(result.status, ("HOLD", "REVIEW_ONLY"))
        self.assertEqual(
            (result.authorized, result.consent_verified,
             result.dispatch_allowed, result.release_allowed),
            FALSE,
        )
        self.assertIs(type(result.reason), str)
        self.assertNotIn("127.0.0.1", result.reason)

    def test_positive_fictional_loopback_review_is_not_authorization(self):
        r = self.review()
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assert_no_authority(r)

    def test_true_source_gate_permit_without_external_dispatch(self):
        gate = ActivationGate(
            ScopePolicy(), ActivationPolicy(
                mode=ActivationMode.LAB_ONLY, activation_reference="LAB-SYNTHETIC"
            )
        )
        target = Target("127.0.0.1")
        decision = gate.scope_policy.decide(target)
        with patch("lightup.activation.token_urlsafe", return_value="x" * 32):
            permit = gate.issue(target, "web-baseline")
        r = self.review(permit, decision)
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assert_no_authority(r)

    def test_source_plan_only_has_no_permit(self):
        gate = ActivationGate(ScopePolicy(), ActivationPolicy())
        with self.assertRaises(PermissionError):
            gate.issue(Target("127.0.0.1"), "web-baseline")

    def test_public_decision_cannot_satisfy_lab_mode(self):
        for reason in (ScopeReason.EXPLICIT_HOST, ScopeReason.EXPLICIT_NETWORK):
            with self.subTest(reason=reason):
                r = self.review(decision=replace(self.decision, reason=reason))
                self.assertEqual(r.status, "HOLD")
                self.assert_no_authority(r)

    def test_forged_public_host_with_loopback_reason_is_held(self):
        r = self.review(
            permit=replace(self.permit, target="public.example.test"),
            decision=ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK)
        )
        self.assertEqual(r.status, "HOLD")

    def test_reject_target_mismatch(self):
        self.assertEqual(
            self.review(permit=replace(self.permit, target="127.0.0.2")).status,
            "HOLD",
        )

    def test_reject_denial_and_truthy_nonboolean(self):
        for bad in (False, "yes", 1):
            with self.subTest(bad=bad):
                self.assertEqual(
                    self.review(decision=replace(self.decision, allowed=bad)).status,
                    "HOLD",
                )

    def test_reject_foreign_reason_type(self):
        self.assertEqual(
            self.review(decision=replace(self.decision, reason="loopback")).status,
            "HOLD",
        )

    def test_canonical_private_network_positive_and_special_use_negative(self):
        for host in ("10.2.3.4", "172.16.0.1", "192.168.7.8", "fd00::1"):
            with self.subTest(host=host):
                r = self.review(
                    permit=replace(self.permit, target=host),
                    decision=ScopeDecision(True, host, ScopeReason.PRIVATE_LAB),
                )
                self.assertEqual(r.status, "REVIEW_ONLY")
                self.assert_no_authority(r)
        for host in ("169.254.1.2", "192.0.2.10", "fe80::1", "0.0.0.0"):
            with self.subTest(host=host):
                self.assertEqual(
                    self.review(
                        permit=replace(self.permit, target=host),
                        decision=ScopeDecision(True, host, ScopeReason.PRIVATE_LAB)
                    ).status, "HOLD",
                )

    def test_canonical_ipv6_loopback_and_zone_denial(self):
        for host, expected in (("::1", "REVIEW_ONLY"), ("::1%eth0", "HOLD")):
            with self.subTest(host=host):
                self.assertEqual(self.review(
                    permit=replace(self.permit, target=host),
                    decision=ScopeDecision(True, host, ScopeReason.LOOPBACK)
                ).status, expected)

    def test_malformed_identifiers_and_reference(self):
        variations = (
            replace(self.permit, permit_id=""),
            replace(self.permit, permit_id="x" * 100),
            replace(self.permit, permit_id=123),
            replace(self.permit, capability_id="web baseline"),
            replace(self.permit, capability_id="CAP"),
            replace(self.permit, activation_reference="LAB"),
            replace(self.permit, activation_reference="LAB-OTHER"),
        )
        for p in variations:
            with self.subTest(value=type(p.permit_id).__name__):
                r = self.review(permit=p)
                self.assertEqual(r.status, "HOLD")
                self.assert_no_authority(r)
        for ref in ("LAB", "LAB-SYＮTHETIC", 7, "LAB-\nSYNTHETIC"):
            with self.subTest(ref=type(ref).__name__):
                self.assertEqual(self.review(reference=ref).status, "HOLD")

    def test_plan_and_authorized_always_hold(self):
        for mode in (ActivationMode.PLAN_ONLY, ActivationMode.AUTHORIZED, "lab_only"):
            with self.subTest(mode=mode):
                r = self.review(permit=replace(self.permit, mode=mode))
                self.assertEqual(r.status, "HOLD")
                self.assert_no_authority(r)

    def test_naive_non_utc_and_subclass_timestamp_hold(self):
        class WeirdDatetime(datetime):
            pass
        for dt in (
            datetime(2026, 10, 16),
            datetime(2026, 10, 16, tzinfo=timezone.utc).astimezone(
                timezone(__import__("datetime").timedelta(hours=1))
            ),
            WeirdDatetime(2026, 10, 16, tzinfo=timezone.utc),
            "2026-10-16T12:00:00Z",
        ):
            with self.subTest(dt=type(dt).__name__):
                self.assertEqual(
                    self.review(permit=replace(self.permit, issued_at=dt)).status,
                    "HOLD",
                )

    def test_extra_and_missing_fields_hold_without_exception(self):
        p = replace(self.permit)
        object.__setattr__(p, "release_allowed", True)
        self.assertEqual(self.review(permit=p).status, "HOLD")
        uninitialized = object.__new__(ExecutionPermit)
        self.assertEqual(self.review(permit=uninitialized).status, "HOLD")
        d = replace(self.decision)
        object.__setattr__(d, "verified", True)
        self.assertEqual(self.review(decision=d).status, "HOLD")
        uninitialized_decision = object.__new__(ScopeDecision)
        self.assertEqual(self.review(decision=uninitialized_decision).status, "HOLD")

    def test_fake_subclass_and_foreign_objects_are_held(self):
        class PermSub(ExecutionPermit):
            pass
        class DecSub(ScopeDecision):
            pass
        values = (
            (PermSub(**vars(self.permit)), self.decision),
            (self.permit, DecSub(**vars(self.decision))),
            (object(), self.decision),
            (self.permit, object()),
        )
        for p, d in values:
            r = self.review(permit=p, decision=d)
            self.assertEqual(r.status, "HOLD")
            self.assert_no_authority(r)

    def test_no_network_sqlite_process_or_file_during_review(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("review must never do I/O")
        with (
            patch("socket.socket", side_effect=forbidden),
            patch("socket.getaddrinfo", side_effect=forbidden),
            patch("sqlite3.connect", side_effect=forbidden),
            patch("subprocess.Popen", side_effect=forbidden),
            patch("builtins.open", side_effect=forbidden),
            patch("os.open", side_effect=forbidden),
        ):
            self.assertEqual(self.review().status, "REVIEW_ONLY")

    def test_no_input_mutation_and_repeatable_review(self):
        p_before, d_before = dict(vars(self.permit)), dict(vars(self.decision))
        results = [self.review() for _ in range(32)]
        self.assertTrue(all(r == results[0] for r in results))
        self.assertEqual(vars(self.permit), p_before)
        self.assertEqual(vars(self.decision), d_before)
        self.assert_no_authority(results[0])


if __name__ == "__main__":
    unittest.main()
