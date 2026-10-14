"""#1422: real LAB_ONLY ActivationGate issue chain; offline RED witnesses.

No network, DNS, executor, adapter, persisted grant or real permit is used.
Known unsafe current-source admissions are intentional expected failures.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import builtins
import importlib.util
import json
import os
import sqlite3
import socket
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup import activation as activation_module
from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy, ExecutionPermit
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason

SCRIPT = ROOT / "scripts" / "audit_scope_activation_lab_permit_1422_offline.py"
SPEC = importlib.util.spec_from_file_location("scope_activation_lab_permit_1422", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ActualActivationPermitChainRED(unittest.TestCase):
    def setUp(self):
        self.gate = ActivationGate(
            ScopePolicy(allow_private_lab=True),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )

    def _must_deny_without_target_io(self, literal: str):
        # The source's only token creator is replaced with a marker to avoid
        # generating any real authorization artifact.
        with patch("lightup.activation.token_urlsafe", return_value="SYNTHETIC"):
            with self.assertRaises(PermissionError):
                self.gate.issue(Target(literal), "synthetic_reference_only")

    @unittest.expectedFailure
    def test_documentation_192_0_2_denied_before_permit(self):
        self._must_deny_without_target_io("192.0.2.1")

    @unittest.expectedFailure
    def test_documentation_198_51_100_denied_before_permit(self):
        self._must_deny_without_target_io("198.51.100.1")

    @unittest.expectedFailure
    def test_documentation_203_0_113_denied_before_permit(self):
        self._must_deny_without_target_io("203.0.113.1")

    @unittest.expectedFailure
    def test_benchmark_198_18_denied_before_permit(self):
        self._must_deny_without_target_io("198.18.0.1")

    @unittest.expectedFailure
    def test_unspecified_0_0_0_0_denied_before_permit(self):
        self._must_deny_without_target_io("0.0.0.0")

    @unittest.expectedFailure
    def test_broadcast_255_255_255_255_denied_before_permit(self):
        self._must_deny_without_target_io("255.255.255.255")

    @unittest.expectedFailure
    def test_ipv6_documentation_denied_before_permit(self):
        self._must_deny_without_target_io("[2001:db8::1]")

    @unittest.expectedFailure
    def test_ipv4_link_local_denied_before_permit(self):
        self._must_deny_without_target_io("169.254.1.1")

    @unittest.expectedFailure
    def test_ipv4_mapped_documentation_denied_before_permit(self):
        self._must_deny_without_target_io("[::ffff:192.0.2.1]")

    @unittest.expectedFailure
    def test_ipv6_link_local_denied_before_permit(self):
        self._must_deny_without_target_io("[fe80::1]")

    def test_actual_known_lab_controls_are_not_public_approval(self):
        for literal in AUDIT.SAFE_LAB:
            with self.subTest(sample=literal):
                with patch("lightup.activation.token_urlsafe", return_value="SYNTHETIC"):
                    permit = self.gate.issue(Target(literal), "synthetic_reference_only")
                self.assertIs(type(permit), ExecutionPermit)
                self.assertEqual(permit.permit_id, "SYNTHETIC")
                self.assertIs(permit.mode, ActivationMode.LAB_ONLY)

    def test_plan_only_is_terminal_for_all_synthetic_samples(self):
        gate = ActivationGate(
            ScopePolicy(), ActivationPolicy(mode=ActivationMode.PLAN_ONLY)
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for literal in AUDIT.SAFE_LAB + AUDIT.NOT_LAB:
                with self.subTest(sample=literal), self.assertRaises(PermissionError):
                    gate.issue(Target(literal), "synthetic_reference_only")

    def test_lockdown_denies_special_and_private_except_loopback(self):
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for literal in (
                "192.0.2.1", "198.18.0.1", "[2001:db8::1]",
                "169.254.1.1", "10.1.2.3", "192.168.1.1",
            ):
                with self.subTest(sample=literal), self.assertRaises(PermissionError):
                    gate.issue(Target(literal), "synthetic_reference_only")


    def test_explicit_public_scope_never_upgrades_lab_only_to_target_active(self):
        # A policy may permit an explicitly scoped public host or network
        # syntactically, but LAB_ONLY must not turn EXPLICIT_* into a lab permit.
        fake_consent = Authorization(owner="synthetic-owner", reference="SYNTHETIC-ONLY")
        cases = (
            (
                ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset({"consented.example.test"}),
                ),
                Target("consented.example.test", authorization=fake_consent),
                ScopeReason.EXPLICIT_HOST,
            ),
            (
                ScopePolicy(
                    allow_private_lab=False,
                    explicit_networks=("192.0.2.0/24",),
                ),
                Target("192.0.2.42", authorization=fake_consent),
                ScopeReason.EXPLICIT_NETWORK,
            ),
            (
                ScopePolicy(
                    allow_private_lab=False,
                    require_authorization_for_public=False,
                    explicit_hosts=frozenset({"unconsented.example.test"}),
                ),
                Target("unconsented.example.test"),
                ScopeReason.EXPLICIT_HOST,
            ),
            (
                ScopePolicy(
                    allow_private_lab=False,
                    require_authorization_for_public=False,
                    explicit_networks=("198.51.100.0/24",),
                ),
                Target("198.51.100.42"),
                ScopeReason.EXPLICIT_NETWORK,
            ),
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for policy, target, reason in cases:
                with self.subTest(sample=target.value, expected_reason=reason.value):
                    scope_decision = policy.decide(target)
                    self.assertTrue(scope_decision.allowed)
                    self.assertIs(scope_decision.reason, reason)
                    gate = ActivationGate(
                        policy, ActivationPolicy(mode=ActivationMode.LAB_ONLY)
                    )
                    with self.assertRaises(PermissionError):
                        gate.issue(target, "synthetic_reference_only")

    def test_expected_red_is_assertion_not_import_error(self):
        names = tuple(
            name for name in dir(self)
            if name.startswith("test_")
            and name.endswith("_denied_before_permit")
        )
        self.assertEqual(len(names), 10)
        result = unittest.TestResult()
        unittest.TestSuite(type(self)(name) for name in names).run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(len(result.expectedFailures), len(names))
        for _case, trace in result.expectedFailures:
            self.assertIn("AssertionError", trace)

    def test_auditor_reports_unsafe_chain_only_as_hold(self):
        result = AUDIT.audit()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["checked"], 50)
        self.assertGreaterEqual(result["violations"], 10)
        self.assertEqual(type(result["violations"]), int)
        for key in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "scan_allowed", "merge_approved", "release_approved",
        ):
            self.assertIs(result[key], False)

    def test_ipv4_mapped_and_ipv6_linklocal_lockdown_is_terminal(self):
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        with patch("lightup.activation.token_urlsafe", side_effect=AssertionError("minted")):
            for literal in ("[::ffff:192.0.2.1]", "[fe80::1]"):
                with self.subTest(sample=literal), self.assertRaises(PermissionError):
                    gate.issue(Target(literal), "synthetic_reference_only")


    def test_authority_receipt_flags_cannot_be_mutated_by_importers(self):
        with self.assertRaises(TypeError):
            AUDIT._DENIED["permit_issued"] = True
        with self.assertRaises(TypeError):
            AUDIT._DENIED["release_approved"] = True
        receipt = AUDIT.audit()
        for key in AUDIT._DENIED:
            self.assertIs(receipt[key], False)
        self.assertEqual(set(receipt), {
            "status", "checked", "violations", *AUDIT._DENIED,
        })
        self.assertLessEqual(len(json.dumps(receipt, sort_keys=True).encode()), 256)

    def test_permit_metadata_mutants_increase_violations_without_reflecting(self):
        baseline = AUDIT.audit()
        self.assertEqual(baseline["checked"], 50)
        self.assertEqual(baseline["violations"], 10)
        for field, replacement in (
            ("target", "forged.example.invalid"),
            ("activation_reference", "USER-CONTROLLED"),
            ("capability_id", "different-synthetic-capability"),
            ("issued_at", datetime(2026, 1, 1)),  # Naive timestamp
            ("issued_at", datetime(2000, 1, 1, tzinfo=timezone.utc)),
            ("issued_at", datetime(2100, 1, 1, tzinfo=timezone.utc)),
            ("permit_id", type("ForgedPermitId", (str,), {})("NO_REAL_PERMIT")),
        ):
            with self.subTest(field=field):
                class MutatedGate:
                    def __init__(self, *args, **kwargs):
                        self.original = ActivationGate(*args, **kwargs)

                    def issue(self, target, capability):
                        permit = self.original.issue(target, capability)
                        if target.value in AUDIT.SAFE_LAB:
                            return replace(permit, **{field: replacement})
                        return permit

                with patch.object(AUDIT, "ActivationGate", MutatedGate):
                    receipt = AUDIT.audit()
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["checked"], 50)
                self.assertEqual(
                    receipt["violations"],
                    baseline["violations"] + len(AUDIT.SAFE_LAB),
                )
                self.assertIs(receipt["permit_issued"], False)
                self.assertIs(receipt["release_approved"], False)
                self.assertNotIn(str(replacement), json.dumps(receipt))

    def test_python_io_mutant_canaries_fail_closed_without_effects(self):
        # All mutations use harmless local/synthetic arguments; a missing
        # guard is detected as an untripped mock rather than used as proof.
        attempts = (
            ("file_read", lambda: builtins.open(__file__, "rb")),
            ("path_read", lambda: Path(__file__).open("rb")),
            ("fd_read", lambda: os.open(__file__, os.O_RDONLY)),
            ("fd_write", lambda: os.write(-1, b"")),
            ("shell", lambda: os.system("")),
            ("sqlite", lambda: sqlite3.connect(":memory:")),
            ("process", lambda: subprocess.Popen(["/__synthetic_nonexistent__/binary"])),
            ("socket", lambda: socket.socket()),
        )
        for name, action in attempts:
            with self.subTest(name=name):
                class SideEffectGate:
                    def __init__(self, *args, **kwargs):
                        pass

                    def issue(self, target, capability):
                        action()
                        raise AssertionError("guard missing")

                with (
                    patch.object(AUDIT, "ActivationGate", SideEffectGate),
                    patch.object(
                        AUDIT, "_unexpected_io",
                        side_effect=RuntimeError("SENSITIVE-CANARY"),
                    ) as tripped,
                ):
                    receipt = AUDIT.audit()
                self.assertGreaterEqual(tripped.call_count, 1)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["checked"], 0)
                self.assertEqual(receipt["violations"], 1)
                self.assertNotIn("SENSITIVE", json.dumps(receipt))
                self.assertIs(receipt["execution_enabled"], False)

    def test_io_guards_leave_process_environment_restored(self):
        before_open = builtins.open
        before_os_open = os.open
        before_os_write = os.write
        before_popen = subprocess.Popen
        before_db = sqlite3.connect
        receipt = AUDIT.audit()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertIs(builtins.open, before_open)
        self.assertIs(os.open, before_os_open)
        self.assertIs(os.write, before_os_write)
        self.assertIs(subprocess.Popen, before_popen)
        self.assertIs(sqlite3.connect, before_db)


    def test_denied_locked_gate_never_mints_before_raising(self):
        baseline = AUDIT.audit()
        real_gate = ActivationGate

        class PrematureLockedMint:
            def __init__(self, policy, activation):
                self.real = real_gate(policy, activation)
                self.locked = (
                    activation.mode is ActivationMode.LAB_ONLY
                    and policy.allow_private_lab is False
                )

            def issue(self, target, capability):
                if self.locked and target.value == AUDIT.NOT_LAB[0]:
                    activation_module.token_urlsafe(24)
                    raise PermissionError("SENSITIVE-MINT-DENIED")
                return self.real.issue(target, capability)

        with patch.object(AUDIT, "ActivationGate", PrematureLockedMint):
            receipt = AUDIT.audit()
        self.assertEqual(receipt["checked"], baseline["checked"])
        self.assertEqual(receipt["violations"], baseline["violations"] + 1)
        self.assertIs(receipt["permit_issued"], False)
        self.assertNotIn("SENSITIVE", json.dumps(receipt))

    def test_denied_plan_only_never_mints_before_raising(self):
        baseline = AUDIT.audit()
        real_gate = ActivationGate

        class PrematurePlanMint:
            def __init__(self, policy, activation):
                self.real = real_gate(policy, activation)
                self.plan = activation.mode is ActivationMode.PLAN_ONLY

            def issue(self, target, capability):
                if self.plan and target.value == AUDIT.SAFE_LAB[0]:
                    activation_module.token_urlsafe(24)
                    raise PermissionError("SENSITIVE-MINT-DENIED")
                return self.real.issue(target, capability)

        with patch.object(AUDIT, "ActivationGate", PrematurePlanMint):
            receipt = AUDIT.audit()
        self.assertEqual(receipt["checked"], baseline["checked"])
        self.assertEqual(receipt["violations"], baseline["violations"] + 1)
        self.assertIs(receipt["execution_enabled"], False)
        self.assertNotIn("SENSITIVE", json.dumps(receipt))

    def test_approved_synthetic_lab_sample_never_double_mints(self):
        baseline = AUDIT.audit()
        real_gate = ActivationGate

        class DoubleMint:
            def __init__(self, policy, activation):
                self.real = real_gate(policy, activation)
                self.allowed = (
                    activation.mode is ActivationMode.LAB_ONLY
                    and policy.allow_private_lab is True
                )

            def issue(self, target, capability):
                permit = self.real.issue(target, capability)
                if self.allowed and target.value == AUDIT.SAFE_LAB[0]:
                    activation_module.token_urlsafe(24)
                return permit

        with patch.object(AUDIT, "ActivationGate", DoubleMint):
            receipt = AUDIT.audit()
        self.assertEqual(receipt["checked"], baseline["checked"])
        self.assertEqual(receipt["violations"], baseline["violations"] + 1)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertIs(receipt["release_approved"], False)


    def test_fake_token_entropy_size_downgrade_and_type_confusion_hold(self):
        baseline = AUDIT.audit()
        self.assertEqual(baseline["violations"], 10)
        real_gate = ActivationGate
        for length in (0, 1, 16, 32, True, 24.0, "24"):
            with self.subTest(synthetic_length=repr(length)):
                class SyntheticWeakPermit:
                    def __init__(self, policy, activation):
                        self.real = real_gate(policy, activation)
                        self.lab = (
                            policy.allow_private_lab is True
                            and activation.mode is ActivationMode.LAB_ONLY
                        )

                    def issue(self, target, capability):
                        if self.lab and target.value == AUDIT.SAFE_LAB[0]:
                            # Mutation deliberately constructs an otherwise
                            # perfect synthetic permit using one weak token
                            # request; the mock must detect the call shape.
                            return ExecutionPermit(
                                permit_id=activation_module.token_urlsafe(length),
                                target="127.0.0.1",
                                capability_id=capability,
                                mode=ActivationMode.LAB_ONLY,
                                activation_reference="LAB",
                                issued_at=datetime.now(timezone.utc),
                            )
                        return self.real.issue(target, capability)

                with patch.object(AUDIT, "ActivationGate", SyntheticWeakPermit):
                    receipt = AUDIT.audit()
                self.assertEqual(receipt["checked"], baseline["checked"])
                self.assertEqual(receipt["violations"], baseline["violations"] + 1)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertIs(receipt["permit_issued"], False)
                self.assertEqual(set(receipt), {"status", "checked", "violations", *AUDIT._DENIED})


    def test_public_scope_denial_cannot_hide_premature_token_mint(self):
        baseline = AUDIT.audit()
        self.assertEqual(baseline["checked"], 50)
        self.assertEqual(baseline["violations"], 10)
        real_gate = ActivationGate

        class PrematureExplicitMint:
            def __init__(self, policy, activation):
                self.real = real_gate(policy, activation)

            def issue(self, target, capability):
                if target.value == "consented.example.test":
                    activation_module.token_urlsafe(24)
                    raise PermissionError("SYNTHETIC-PUBLIC-MINT-DENIED")
                return self.real.issue(target, capability)

        with patch.object(AUDIT, "ActivationGate", PrematureExplicitMint):
            receipt = AUDIT.audit()
        self.assertEqual(receipt["checked"], 50)
        self.assertEqual(receipt["violations"], 11)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(set(receipt), {"status", "checked", "violations", *AUDIT._DENIED})
        self.assertIs(receipt["permit_issued"], False)
        self.assertIs(receipt["scan_allowed"], False)


    def test_token_request_positional_shape_cannot_be_spoofed(self):
        baseline = AUDIT.audit()
        self.assertEqual(baseline["checked"], 50)
        self.assertEqual(baseline["violations"], 10)
        real_gate = ActivationGate

        class IntegerImpersonator(int):
            pass

        calls = (
            ("implicit_default", lambda: activation_module.token_urlsafe()),
            ("keyword", lambda: activation_module.token_urlsafe(nbytes=24)),
            ("keyword_alias", lambda: activation_module.token_urlsafe(_length=24)),
            ("extra_positional", lambda: activation_module.token_urlsafe(24, 24)),
            ("extra_keyword", lambda: activation_module.token_urlsafe(24, ignored=True)),
            ("integer_subclass", lambda: activation_module.token_urlsafe(IntegerImpersonator(24))),
        )
        for name, token_request in calls:
            with self.subTest(case=name):
                class SyntheticUnexpectedCall:
                    def __init__(self, policy, activation):
                        self.real = real_gate(policy, activation)
                        self.lab = (
                            policy.allow_private_lab is True
                            and activation.mode is ActivationMode.LAB_ONLY
                        )

                    def issue(self, target, capability):
                        if self.lab and target.value == AUDIT.SAFE_LAB[0]:
                            return ExecutionPermit(
                                permit_id=token_request(),
                                target="127.0.0.1",
                                capability_id=capability,
                                mode=ActivationMode.LAB_ONLY,
                                activation_reference="LAB",
                                issued_at=datetime.now(timezone.utc),
                            )
                        return self.real.issue(target, capability)

                with patch.object(AUDIT, "ActivationGate", SyntheticUnexpectedCall):
                    receipt = AUDIT.audit()
                self.assertEqual(receipt["checked"], baseline["checked"])
                self.assertEqual(receipt["violations"], baseline["violations"] + 1)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(set(receipt), {"status", "checked", "violations", *AUDIT._DENIED})

    def test_cli_single_fixed_receipt_no_literal_or_token_reflection(self):
        run = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT, capture_output=True, text=True, timeout=12, check=False,
        )
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stderr, "")
        self.assertEqual(len(run.stdout.splitlines()), 1)
        receipt = json.loads(run.stdout)
        self.assertEqual(receipt, AUDIT.audit())
        self.assertNotIn("192.0.2.1", run.stdout)
        self.assertNotIn("NO_REAL_PERMIT", run.stdout)

    def test_invalid_argv_always_hold_without_reflection(self):
        secret = "SYNTHETIC_NEVER_ECHO_SECRET"
        run = subprocess.run(
            [sys.executable, str(SCRIPT), "--target", secret],
            cwd=ROOT, capture_output=True, text=True, timeout=12, check=False,
        )
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stderr, "")
        self.assertEqual(json.loads(run.stdout)["checked"], 0)
        self.assertNotIn(secret, run.stdout)

    def test_unanticipated_gate_failure_fails_closed_without_exception_detail(self):
        with patch.object(AUDIT, "ActivationGate", side_effect=ValueError("SENSITIVE")):
            receipt = AUDIT.audit()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["checked"], 0)
        self.assertEqual(receipt["violations"], 1)
        self.assertNotIn("SENSITIVE", json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
