"""Offline acceptance for issue #1422's deterministic dual-stack boundary sweep."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from ipaddress import IPv6Address, ip_address, ip_network
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason
from audit_scope_ipv4_octet_sweep_1422_offline import (
    TOTAL_DECISIONS,
    main,
    review_ipv4_octet_sweep,
)


class IndependentStrictPolicy:
    """Only a synthetic oracle; never used by production or target execution."""

    def __init__(self, *, allow_private_lab, **kwargs):
        self.lab = allow_private_lab

    def decide(self, target):
        host = target.value[1:-1] if target.value.startswith("[") else target.value
        addr = ip_address(host)
        loopback = addr in (
            ip_network("127.0.0.0/8") if addr.version == 4
            else ip_network("::1/128")
        )
        networks = (
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            if addr.version == 4 else ("fc00::/7",)
        )
        lab = any(addr in ip_network(network) for network in networks)
        if loopback:
            return ScopeDecision(True, host, ScopeReason.LOOPBACK)
        if lab and self.lab:
            return ScopeDecision(True, host, ScopeReason.PRIVATE_LAB)
        return ScopeDecision(False, host, ScopeReason.OUT_OF_SCOPE)


class TrustAllPolicy(IndependentStrictPolicy):
    def decide(self, target):
        return ScopeDecision(True, target.value, ScopeReason.PRIVATE_LAB)


class DenyAllPolicy(IndependentStrictPolicy):
    def decide(self, target):
        return ScopeDecision(False, target.value, ScopeReason.OUT_OF_SCOPE)


class WrongIdentityPolicy(IndependentStrictPolicy):
    def decide(self, target):
        result = super().decide(target)
        return ScopeDecision(result.allowed, "127.0.0.1", result.reason)


class WrongTypePolicy(IndependentStrictPolicy):
    def decide(self, target):
        result = super().decide(target)
        return ScopeDecision(1 if result.allowed else 0, target.value, result.reason)


class CountedStrictPolicy(IndependentStrictPolicy):
    observed = []

    def decide(self, target):
        type(self).observed.append((self.lab, target.value))
        return super().decide(target)


class PoisonReprDecision:
    def __repr__(self):
        raise AssertionError("must not format untrusted scope decision")

    def __str__(self):
        raise AssertionError("must not stringify untrusted scope decision")


class PoisonReprPolicy(IndependentStrictPolicy):
    def decide(self, target):
        return PoisonReprDecision()


class WrongReasonPolicy(IndependentStrictPolicy):
    def decide(self, target):
        result = super().decide(target)
        return ScopeDecision(
            result.allowed, result.normalized_host, ScopeReason.INVALID_TARGET
        )


class NoImplicitAuthorizationPolicy(IndependentStrictPolicy):
    """Accept a synthetic preview only when every scope/grant input is inert."""

    observed_modes = []
    observed_targets = 0

    def __init__(
        self, *, allow_private_lab, explicit_hosts, explicit_networks,
        require_authorization_for_public,
    ):
        if (
            type(allow_private_lab) is not bool
            or type(explicit_hosts) is not frozenset
            or explicit_hosts
            or type(explicit_networks) is not tuple
            or explicit_networks
            or require_authorization_for_public is not True
        ):
            raise AssertionError("offline diagnostic must have no explicit grants")
        type(self).observed_modes.append(allow_private_lab)
        super().__init__(allow_private_lab=allow_private_lab)

    def decide(self, target):
        if (
            type(target) is not Target
            or target.authorization is not None
            or type(target.labels) is not tuple
            or target.labels
        ):
            raise AssertionError("scope diagnostic must not attach authority")
        type(self).observed_targets += 1
        return super().decide(target)


class LateFalseAdmissionPolicy(IndependentStrictPolicy):
    def decide(self, target):
        if target.value == "198.255.254.1":
            return ScopeDecision(True, target.value, ScopeReason.PRIVATE_LAB)
        return super().decide(target)


class LateFalseDenialPolicy(IndependentStrictPolicy):
    def decide(self, target):
        if target.value == "192.168.254.1":
            return ScopeDecision(False, target.value, ScopeReason.OUT_OF_SCOPE)
        return super().decide(target)


class UnexpectedErrorPolicy(IndependentStrictPolicy):
    def decide(self, target):
        raise RuntimeError("synthetic-secret-must-not-leak")


class OctetSweepTests(unittest.TestCase):
    CODES = frozenset({
        "RESULT_TYPE_MISMATCH", "HOST_IDENTITY_MISMATCH",
        "SCOPE_CLASSIFICATION_MISMATCH", "EVALUATION_EXCEPTION",
        "SAMPLE_COUNT_MISMATCH", "ARGUMENT_REJECTED",
        "MATCHED_NON_AUTHORIZING",
    })
    def assert_non_authorizing(self, receipt, status):
        self.assertEqual(
            set(receipt),
            {"status", "diagnostic_code", "checked_count", "total_count",
             "authorization_verified", "permit_issued", "execution_enabled",
             "merge_approved", "release_approved"},
        )
        self.assertIs(type(receipt["diagnostic_code"]), str)
        self.assertIn(receipt["diagnostic_code"], self.CODES)
        self.assertEqual(receipt["status"], status)
        self.assertEqual(receipt["total_count"], TOTAL_DECISIONS)
        self.assertEqual(
            receipt["checked_count"], TOTAL_DECISIONS if status == "REVIEW_ONLY" else 0
        )
        for field in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved",
        ):
            self.assertIs(receipt[field], False)

    def test_reference_matrix_is_real_and_bounded(self):
        self.assertEqual(TOTAL_DECISIONS, 15360)
        self.assert_non_authorizing(
            review_ipv4_octet_sweep(IndependentStrictPolicy), "REVIEW_ONLY"
        )

    def test_actual_oracle_invokes_every_unique_case_for_both_modes(self):
        from audit_scope_ipv4_octet_sweep_1422_offline import (
            _samples, _samples_ipv6,
        )
        expected = {row[0] for row in _samples()}
        expected.update(row[0] for row in _samples_ipv6())
        self.assertEqual(len(expected), 7680)
        CountedStrictPolicy.observed = []
        result = review_ipv4_octet_sweep(CountedStrictPolicy)
        self.assert_non_authorizing(result, "REVIEW_ONLY")
        self.assertEqual(len(CountedStrictPolicy.observed), TOTAL_DECISIONS)
        self.assertEqual(
            set(CountedStrictPolicy.observed),
            {(enabled, value) for enabled in (False, True) for value in expected},
        )

    def test_embedded_ipv4_ipv6_authorities_are_explicitly_untrusted(self):
        from audit_scope_ipv4_octet_sweep_1422_offline import (
            _expected_ipv6, _samples_ipv6,
        )
        entries = list(_samples_ipv6())
        self.assertEqual(len(entries), 1536)
        self.assertEqual(len({row[0] for row in entries}), 1536)
        self.assertTrue(all(row[0].startswith("[") and row[0].endswith("]") for row in entries))
        for ipv4_first in range(256):
            inner_ipv4 = f"{ipv4_first}.0.0.1"
            mapped = IPv6Address(f"::ffff:{inner_ipv4}")
            sixtofour = IPv6Address(f"2002:{ipv4_first:02x}00:1::1")
            nat64 = IPv6Address(f"64:ff9b::{inner_ipv4}")
            self.assertEqual(str(mapped.ipv4_mapped), inner_ipv4)
            self.assertIsNotNone(sixtofour.sixtofour)
            self.assertEqual(int(nat64) & ((1 << 32) - 1), int(ip_address(inner_ipv4)))
            for address in (mapped, sixtofour, nat64):
                normalized = address.compressed
                row = (f"[{normalized}]", normalized, int(address) >> 120)
                self.assertIn(row, entries)
                for enabled in (False, True):
                    self.assertEqual(
                        _expected_ipv6(normalized, row[2], enabled),
                        (False, ScopeReason.OUT_OF_SCOPE),
                    )

    def test_embedded_private_ipv4_cannot_be_laundered_into_lab(self):
        for address in (
            IPv6Address("::ffff:10.0.0.1"),
            IPv6Address("2002:0a00:0001::1"),
            IPv6Address("64:ff9b::10.0.0.1"),
            IPv6Address("::ffff:127.0.0.1"),
        ):
            literal = f"[{address.compressed}]"

            class UnsafeEmbeddedPolicy(IndependentStrictPolicy):
                def decide(self, target):
                    if target.value == literal:
                        return ScopeDecision(
                            True, address.compressed, ScopeReason.PRIVATE_LAB
                        )
                    return super().decide(target)

            self.assert_non_authorizing(
                review_ipv4_octet_sweep(UnsafeEmbeddedPolicy), "HOLD"
            )

    def test_last_decision_in_off_mode_cannot_leave_partial_approval(self):
        last_ipv6 = IPv6Address("64:ff9b::255.0.0.1")
        last_literal = f"[{last_ipv6.compressed}]"

        class LastDecisionUnsafePolicy(IndependentStrictPolicy):
            calls = 0

            def decide(self, target):
                type(self).calls += 1
                if not self.lab and target.value == last_literal:
                    return ScopeDecision(
                        True, last_ipv6.compressed, ScopeReason.PRIVATE_LAB
                    )
                return super().decide(target)

        receipt = review_ipv4_octet_sweep(LastDecisionUnsafePolicy)
        self.assertEqual(LastDecisionUnsafePolicy.calls, TOTAL_DECISIONS)
        self.assert_non_authorizing(receipt, "HOLD")

    def test_exact_policy_configuration_and_targets_never_mint_authority(self):
        NoImplicitAuthorizationPolicy.observed_modes = []
        NoImplicitAuthorizationPolicy.observed_targets = 0
        self.assert_non_authorizing(
            review_ipv4_octet_sweep(NoImplicitAuthorizationPolicy), "REVIEW_ONLY"
        )
        self.assertEqual(
            NoImplicitAuthorizationPolicy.observed_modes, [True, False]
        )
        self.assertEqual(
            NoImplicitAuthorizationPolicy.observed_targets, TOTAL_DECISIONS
        )

    def test_diagnostic_codes_are_fixed_and_no_sensitive_values_leak(self):
        cases = (
            (IndependentStrictPolicy, "REVIEW_ONLY", "MATCHED_NON_AUTHORIZING"),
            (TrustAllPolicy, "HOLD", "SCOPE_CLASSIFICATION_MISMATCH"),
            (DenyAllPolicy, "HOLD", "SCOPE_CLASSIFICATION_MISMATCH"),
            (WrongIdentityPolicy, "HOLD", "HOST_IDENTITY_MISMATCH"),
            (WrongTypePolicy, "HOLD", "RESULT_TYPE_MISMATCH"),
            (WrongReasonPolicy, "HOLD", "SCOPE_CLASSIFICATION_MISMATCH"),
            (PoisonReprPolicy, "HOLD", "RESULT_TYPE_MISMATCH"),
            (UnexpectedErrorPolicy, "HOLD", "EVALUATION_EXCEPTION"),
            (ScopePolicy, "HOLD", "SCOPE_CLASSIFICATION_MISMATCH"),
        )
        for factory, expected_status, expected_code in cases:
            with self.subTest(code=expected_code, factory=factory.__name__):
                buffer = StringIO()
                with redirect_stdout(buffer):
                    receipt = review_ipv4_octet_sweep(factory)
                self.assertEqual(buffer.getvalue(), "")
                self.assert_non_authorizing(receipt, expected_status)
                self.assertEqual(receipt["diagnostic_code"], expected_code)
                raw = json.dumps(receipt, sort_keys=True)
                self.assertNotIn("synthetic-secret", raw)
                self.assertNotIn("0.0.0.2", raw)
                self.assertNotIn("127.0.0.1", raw)

    def test_invalid_argv_reports_only_argument_rejected(self):
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main(["--target", "private-customer-secret.example"])
        receipt = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(receipt["diagnostic_code"], "ARGUMENT_REJECTED")
        self.assertNotIn("private-customer-secret.example", output.getvalue())

    def test_final_ipv6_mismatch_classification_is_atomic_and_private(self):
        final = IPv6Address("64:ff9b::255.0.0.1")
        last_literal = f"[{final.compressed}]"

        class LastHostSpoofPolicy(IndependentStrictPolicy):
            decisions = 0

            def decide(self, target):
                type(self).decisions += 1
                result = super().decide(target)
                if not self.lab and target.value == last_literal:
                    return ScopeDecision(
                        result.allowed,
                        "private-internal-target.invalid",
                        result.reason,
                    )
                return result

        result = review_ipv4_octet_sweep(LastHostSpoofPolicy)
        self.assertEqual(LastHostSpoofPolicy.decisions, TOTAL_DECISIONS)
        self.assert_non_authorizing(result, "HOLD")
        self.assertEqual(result["diagnostic_code"], "HOST_IDENTITY_MISMATCH")
        self.assertNotIn("private-internal-target", json.dumps(result))
        self.assertEqual(result["checked_count"], 0)

    def test_receipt_flags_are_fresh_literals_after_external_tampering(self):
        first = review_ipv4_octet_sweep(IndependentStrictPolicy)
        first["authorization_verified"] = True
        first["permit_issued"] = True
        first["execution_enabled"] = True
        first["merge_approved"] = True
        first["release_approved"] = True
        later_review = review_ipv4_octet_sweep(IndependentStrictPolicy)
        later_hold = review_ipv4_octet_sweep(TrustAllPolicy)
        self.assert_non_authorizing(later_review, "REVIEW_ONLY")
        self.assert_non_authorizing(later_hold, "HOLD")

    def test_unsafe_auto_admission_and_off_switch_are_atomic_hold(self):
        self.assert_non_authorizing(review_ipv4_octet_sweep(TrustAllPolicy), "HOLD")
        self.assert_non_authorizing(review_ipv4_octet_sweep(DenyAllPolicy), "HOLD")

    def test_late_boundaries_never_return_partial_review(self):
        # Neither the last reserved IPv4 nor deep private-use address may
        # escape a bounded atomic review by an early positive shortcut.
        self.assert_non_authorizing(
            review_ipv4_octet_sweep(LateFalseAdmissionPolicy), "HOLD"
        )
        self.assert_non_authorizing(
            review_ipv4_octet_sweep(LateFalseDenialPolicy), "HOLD"
        )

    def test_deep_matrix_has_distinct_samples_and_expected_boundaries(self):
        from audit_scope_ipv4_octet_sweep_1422_offline import _samples
        rows = list(_samples())
        self.assertEqual(len(rows), 6144)
        self.assertEqual(len({row[0] for row in rows}), len(rows))
        self.assertIn(("100.64.254.1", 100, 64), rows)
        self.assertIn(("169.254.128.1", 169, 254), rows)
        self.assertIn(("198.18.1.1", 198, 18), rows)
        self.assertIn(("192.168.254.1", 192, 168), rows)
        self.assertIn(("172.31.254.1", 172, 31), rows)

    def test_target_identity_laundering_and_type_confusion_hold(self):
        self.assert_non_authorizing(review_ipv4_octet_sweep(WrongIdentityPolicy), "HOLD")
        self.assert_non_authorizing(review_ipv4_octet_sweep(WrongTypePolicy), "HOLD")

    def test_unexpected_error_is_private_atomic_hold(self):
        output = StringIO()
        with redirect_stdout(output):
            receipt = review_ipv4_octet_sweep(UnexpectedErrorPolicy)
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("synthetic-secret", str(receipt))

    def test_all_matched_literally_without_network_or_process_io(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("network or process I/O attempted")
        with (
            patch.object(socket, "socket", side_effect=forbidden),
            patch.object(socket, "getaddrinfo", side_effect=forbidden),
            patch.object(socket, "create_connection", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        ):
            self.assert_non_authorizing(
                review_ipv4_octet_sweep(IndependentStrictPolicy), "REVIEW_ONLY"
            )

    def test_original_checkout_denial_diagnostic_is_io_free(self):
        # Running an installed-source HOLD must not touch even a lab literal.
        def forbidden(*args, **kwargs):
            raise AssertionError("unexpected network or process I/O")
        with (
            patch.object(socket, "socket", side_effect=forbidden),
            patch.object(socket, "getaddrinfo", side_effect=forbidden),
            patch.object(socket, "create_connection", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
        ):
            self.assert_non_authorizing(
                review_ipv4_octet_sweep(ScopePolicy), "HOLD"
            )

    def test_reference_review_only_cli_still_returns_nonzero(self):
        # An opt-in positive preview is never a successful execution token.
        with patch(
            "audit_scope_ipv4_octet_sweep_1422_offline.review_ipv4_octet_sweep",
            return_value=review_ipv4_octet_sweep(IndependentStrictPolicy),
        ):
            buffer = StringIO()
            with redirect_stdout(buffer):
                rc = main([])
        self.assertEqual(rc, 3)
        self.assert_non_authorizing(json.loads(buffer.getvalue()), "REVIEW_ONLY")
        self.assertEqual(len(buffer.getvalue().splitlines()), 1)

    def test_valid_no_argument_cli_never_reads_privacy_sensitive_stdin(self):
        class PoisonStdin:
            @property
            def buffer(self):
                raise AssertionError("stdin must never be read")

            def read(self, *args, **kwargs):
                raise AssertionError("stdin must never be read")

        output = StringIO()
        with patch.object(sys, "stdin", PoisonStdin()), redirect_stdout(output):
            rc = main([])
        self.assertEqual(rc, 2)  # installed policy still unsafe: HOLD
        receipt = json.loads(output.getvalue())
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(len(output.getvalue().splitlines()), 1)

    def test_malicious_empty_argv_list_subclass_denied_without_magic_methods(self):
        class PoisonList(list):
            def __len__(self):
                raise AssertionError("untrusted argv len called")

            def __iter__(self):
                raise AssertionError("untrusted argv iteration called")

        output = StringIO()
        with redirect_stdout(output):
            rc = main(PoisonList())
        self.assertEqual(rc, 2)
        self.assert_non_authorizing(json.loads(output.getvalue()), "HOLD")

    def test_invalid_argv_holds_without_echo_or_stdin_read(self):
        for argv in (["--help"], ["--target", "secret.example"], [], "bad", [object()]):
            if argv == []:
                continue
            output = StringIO()
            with redirect_stdout(output):
                code = main(argv)
            receipt = json.loads(output.getvalue())
            self.assertEqual(code, 2)
            self.assert_non_authorizing(receipt, "HOLD")
            self.assertNotIn("secret.example", output.getvalue())

    def test_real_isolated_cli_never_exits_successfully(self):
        command = [sys.executable, "-I", "-B", str(ROOT / "scripts" / "audit_scope_ipv4_octet_sweep_1422_offline.py")]
        for extra in ([], ["--unexpected", "secret.example"]):
            proc = subprocess.run(
                command + extra, input=b"ignored-secret", capture_output=True,
                cwd=ROOT, check=False, timeout=20,
            )
            self.assertIn(proc.returncode, (2, 3))
            self.assertEqual(proc.stderr, b"")
            self.assertEqual(len(proc.stdout.splitlines()), 1)
            receipt = json.loads(proc.stdout)
            self.assert_non_authorizing(
                receipt, "HOLD" if extra else receipt["status"]
            )
            self.assertNotIn(b"ignored-secret", proc.stdout)
            self.assertNotIn(b"secret.example", proc.stdout)

    @unittest.expectedFailure
    def test_current_installed_scope_policy_must_match_safe_matrix_RED(self):
        """Known #1422 source defect; intentionally RED, never a security PASS."""
        self.assert_non_authorizing(review_ipv4_octet_sweep(), "REVIEW_ONLY")

    def test_installed_red_witness_is_genuine_assertion_not_runtime_error(self):
        result = unittest.TestResult()
        suite = unittest.TestSuite([
            type(self)("test_current_installed_scope_policy_must_match_safe_matrix_RED")
        ])
        suite.run(result)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertFalse(result.unexpectedSuccesses)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertIn("AssertionError", result.expectedFailures[0][1])


if __name__ == "__main__":
    unittest.main()
