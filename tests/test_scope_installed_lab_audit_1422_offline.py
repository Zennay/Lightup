"""Fail-closed offline acceptance for source-backed lab admission audit #1422."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_scope_installed_lab_policy_1422_offline import (
    LAB, NOT_LAB, EXPLICIT_HOST_DENIALS, TOTAL_CHECKS, ScopeDecision, ScopeReason,
    audit_installed_scope, main, _source_is_this_checkout,
)


class _FixturePolicy:
    def __init__(self, *, allow_private_lab, require_authorization_for_public=True,
                 explicit_networks=(), explicit_hosts=frozenset()):
        self.enabled = allow_private_lab
        self.explicit = bool(explicit_networks)
        self.requires_grant = require_authorization_for_public
        self.explicit_hosts = explicit_hosts

    def decide(self, target):
        hosts = dict(EXPLICIT_HOST_DENIALS)
        if target.value in hosts and "review.invalid" in self.explicit_hosts:
            reason = (
                ScopeReason.AUTHORIZATION_MISSING
                if target.authorization is None
                else ScopeReason.AUTHORIZATION_EXPIRED
            )
            return ScopeDecision(False, hosts[target.value], reason)
        positive = {original: (canonical, reason) for original, canonical, reason in LAB}
        if target.value in positive:
            host, reason = positive[target.value]
            if reason is ScopeReason.LOOPBACK:
                return ScopeDecision(True, host, ScopeReason.LOOPBACK)
            if self.enabled:
                return ScopeDecision(True, host, ScopeReason.PRIVATE_LAB)
            return ScopeDecision(False, host, ScopeReason.OUT_OF_SCOPE)
        if target.value in NOT_LAB:
            normalized = (target.value[1:-1]
                          if target.value.startswith("[") else target.value)
            if self.explicit and self.requires_grant:
                reason = (
                    ScopeReason.AUTHORIZATION_MISSING
                    if target.authorization is None
                    else ScopeReason.AUTHORIZATION_EXPIRED
                )
                return ScopeDecision(False, normalized, reason)
            return ScopeDecision(False, normalized, ScopeReason.OUT_OF_SCOPE)
        raise ValueError("unexpected fixture input")


class InstalledScopeLabAuditTests(unittest.TestCase):
    def assert_never_authority(self, receipt):
        self.assertEqual(
            {key: receipt[key] for key in (
                "authorization_verified", "permit_issued", "execution_enabled",
                "merge_approved", "release_approved"
            )},
            dict.fromkeys((
                "authorization_verified", "permit_issued", "execution_enabled",
                "merge_approved", "release_approved"
            ), False),
        )
        self.assertEqual(set(receipt), {
            "status", "checked_count", "total_count",
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved",
        })
        self.assertEqual(receipt["total_count"], TOTAL_CHECKS)
        self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
        self.assertEqual(receipt["checked_count"], TOTAL_CHECKS if
                         receipt["status"] == "REVIEW_ONLY" else 0)

    def test_fixture_complete_strict_policy_is_review_only_without_authority(self):
        receipt = audit_installed_scope(_FixturePolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")

    def test_strict_fixture_executes_every_declared_policy_case_exactly_once(self):
        # This is a real counting witness, not a guessed total in a receipt:
        # a future accidental early skip or duplicated policy decision fails.
        seen = []

        class CountingPolicy(_FixturePolicy):
            def decide(self, target):
                permission = target.authorization
                category = (
                    "host" if self.explicit_hosts
                    else "network" if self.explicit
                    else "lab_enabled" if self.enabled else "lab_disabled"
                )
                window = (
                    "none" if permission is None
                    else "future" if permission.valid_from is not None
                    else "expired"
                )
                seen.append((category, target.value, window))
                return super().decide(target)

        receipt = audit_installed_scope(CountingPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")

        expected = []
        for literal, _, _ in LAB:
            expected.extend((
                ("lab_enabled", literal, "none"),
                ("lab_disabled", literal, "none"),
            ))
        for literal in NOT_LAB:
            expected.extend((
                ("lab_enabled", literal, "none"),
                ("lab_disabled", literal, "none"),
                ("network", literal, "none"),
                ("network", literal, "expired"),
                ("network", literal, "future"),
            ))
        for literal, _ in EXPLICIT_HOST_DENIALS:
            expected.extend((
                ("host", literal, "none"),
                ("host", literal, "expired"),
                ("host", literal, "future"),
            ))
        self.assertEqual(len(expected), TOTAL_CHECKS)
        self.assertEqual(len(seen), TOTAL_CHECKS)
        self.assertCountEqual(seen, expected)

    def test_checkout_source_guard_does_not_hide_policy_evaluation(self):
        # This detects a vacuous HOLD from a source-path mismatch on a clean
        # checkout; fixture REVIEW_ONLY must exercise actual policy decisions.
        self.assertTrue(_source_is_this_checkout())

    def test_real_checkout_policy_audit_is_diagnostic_not_permission(self):
        self.assert_never_authority(audit_installed_scope())

    def test_one_misclassified_documentation_address_holds_entire_review(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1" and self.enabled:
                    return ScopeDecision(True, target.value, ScopeReason.PRIVATE_LAB)
                return super().decide(target)
        receipt = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")

    def test_explicit_all_networks_without_grant_must_never_grant(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit and target.value == "8.8.8.8":
                    return ScopeDecision(True, target.value, ScopeReason.EXPLICIT_NETWORK)
                return super().decide(target)
        receipt = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")

    def test_not_yet_effective_explicit_network_must_deny(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                permission = target.authorization
                if self.explicit and permission is not None and permission.valid_from is not None:
                    return ScopeDecision(True, "8.8.8.8", ScopeReason.EXPLICIT_NETWORK)
                return super().decide(target)
        result = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(result)
        self.assertEqual(result["status"], "HOLD")

    def test_not_yet_effective_explicit_network_denial_reason(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                permission = target.authorization
                if self.explicit and permission is not None and permission.valid_from is not None:
                    return ScopeDecision(False, target.value, ScopeReason.OUT_OF_SCOPE)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_expired_explicit_network_grant_must_deny(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit and target.authorization is not None:
                    return ScopeDecision(True, "8.8.8.8", ScopeReason.EXPLICIT_NETWORK)
                return super().decide(target)
        receipt = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")

    def test_expired_explicit_network_must_use_expired_reason(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit and target.authorization is not None:
                    return ScopeDecision(
                        False, target.value, ScopeReason.AUTHORIZATION_MISSING
                    )
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_not_yet_effective_explicit_host_must_deny(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                permission = target.authorization
                if self.explicit_hosts and permission is not None and permission.valid_from is not None:
                    return ScopeDecision(True, "review.invalid", ScopeReason.EXPLICIT_HOST)
                return super().decide(target)
        result = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(result)
        self.assertEqual(result["status"], "HOLD")

    def test_not_yet_effective_explicit_host_denial_reason(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                permission = target.authorization
                if self.explicit_hosts and permission is not None and permission.valid_from is not None:
                    return ScopeDecision(False, "review.invalid", ScopeReason.AUTHORIZATION_MISSING)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_explicit_host_missing_grant_must_deny(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit_hosts and target.authorization is None:
                    return ScopeDecision(True, "review.invalid", ScopeReason.EXPLICIT_HOST)
                return super().decide(target)
        receipt = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")

    def test_explicit_host_expired_grant_must_deny(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit_hosts and target.authorization is not None:
                    return ScopeDecision(True, "review.invalid", ScopeReason.EXPLICIT_HOST)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_explicit_host_normalization_is_required_for_denial(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit_hosts and target.value.startswith("https://"):
                    return ScopeDecision(
                        False, target.value, ScopeReason.AUTHORIZATION_MISSING
                    )
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_false_denial_reason_for_missing_grant_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if self.explicit and target.value in NOT_LAB:
                    return ScopeDecision(False, target.value, ScopeReason.OUT_OF_SCOPE)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_wrong_ipv6_loopback_or_bad_normalization_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "[::1]":
                    return ScopeDecision(True, "::01", ScopeReason.LOOPBACK)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_disabled_switch_cannot_admit_private_lab(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "10.0.0.1":
                    return ScopeDecision(True, target.value, ScopeReason.PRIVATE_LAB)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_denied_reserved_ip_cannot_be_relabelled_to_private_lab_host(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1" and self.enabled:
                    return ScopeDecision(
                        False, "10.0.0.1", ScopeReason.OUT_OF_SCOPE
                    )
                return super().decide(target)
        receipt = audit_installed_scope(IncorrectPolicy)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")

    def test_missing_grant_denial_preserves_exact_ipv4_host(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if (self.explicit and target.value == "8.8.8.8"
                        and target.authorization is None):
                    return ScopeDecision(
                        False, "127.0.0.1", ScopeReason.AUTHORIZATION_MISSING
                    )
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_expired_grant_denial_preserves_exact_ipv6_host(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if (self.explicit and target.value == "[2001:db8::1]"
                        and target.authorization is not None):
                    return ScopeDecision(
                        False, "::1", ScopeReason.AUTHORIZATION_EXPIRED
                    )
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_nonboolean_allowed_identity_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1":
                    return ScopeDecision(0, target.value, ScopeReason.OUT_OF_SCOPE)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_noncanonical_reason_identity_holds(self):
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1":
                    return ScopeDecision(False, target.value, "out_of_scope")
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_polymorphic_decision_identity_holds(self):
        class DerivedDecision(ScopeDecision):
            pass
        class IncorrectPolicy(_FixturePolicy):
            def decide(self, target):
                if target.value == "192.0.2.1":
                    return DerivedDecision(False, target.value, ScopeReason.OUT_OF_SCOPE)
                return super().decide(target)
        self.assertEqual(audit_installed_scope(IncorrectPolicy)["status"], "HOLD")

    def test_policy_exception_is_private_hold_receipt(self):
        def broken(*, allow_private_lab):
            raise RuntimeError("a simulated customer secret that must never leak")
        receipt = audit_installed_scope(broken)
        self.assert_never_authority(receipt)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertNotIn("secret", json.dumps(receipt))

    def test_in_process_strict_fixture_never_uses_network_or_subprocess(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")):
            self.assertEqual(audit_installed_scope(_FixturePolicy)["status"], "REVIEW_ONLY")

    def test_literal_matrix_covers_each_cidr_edge_and_is_duplicate_free(self):
        positive = [literal for literal, _, _ in LAB]
        self.assertEqual(len(positive), len(set(positive)))
        self.assertEqual(len(NOT_LAB), len(set(NOT_LAB)))
        self.assertFalse(set(positive).intersection(NOT_LAB))
        self.assertTrue({
            "9.255.255.255", "11.0.0.1", "172.15.255.255",
            "172.32.0.0", "192.167.255.255", "192.169.0.1",
            "126.255.255.255", "128.0.0.1",
            "[fbff:ffff::1]", "[fe00::1]",
            "[::ffff:10.0.0.1]", "[::ffff:127.0.0.1]",
            "[2002:c000:201::1]", "[2001:0::1]",
        }.issubset(NOT_LAB))
        self.assertEqual(len(EXPLICIT_HOST_DENIALS), 3)
        self.assertEqual(TOTAL_CHECKS, 201)

    def test_real_source_audit_performs_no_network_file_or_child_process(self):
        # Mocks MUST NOT be called: catching a forbidden IO exception and then
        # returning HOLD would otherwise conceal an actual attempted side effect.
        with patch.object(socket, "socket") as sock, \
             patch.object(socket, "getaddrinfo") as dns, \
             patch("builtins.open") as file_open, \
             patch.object(subprocess, "Popen") as popen:
            result = audit_installed_scope()
            self.assert_never_authority(result)
            sock.assert_not_called()
            dns.assert_not_called()
            file_open.assert_not_called()
            popen.assert_not_called()

    def test_preimported_foreign_scope_path_refuses_review(self):
        module = sys.modules["lightup.scope"]
        with patch.object(module, "__file__", "/tmp/unrelated/site/lightup/scope.py"):
            receipt = audit_installed_scope(_FixturePolicy)
            self.assert_never_authority(receipt)
            self.assertEqual(receipt["status"], "HOLD")

    def test_preimported_foreign_models_path_refuses_review(self):
        module = sys.modules["lightup.models"]
        with patch.object(module, "__file__", "/tmp/unrelated/site/lightup/models.py"):
            self.assertEqual(audit_installed_scope(_FixturePolicy)["status"], "HOLD")

    def test_preimported_noncanonical_module_fails_closed(self):
        with patch.dict(sys.modules, {"lightup.scope": object()}):
            self.assertEqual(audit_installed_scope(_FixturePolicy)["status"], "HOLD")

    def test_invalid_cli_arguments_hold_without_echo(self):
        for args in (["--literal", "customer-secret.example"], ["--help"], ["--json", "--json"]):
            with self.subTest(args=args):
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    exit_code = main(args)
                self.assertEqual(exit_code, 2)
                self.assertEqual(json.loads(buffer.getvalue())["status"], "HOLD")
                self.assertNotIn("customer-secret", buffer.getvalue())
                self.assertEqual(len(buffer.getvalue().splitlines()), 1)

    def test_isolated_interpreter_remains_non_authorizing(self):
        script = ROOT / "scripts" / "audit_scope_installed_lab_policy_1422_offline.py"
        process = subprocess.run(
            [sys.executable, "-I", "-B", str(script)],
            capture_output=True, text=True, timeout=15, cwd=ROOT, check=False,
        )
        self.assertIn(process.returncode, (2, 3))
        self.assertFalse(process.stderr)
        self.assertEqual(len(process.stdout.splitlines()), 1)
        self.assert_never_authority(json.loads(process.stdout))

    def test_cli_real_subprocess_is_single_receipt_and_never_success(self):
        script = ROOT / "scripts" / "audit_scope_installed_lab_policy_1422_offline.py"
        proc = subprocess.run(
            [sys.executable, "-B", str(script)],
            capture_output=True, text=True, timeout=15, cwd=ROOT, check=False,
        )
        self.assertIn(proc.returncode, (2, 3))
        self.assertFalse(proc.stderr)
        self.assertEqual(len(proc.stdout.splitlines()), 1)
        receipt = json.loads(proc.stdout)
        self.assert_never_authority(receipt)
        self.assertEqual(proc.returncode, 3 if receipt["status"] == "REVIEW_ONLY" else 2)


if __name__ == "__main__":
    unittest.main()
