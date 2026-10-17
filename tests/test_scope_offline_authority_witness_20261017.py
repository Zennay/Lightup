"""Regression controls for the wholly offline, non-authorizing witness (#1565)."""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import scope_offline_authority_witness_20261017 as witness  # noqa: E402

FLAGS = tuple(witness.FALSE_AUTHORITY)


class OfflineAuthorityWitnessTests(unittest.TestCase):
    def assert_no_authority(self, receipt):
        self.assertEqual(receipt["schema"], witness.SCHEMA)
        for key in FLAGS:
            self.assertIs(receipt[key], False, key)
        self.assertNotIn("target", receipt)
        self.assertNotIn("authorization", receipt)
        self.assertNotIn("token", receipt)

    def test_canonical_matrix_is_review_only_not_execution_permission(self):
        result = witness.evaluate()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["checked"], 11)
        self.assertRegex(result["synthetic_matrix_sha256"], r"^[0-9a-f]{64}$")
        self.assert_no_authority(result)

    def test_receipt_digest_is_deterministic(self):
        one = witness.evaluate()
        two = witness.evaluate()
        self.assertEqual(one, two)
        self.assertEqual(one["status"], "REVIEW_ONLY")

    def test_no_target_host_or_synthetic_consent_text_is_exposed(self):
        rendered = json.dumps(witness.evaluate(), sort_keys=True)
        for text in ("127.0.0.1", "8.8.8.8", "fixture.example.test", "SYNTHETIC-NOT-CONSENT"):
            self.assertNotIn(text, rendered)

    def test_policy_drift_to_allow_denied_case_fails_closed(self):
        def allow_all(self, target):
            return witness.ScopeDecision(True, "127.0.0.1", witness.ScopeReason.LOOPBACK)
        with patch.object(witness.ScopePolicy, "decide", allow_all):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "scope_policy_contract_drift")
        self.assert_no_authority(result)

    def test_reason_drift_fails_closed(self):
        original = witness.ScopePolicy.decide
        def different_reason(self, target):
            found = original(self, target)
            return witness.ScopeDecision(found.allowed, found.normalized_host, witness.ScopeReason.OUT_OF_SCOPE)
        with patch.object(witness.ScopePolicy, "decide", different_reason):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_host_normalization_drift_fails_closed(self):
        original = witness.ScopePolicy.decide
        def different_host(self, target):
            found = original(self, target)
            return witness.ScopeDecision(found.allowed, "unexpected.example.test", found.reason)
        with patch.object(witness.ScopePolicy, "decide", different_host):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_non_boolean_allowed_flag_fails_closed(self):
        with patch.object(witness.ScopePolicy, "decide", return_value=witness.ScopeDecision(1, "127.0.0.1", witness.ScopeReason.LOOPBACK)):
            result = witness.evaluate()
        self.assertEqual(result["reason"], "invalid_decision_shape")
        self.assert_no_authority(result)

    def test_evaluator_exception_is_generic_hold_without_leakage(self):
        with patch.object(witness.ScopePolicy, "decide", side_effect=RuntimeError("DONT-LEAK-PRIVATE")):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_evaluation_failed")
        self.assertNotIn("DONT-LEAK-PRIVATE", json.dumps(result))
        self.assert_no_authority(result)

    def test_duplicate_and_noncanonical_case_identity_fail_closed(self):
        cases = witness.canonical_cases()
        for tampered in (
            (cases[0],) + (cases[0],) + cases[2:],
            (replace(cases[0], case_id="bad-Σ"),) + cases[1:],
            cases[:-1],
        ):
            with self.subTest(tampered=tampered[0].case_id, size=len(tampered)):
                result = witness.evaluate(tampered)
                self.assertEqual(result["status"], "HOLD")
                self.assert_no_authority(result)

    def test_fake_expected_acceptance_fails_closed(self):
        cases = witness.canonical_cases()
        changed = (replace(cases[4], expected_allowed=True),)
        result = witness.evaluate(cases[:4] + changed + cases[5:])
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_no_network_socket_or_dns_is_necessary(self):
        with (patch.object(socket, "socket", side_effect=AssertionError("network invoked")),
              patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns invoked"))):
            result = witness.evaluate()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assert_no_authority(result)

    def test_main_refuses_missing_or_invalid_opt_in(self):
        for args in ([], ["--json"], ["--offline-lab-only", "--anything"], "bad", [object()], (["--offline-lab-only"]), ["--offline-lab-only", 1]):
            with self.subTest(args=repr(args)):
                with patch("builtins.print") as report:
                    code = witness.main(args)
                self.assertEqual(code, 2)
                body = json.loads(report.call_args.args[0])
                self.assertEqual(body["status"], "HOLD")
                self.assert_no_authority(body)

    def test_cli_refuses_str_subclass_and_list_subclass(self):
        class FakeStr(str):
            def __eq__(self, other):
                raise AssertionError("untrusted equality invoked")
        class FakeList(list):
            def __iter__(self):
                raise AssertionError("untrusted iterator invoked")
        for argv in ([FakeStr("--offline-lab-only")], FakeList(["--offline-lab-only"])):
            with patch("builtins.print") as report:
                code = witness.main(argv)
            self.assertEqual(code, 2)
            body = json.loads(report.call_args.args[0])
            self.assert_no_authority(body)

    def test_real_python_child_requires_exact_opt_in_and_never_exits_zero(self):
        script = ROOT / "scripts" / "scope_offline_authority_witness_20261017.py"
        for args, expected_code, expected_status in (
            ([], 2, "HOLD"),
            (["--offline-lab-only"], 3, "REVIEW_ONLY"),
        ):
            with self.subTest(args=args):
                done = subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(done.returncode, expected_code, done.stderr)
                self.assertEqual(done.stderr, "")
                result = json.loads(done.stdout)
                self.assertEqual(result["status"], expected_status)
                self.assert_no_authority(result)


if __name__ == "__main__":
    unittest.main()
