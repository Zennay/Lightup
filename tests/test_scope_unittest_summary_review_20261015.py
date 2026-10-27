"""Synthetic job summary logs; no GitHub, DNS, server, targets, consent."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "scope_unittest_summary_review_20261015.py"
FAILED = b"2026-10-15T22:18:15.2183779Z Ran 1274 tests in 41.299s\n2026-10-15T22:18:15.2184157Z FAILED (failures=1, expected failures=23)\n"
SUCCESS = b"Ran 37 tests in 0.06s\nOK\n"


def run(raw):
    p = subprocess.run([sys.executable, str(PATH)], input=raw,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return p, json.loads(p.stdout)


class SummaryReviewTests(unittest.TestCase):
    def test_realistic_timestamped_failure(self):
        p, r = run(FAILED)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(r["summary"]["reported_tests"], 1274)
        self.assertEqual(r["summary"]["expected_failures"], 23)
        self.assertEqual(r["summary"]["failures"], 1)

    def test_clean_success_still_hold(self):
        _, r = run(SUCCESS)
        self.assertEqual(r["summary"]["reported_result"], "OK")
        self.assertEqual(r["status"], "HOLD")
        self.assertFalse(r["release_approved"])

    def test_expected_failure_without_runtime_failure(self):
        _, r = run(b"Ran 30 tests in 1.0s\nOK (expected failures=5)\n")
        self.assertEqual(r["summary"]["expected_failures"], 5)
        self.assertFalse(r["authorization_verified"])

    def test_other_counters(self):
        _, r = run(b"Ran 30 tests in 1.0s\nFAILED (failures=2, errors=1, skipped=4, expected failures=5, unexpected successes=1)\n")
        self.assertEqual(r["summary"]["unexpected_successes"], 1)
        self.assertEqual(r["summary"]["skipped"], 4)

    def test_no_summary_opaque(self):
        _, r = run(b"Run in progress\n")
        self.assertNotIn("summary", r)

    def test_duplicate_suite_opaque(self):
        _, r = run(FAILED + SUCCESS)
        self.assertNotIn("summary", r)

    def test_duplicate_finish_opaque(self):
        _, r = run(SUCCESS + b"OK\n")
        self.assertNotIn("summary", r)

    def test_failed_without_reason_opaque(self):
        _, r = run(b"Ran 3 tests in 0.2s\nFAILED\n")
        self.assertNotIn("summary", r)

    def test_ok_with_failures_opaque(self):
        _, r = run(b"Ran 3 tests in 0.2s\nOK (failures=1)\n")
        self.assertNotIn("summary", r)

    def test_impossible_counts_opaque(self):
        _, r = run(b"Ran 2 tests in 0.2s\nFAILED (failures=1, errors=2)\n")
        self.assertNotIn("summary", r)

    def test_duplicate_counter_opaque(self):
        _, r = run(b"Ran 3 tests in 0.2s\nFAILED (failures=1, failures=2)\n")
        self.assertNotIn("summary", r)

    def test_duplicate_zero_counter_is_rejected(self):
        _, r = run(b"Ran 3 tests in 0.2s\nFAILED (failures=0, failures=1)\n")
        self.assertNotIn("summary", r)

    def test_unknown_counter_opaque(self):
        _, r = run(b"Ran 3 tests in 0.2s\nFAILED (failures=1, issued_grant=1)\n")
        self.assertNotIn("summary", r)

    def test_invalid_utf8_opaque(self):
        _, r = run(b"\xff")
        self.assertNotIn("summary", r)

    def test_oversized_opaque(self):
        _, r = run(b"x" * (1024*1024+1))
        self.assertNotIn("summary", r)

    def test_cannot_spoof_by_embedded_prefix(self):
        _, r = run(b"attacker Ran 2 tests in 0.3s\nFAILED (failures=1)\n")
        self.assertNotIn("summary", r)

    def test_no_echo_arbitrary_log_secrets(self):
        p, r = run(b"fictional_token=secret.invalid\n" + FAILED)
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(b"secret.invalid", p.stdout)
        self.assertEqual(r["status"], "HOLD")

    def test_all_flags_false_even_success(self):
        _, r = run(SUCCESS)
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved", "scan_allowed"):
            self.assertIs(r[key], False)


if __name__ == "__main__":
    unittest.main()
