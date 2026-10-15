"""Python-pair summary equality is never proof of provenance/release."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

CLI = Path(__file__).resolve().parents[1] / "scripts" / "scope_python_pair_summary_review_20261015.py"
RED = "Ran 1341 tests in 42.807s\nFAILED (failures=1, expected failures=23)\n"
GREEN = "Ran 1341 tests in 42.807s\nOK (expected failures=23)\n"


def data(a=RED, b=RED, complete=True):
    return json.dumps({"schema_version": 1, "complete": complete,
                       "python_311_log": a, "python_314_log": b}).encode()


def run(raw):
    proc = subprocess.run([sys.executable, str(CLI)], input=raw,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return proc, json.loads(proc.stdout)


class PairTest(unittest.TestCase):
    def test_equal_failed_cannot_release(self):
        p, r = run(data())
        self.assertEqual(p.returncode, 2)
        self.assertEqual(r["summary"]["classification"], "UNAUTHENTICATED_EQUALITY")
        self.assertEqual(r["summary"]["reported_result_311"], "FAILED")
        self.assertFalse(r["release_approved"])

    def test_equal_green_cannot_release(self):
        p, r = run(data(GREEN, GREEN))
        self.assertEqual(p.returncode, 2)
        self.assertEqual(r["status"], "HOLD")
        self.assertFalse(r["authorization_verified"])

    def test_different_result_identified(self):
        _, r = run(data(RED, GREEN))
        self.assertEqual(r["summary"]["classification"], "MISMATCH")
        self.assertGreater(r["summary"]["different_summary_fields"], 0)

    def test_different_total_identified(self):
        _, r = run(data(RED, RED.replace("1341", "1342")))
        self.assertEqual(r["summary"]["different_summary_fields"], 1)

    def test_different_expected_red_identified(self):
        _, r = run(data(RED, RED.replace("expected failures=23", "expected failures=24")))
        self.assertEqual(r["summary"]["classification"], "MISMATCH")

    def test_same_counts_different_seconds_not_proof(self):
        _, r = run(data(RED, RED.replace("42.807s", "40.119s")))
        self.assertEqual(r["summary"]["different_summary_fields"], 0)
        self.assertEqual(r["summary"]["source_provenance"], "UNTRUSTED_LOG_TEXT")

    def test_identical_summary_but_different_actual_method_names(self):
        a = "test_alpha (test_scope_pair.Pair.test_alpha) ... ok\nRan 1 test in 0.1s\nOK\n"
        b = "test_beta (test_scope_pair.Pair.test_beta) ... ok\nRan 1 test in 0.1s\nOK\n"
        _, result = run(data(a, b))
        self.assertEqual(result["summary"]["different_summary_fields"], 0)
        self.assertEqual(result["summary"]["different_method_names"], 2)
        self.assertEqual(result["summary"]["classification"], "MISMATCH")

    def test_same_named_method_with_different_outcome_even_matching_summary(self):
        a = ("test_alpha (test_scope_pair.Pair.test_alpha) ... ok\n"
             "test_beta (test_scope_pair.Pair.test_beta) ... expected failure\n"
             "Ran 2 tests in 0.1s\nOK (expected failures=1)\n")
        b = ("test_alpha (test_scope_pair.Pair.test_alpha) ... expected failure\n"
             "test_beta (test_scope_pair.Pair.test_beta) ... ok\n"
             "Ran 2 tests in 0.1s\nOK (expected failures=1)\n")
        _, result = run(data(a, b))
        self.assertEqual(result["summary"]["different_method_names"], 0)
        self.assertEqual(result["summary"]["changed_method_results"], 2)
        self.assertEqual(result["summary"]["classification"], "MISMATCH")

    def test_same_methods_different_elapsed_does_not_create_mismatch(self):
        a = "test_alpha (test_scope_pair.Pair.test_alpha) ... ok\nRan 1 test in 1.1s\nOK\n"
        b = "test_alpha (test_scope_pair.Pair.test_alpha) ... ok\nRan 1 test in 2.2s\nOK\n"
        _, result = run(data(a, b))
        self.assertEqual(result["summary"]["method_listing"], "SELF_REPORTED_FULL")
        self.assertEqual(result["summary"]["classification"], "UNAUTHENTICATED_EQUALITY")
        self.assertFalse(result["release_approved"])

    def test_duplicate_verbosed_method_opaque_hold(self):
        row = "test_alpha (test_scope_pair.Pair.test_alpha) ... ok\n"
        text = row+row+"Ran 2 tests in 0.1s\nOK\n"
        _, result = run(data(text, text))
        self.assertNotIn("summary", result)

    def test_method_expected_red_more_than_footer_rejected(self):
        text = "test_red (test_scope_pair.Pair.test_red) ... expected failure\nRan 1 test in 0.1s\nOK\n"
        _, result = run(data(text, text))
        self.assertNotIn("summary", result)

    def test_more_method_rows_than_reported_total_rejected(self):
        text = ("test_a (test_scope_pair.Pair.test_a) ... ok\n"
                "test_b (test_scope_pair.Pair.test_b) ... ok\n"
                "Ran 1 test in 0.1s\nOK\n")
        _, result = run(data(text, text))
        self.assertNotIn("summary", result)

    def test_partial_verbose_log_is_explicit(self):
        text = "test_a (test_scope_pair.Pair.test_a) ... ok\nRan 2 tests in 0.1s\nOK\n"
        _, result = run(data(text, text))
        self.assertEqual(result["summary"]["method_listing"], "PARTIAL_OR_MISSING")
        self.assertEqual(result["status"], "HOLD")

    def test_incomplete_declared(self):
        _, r = run(data(complete=False))
        self.assertEqual(r["summary"]["coverage"], "INCOMPLETE")

    def test_claimed_complete_is_self_asserted(self):
        _, r = run(data())
        self.assertEqual(r["summary"]["coverage"], "SELF_ASSERTED_UNVERIFIED")

    def test_missing_log_rejected(self):
        _, r = run(data("", RED))
        self.assertNotIn("summary", r)

    def test_multi_suite_rejected(self):
        _, r = run(data(RED, RED+RED))
        self.assertNotIn("summary", r)

    def test_bool_version_rejected(self):
        d = json.loads(data())
        d["schema_version"] = True
        _, r = run(json.dumps(d).encode())
        self.assertNotIn("summary", r)

    def test_float_version_rejected(self):
        d = json.loads(data())
        d["schema_version"] = 1.0
        _, r = run(json.dumps(d).encode())
        self.assertNotIn("summary", r)

    def test_duplicate_key_rejected(self):
        _, r = run(b'{"schema_version":1,"schema_version":1,"complete":true,"python_311_log":"x","python_314_log":"x"}')
        self.assertNotIn("summary", r)

    def test_nonfinite_constant_rejected(self):
        d = data().replace(b'"schema_version": 1', b'"schema_version": NaN')
        _, r = run(d)
        self.assertNotIn("summary", r)

    def test_surrogate_character_rejected(self):
        d = json.loads(data())
        d["python_311_log"] = chr(0xD800)
        p, r = run(json.dumps(d).encode())
        self.assertEqual(p.stderr, b"")
        self.assertNotIn("summary", r)

    def test_unknown_property_rejected(self):
        d = json.loads(data())
        d["grant"] = "approved"
        _, r = run(json.dumps(d).encode())
        self.assertNotIn("summary", r)

    def test_oversized_envelope_rejected(self):
        _, r = run(b"x" * (2*1024*1024 + 32769))
        self.assertNotIn("summary", r)

    def test_no_secret_or_raw_line_echo(self):
        secret = "private_fake_key.invalid"
        p, r = run(data(secret+"\n"+RED, RED))
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(secret.encode(), p.stdout)
        self.assertEqual(r["status"], "HOLD")

    def test_flags_all_hard_false(self):
        _, r = run(data(GREEN, GREEN))
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved", "scan_allowed"):
            self.assertIs(r[key], False)


if __name__ == "__main__":
    unittest.main()
