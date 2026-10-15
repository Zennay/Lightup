"""No-network synthetic evidence-only CI failure triage integration."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "scope_ci_failure_triage_review_20261015.py"
STAMP = "2026-10-15T22:30:07.0000000Z "
NAME = "test_all_inputs_remain_unchanged_after_pure_scope_decision"
FULLNAME = "test_scope_legacy_falsy_window_301_red_20261014.LegacyFalsyBoundaryRedTests." + NAME
KNOWN = (
    STAMP + "FAIL: " + NAME + " (" + FULLNAME + ")\n"
    + STAMP + "----------------------------------------------------------------------\n"
    + STAMP + "Traceback (most recent call last):\n"
    + STAMP + '  File "/home/runner/work/Lightup/Lightup/tests/test_scope_legacy_falsy_window_301_red_20261014.py", line 111, in '+NAME+"\n"
    + STAMP + "    self.assertTrue(_pure_scope_decision(a).allowed)\n"
    + STAMP + "AssertionError: False is not true\n"
    + STAMP + "----------------------------------------------------------------------\n"
    + STAMP + "Ran 1319 tests in 40.5s\n"
    + STAMP + "FAILED (failures=1, expected failures=23)\n"
)


def run(raw):
    p = subprocess.run([sys.executable, str(PATH)], input=raw,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return p, json.loads(p.stdout)


class FailureTriageTests(unittest.TestCase):
    def test_realistic_known_fixture_looks_like_hint_only(self):
        p, r = run(KNOWN.encode())
        self.assertEqual(p.returncode, 2)
        self.assertEqual(r["status"], "HOLD")
        self.assertEqual(r["summary"]["known_issue_hint"], 301)
        self.assertFalse(r["authorization_verified"])
        self.assertFalse(r["release_approved"])

    def test_known_fixture_still_reports_failed(self):
        _, r = run(KNOWN.encode())
        self.assertEqual(r["summary"]["reported_result"], "FAILED")
        self.assertEqual(r["summary"]["reported_failures"], 1)

    def test_fake_wrong_test_not_known(self):
        raw = KNOWN.replace("FAIL: "+NAME, "FAIL: test_other")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_wrong_test_module_not_known(self):
        raw = KNOWN.replace(FULLNAME, "test_other.Owned."+NAME)
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_wrong_assertion_not_known(self):
        raw = KNOWN.replace("AssertionError: False is not true", "AssertionError: Other")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_wrong_expression_not_known(self):
        raw = KNOWN.replace("self.assertTrue(_pure_scope_decision(a).allowed)", "self.assertTrue(True)")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_wrong_source_filename_not_known(self):
        raw = KNOWN.replace("test_scope_legacy_falsy_window_301_red_20261014.py", "test_other.py")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_wrong_traceback_method_not_known(self):
        raw = KNOWN.replace("line 111, in "+NAME, "line 111, in test_else")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_extra_real_error_cannot_hide_behind_known(self):
        raw = KNOWN.replace(STAMP+"Ran 1319 tests",
          STAMP+"ERROR: test_other (test_scope.Other.test_other)\n"+STAMP+"Ran 1319 tests")
        _, r = run(raw.encode())
        self.assertNotIn("summary", r)

    def test_footer_two_failures_without_two_tracebacks_rejected(self):
        raw = KNOWN.replace("FAILED (failures=1", "FAILED (failures=2")
        _, r = run(raw.encode())
        self.assertNotIn("summary", r)

    def test_extra_failure_is_not_known(self):
        extra = STAMP+"FAIL: test_other (test_scope.Other.test_other)\n"
        raw = KNOWN.replace(STAMP+"Ran 1319 tests", extra+STAMP+"Ran 1319 tests")
        raw = raw.replace("FAILED (failures=1", "FAILED (failures=2")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_error_only_is_untriaged(self):
        raw = (STAMP+"ERROR: test_other (test_scope.Other.test_other)\n"
               +STAMP+"Ran 2 tests in 0.1s\n"
               +STAMP+"FAILED (errors=1)\n")
        _, r = run(raw.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_ok_is_not_release(self):
        _, r = run(b"Ran 10 tests in 0.1s\nOK\n")
        self.assertEqual(r["status"], "HOLD")
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_forged_traceback_outside_failure_block_not_known(self):
        fake = KNOWN.replace('line 111, in '+NAME, 'line 111, in wrong')
        fake = fake + STAMP + '  File "/tests/test_scope_legacy_falsy_window_301_red_20261014.py", line 111, in '+NAME+'\n'
        _, r = run(fake.encode())
        self.assertIsNone(r["summary"]["known_issue_hint"])

    def test_forged_assertion_after_footer_does_not_promote(self):
        tampered = KNOWN.replace("AssertionError: False is not true",
                                 "AssertionError: Mismatch")
        tampered += STAMP + "AssertionError: False is not true\n"
        _, result = run(tampered.encode())
        self.assertIsNone(result["summary"]["known_issue_hint"])

    def test_forged_source_after_footer_does_not_promote(self):
        tampered = KNOWN.replace("line 111, in "+NAME,
                                 "line 111, in unrelated_method")
        tampered += (STAMP + '  File "/tests/test_scope_legacy_falsy_window_301_red_20261014.py", line 111, in '
                     +NAME+"\n")
        _, result = run(tampered.encode())
        self.assertIsNone(result["summary"]["known_issue_hint"])

    def test_fake_substring_cannot_match_heading(self):
        _, r = run(("Injected "+KNOWN).encode())
        self.assertNotIn("summary", r)

    def test_repeated_run_summary_is_ambiguous(self):
        _, r = run((KNOWN+"Ran 2 tests in 0.1s\nOK\n").encode())
        self.assertNotIn("summary", r)

    def test_oversized_stdin_holds(self):
        _, r = run(b"x" * (1024*1024+1))
        self.assertNotIn("summary", r)

    def test_utf8_error_holds(self):
        _, r = run(b"\xff")
        self.assertNotIn("summary", r)

    def test_logs_not_echoed_or_executed(self):
        marker = "fictional_customer_key.invalid"
        p, r = run((marker+"\n"+KNOWN).encode())
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(marker.encode(), p.stdout)
        self.assertEqual(r["status"], "HOLD")

    def test_zero_permissions_even_for_known_issue(self):
        _, r = run(KNOWN.encode())
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved", "scan_allowed"):
            self.assertIs(r[key], False)


if __name__ == "__main__":
    unittest.main()
