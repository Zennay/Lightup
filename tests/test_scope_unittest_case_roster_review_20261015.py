"""Hermetic real-subprocess tests of the non-authorizing unittest case roster."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "scope_unittest_case_roster_review_20261015.py"
NAME = "test_scope_a.Sample.test_expected_red"
OTHER = "test_scope_a.Sample.test_normal"
LOG = ("2026-10-15T22:23:00.100Z test_expected_red (" + NAME + ") ... expected failure\n"
       "2026-10-15T22:23:00.101Z test_normal (" + OTHER + ") ... ok\n"
       "2026-10-15T22:23:00.102Z Ran 2 tests in 0.03s\n"
       "2026-10-15T22:23:00.103Z OK (expected failures=1)\n")


def row(name=NAME, state="expected_failure", issue=1147, owner=1462):
    return {"test": name, "issue": issue, "owner_pr": owner,
            "expected_status": state}


def payload(watch=None, log=LOG, complete=True):
    return json.dumps({"schema_version": 1, "complete": complete, "raw_log": log,
                       "watch": [row()] if watch is None else watch}).encode()


def run(raw):
    p = subprocess.run([sys.executable, str(PATH)], input=raw,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return p, json.loads(p.stdout)


class CaseRosterTests(unittest.TestCase):
    def test_expected_red_matched_but_no_release(self):
        p, result = run(payload())
        self.assertEqual(p.returncode, 2)
        self.assertEqual(result["summary"]["expected_red_observed"], 1)
        self.assertEqual(result["summary"]["matched"], 1)
        self.assertFalse(result["release_approved"])

    def test_all_expected_good_remains_hold(self):
        p, result = run(payload([row(OTHER, "passed")]))
        self.assertEqual(p.returncode, 2)
        self.assertEqual(result["summary"]["changed_outcome"], 0)
        self.assertFalse(result["authorization_verified"])

    def test_missing_test_visible(self):
        _, result = run(payload([row("test_scope_a.Sample.test_missing")]))
        self.assertEqual(result["summary"]["missing"], 1)

    def test_changed_expected_red_to_pass_visible(self):
        _, result = run(payload([row(OTHER, "expected_failure")]))
        self.assertEqual(result["summary"]["changed_outcome"], 1)

    def test_unexpected_success_visible(self):
        log = LOG.replace("... expected failure", "... unexpected success")
        _, result = run(payload(log=log))
        self.assertEqual(result["summary"]["unexpected_success_observed"], 1)

    def test_unowned_claim_not_silently_trusted(self):
        _, result = run(payload([row(owner=None)]))
        self.assertEqual(result["summary"]["unowned_watched"], 1)

    def test_self_asserted_complete_not_ci_proof(self):
        _, result = run(payload(complete=True))
        self.assertEqual(result["summary"]["coverage"], "SELF_ASSERTED_UNVERIFIED")
        self.assertEqual(result["source"], "UNAUTHENTICATED_LOCAL_TEXT")

    def test_incomplete_claim(self):
        _, result = run(payload(complete=False))
        self.assertEqual(result["summary"]["coverage"], "INCOMPLETE")

    def test_duplicate_watch_rejected(self):
        _, result = run(payload([row(), row()]))
        self.assertNotIn("summary", result)

    def test_duplicate_log_method_rejected(self):
        log = LOG.replace("Ran 2 tests", "test_expected_red (" + NAME
                          + ") ... expected failure\nRan 2 tests")
        _, result = run(payload(log=log))
        self.assertNotIn("summary", result)

    def test_missing_suite_summary_fails_closed(self):
        _, result = run(payload(log="test_expected_red (" + NAME + ") ... expected failure"))
        self.assertNotIn("summary", result)

    def test_duplicate_suite_summary_fails_closed(self):
        _, result = run(payload(log=LOG + "Ran 3 tests in 1.0s\nOK\n"))
        self.assertNotIn("summary", result)

    def test_log_expected_red_cannot_exceed_footer(self):
        inconsistent = LOG.replace("OK (expected failures=1)", "OK")
        _, result = run(payload(log=inconsistent))
        self.assertNotIn("summary", result)

    def test_log_unexpected_success_cannot_exceed_footer(self):
        inconsistent = LOG.replace("... expected failure", "... unexpected success")
        _, result = run(payload(log=inconsistent))
        self.assertNotIn("summary", result)

    def test_log_failures_cannot_exceed_footer(self):
        inconsistent = LOG.replace("... expected failure", "... FAIL")
        _, result = run(payload(log=inconsistent))
        self.assertNotIn("summary", result)

    def test_log_distinct_method_total_cannot_exceed_footer(self):
        inconsistent = LOG.replace("Ran 2 tests", "Ran 1 test")
        _, result = run(payload(log=inconsistent))
        self.assertNotIn("summary", result)

    def test_false_issue_rejected(self):
        _, result = run(payload([row(issue=True)]))
        self.assertNotIn("summary", result)

    def test_fraction_owner_rejected(self):
        _, result = run(payload([row(owner=2.1)]))
        self.assertNotIn("summary", result)

    def test_unicode_name_rejected(self):
        _, result = run(payload([row(name="test_scope_a.Sample.test_\u202e")]))
        self.assertNotIn("summary", result)

    def test_nonfinite_constant_rejected(self):
        _, result = run(payload().replace(b"1147", b"NaN"))
        self.assertNotIn("summary", result)

    def test_ambiguous_json_duplicate_keys_rejected(self):
        _, result = run(b'{"schema_version":1,"schema_version":1,"raw_log":"x","watch":[],"complete":true}')
        self.assertNotIn("summary", result)

    def test_escaped_lone_surrogate_log_fails_closed(self):
        # Python json.loads accepts this but UTF-8 cannot encode the character.
        obj = json.loads(payload())
        obj["raw_log"] = chr(0xD800)
        p, result = run(json.dumps(obj).encode())
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, b"")
        self.assertNotIn("summary", result)

    def test_escaped_low_surrogate_log_fails_closed(self):
        obj = json.loads(payload())
        obj["raw_log"] = chr(0xDFFF)
        p, result = run(json.dumps(obj).encode())
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, b"")
        self.assertNotIn("summary", result)

    def test_extra_untrusted_keys_rejected(self):
        obj = json.loads(payload())
        obj["authorized"] = True
        _, result = run(json.dumps(obj).encode())
        self.assertNotIn("summary", result)

    def test_no_raw_token_or_test_name_ever_echoed(self):
        secret = "fictional_secret_marker.invalid"
        p, result = run(payload(log=secret+"\n"+LOG))
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(secret.encode(), p.stdout)
        self.assertNotIn(NAME.encode(), p.stdout)
        self.assertEqual(result["status"], "HOLD")

    def test_oversized_envelope_rejected(self):
        _, result = run(b"x" * (2*1024*1024+1))
        self.assertNotIn("summary", result)

    def test_six_permission_flags_false(self):
        _, result = run(payload())
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved", "scan_allowed"):
            self.assertIs(result[key], False)


if __name__ == "__main__":
    unittest.main()
