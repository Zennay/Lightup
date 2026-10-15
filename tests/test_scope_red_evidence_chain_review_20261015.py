"""Hermetic tests of the expected-RED versus dual-Python roster chain."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "scope_red_evidence_chain_review_20261015.py"
RED = "test_scope_chain.Sample.test_red"
OK = "test_scope_chain.Sample.test_ok"


def record(name=RED, status="expected_failure", owner=1462, issue=1147):
    return {"issue": issue, "test": name, "outcome": status, "owner_pr": owner}


def log(red="expected failure", good="ok", missing=False, suffix=None):
    a = "" if missing else "test_red (" + RED + ") ... " + red + "\n"
    b = "test_ok (" + OK + ") ... " + good + "\n"
    if suffix is None:
        if red == "expected failure":
            suffix = "OK (expected failures=1)"
        elif red == "ok":
            suffix = "OK"
        elif red == "unexpected success":
            suffix = "FAILED (unexpected successes=1)"
        elif red == "FAIL":
            suffix = "FAILED (failures=1)"
        elif red == "ERROR":
            suffix = "FAILED (errors=1)"
        else:
            suffix = "OK (skipped=1)"
    return a + b + "Ran 2 tests in 0.14s\n" + suffix + "\n"


def obj(cases=None, left=None, right=None, complete=True, snapshot_complete=True):
    return {"schema_version": 1, "complete": complete,
            "debt_snapshot": {"schema_version": 1, "complete": snapshot_complete,
                              "cases": ([record(), record(OK, "passed", 1462, 1147)]
                                        if cases is None else cases)},
            "python_311_log": log() if left is None else left,
            "python_314_log": log() if right is None else right}


def raw(**kwargs):
    return json.dumps(obj(**kwargs)).encode()


def call(data):
    proc = subprocess.run([sys.executable, str(PATH)], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return proc, json.loads(proc.stdout)


class DebtEvidenceChainTests(unittest.TestCase):
    def test_normal_matching_expected_red_is_still_hold(self):
        p, r = call(raw())
        s = r["summary"]
        self.assertEqual(p.returncode, 2)
        self.assertEqual(s["paired_expected_red_reported"], 1)
        self.assertEqual(s["watched_missing_311"], 0)
        self.assertEqual(s["classification"], "NO_DISAGREEMENT_REPORTED_NOT_AUTHORITY")
        self.assertEqual(r["status"], "HOLD")

    def test_matching_log_never_attests_source(self):
        _, r = call(raw())
        self.assertEqual(r["summary"]["provenance"], "UNAUTHENTICATED_CALLER_INPUT")
        self.assertFalse(r["release_evidence"])

    def test_two_failing_suites_can_match_but_never_release(self):
        fail = log(red="FAIL")
        _, r = call(raw(cases=[record(status="failed"), record(OK, "passed")],
                        left=fail, right=fail))
        self.assertEqual(r["summary"]["unittest_result_311"], "FAILED")
        self.assertEqual(r["summary"]["classification"], "NO_DISAGREEMENT_REPORTED_NOT_AUTHORITY")
        self.assertFalse(r["scan_allowed"])

    def test_cross_interpreter_watched_mismatch_detected(self):
        _, r = call(raw(right=log(red="ok")))
        self.assertEqual(r["summary"]["watched_cross_python_disagreements"], 1)
        self.assertEqual(r["summary"]["watched_outcome_mismatch_314"], 1)
        self.assertEqual(r["summary"]["classification"], "DISAGREEMENT_IN_UNVERIFIED_EVIDENCE")

    def test_both_changed_from_expected_red_are_not_silently_promoted(self):
        _, r = call(raw(left=log(red="ok"), right=log(red="ok")))
        self.assertEqual(r["summary"]["watched_outcome_mismatch_311"], 1)
        self.assertEqual(r["summary"]["watched_outcome_mismatch_314"], 1)
        self.assertEqual(r["summary"]["paired_expected_red_reported"], 0)

    def test_missing_red_311_detected(self):
        _, r = call(raw(left=log(missing=True)))
        self.assertEqual(r["summary"]["watched_missing_311"], 1)
        self.assertEqual(r["summary"]["watched_missing_314"], 0)
        self.assertEqual(r["summary"]["listing"], "PARTIAL_OR_MISSING")

    def test_missing_red_both_detected(self):
        _, r = call(raw(left=log(missing=True), right=log(missing=True)))
        self.assertEqual(r["summary"]["watched_missing_311"], 1)
        self.assertEqual(r["summary"]["watched_missing_314"], 1)

    def test_unowned_issue_visible_and_never_release(self):
        _, r = call(raw(cases=[record(owner=None), record(OK, "passed")]))
        self.assertEqual(r["summary"]["missing_owner_issues"], 1)
        self.assertEqual(r["status"], "HOLD")

    def test_matching_source_red_is_still_release_blocker(self):
        _, r = call(raw())
        self.assertEqual(r["summary"]["release_blocking_signal"],
                         "UNFIXED_EXPECTED_SOURCE_REDS")

    def test_matching_unexpected_fail_is_blocker_even_if_watched(self):
        fail = log(red="FAIL")
        _, r = call(raw(cases=[record(status="failed"), record(OK, "passed")],
                        left=fail, right=fail))
        self.assertTrue(r["summary"]["reported_suite_failures_present"])
        self.assertEqual(r["summary"]["release_blocking_signal"],
                         "UNEXPECTED_SUITE_FAILURES")

    def test_untracked_expected_red_cannot_hide_in_matching_footers(self):
        extra = "test_other (test_scope_chain.Sample.test_other) ... expected failure\n"
        def augment(text):
            return text.replace("Ran 2 tests", extra+"Ran 3 tests").replace(
                "expected failures=1", "expected failures=2")
        _, r = call(raw(left=augment(log()), right=augment(log())))
        self.assertEqual(r["summary"]["untracked_expected_red_311"], 1)
        self.assertEqual(r["summary"]["untracked_expected_red_314"], 1)
        self.assertEqual(r["summary"]["classification"],
                         "DISAGREEMENT_IN_UNVERIFIED_EVIDENCE")

    def test_untracked_unexpected_failure_cannot_hide_in_matching_footers(self):
        extra = "test_other (test_scope_chain.Sample.test_other) ... FAIL\n"
        def augment(text):
            return text.replace("Ran 2 tests", extra+"Ran 3 tests").replace(
                "OK (expected failures=1)",
                "FAILED (failures=1, expected failures=1)")
        _, r = call(raw(left=augment(log()), right=augment(log())))
        self.assertEqual(r["summary"]["untracked_unexpected_failure_311"], 1)
        self.assertEqual(r["summary"]["untracked_unexpected_failure_314"], 1)
        self.assertEqual(r["summary"]["release_blocking_signal"],
                         "UNEXPECTED_SUITE_FAILURES")

    def test_both_claimed_all_pass_still_non_authorizing(self):
        clean = log(red="ok")
        _, r = call(raw(cases=[record(status="passed"), record(OK, "passed")],
                        left=clean, right=clean))
        self.assertEqual(r["summary"]["release_blocking_signal"],
                         "NO_FAILURE_REPORTED_STILL_NOT_AUTHORITY")
        self.assertEqual(r["status"], "HOLD")
        self.assertFalse(r["permit_issued"])

    def test_owner_boolean_rejected(self):
        _, r = call(raw(cases=[record(owner=True)]))
        self.assertNotIn("summary", r)

    def test_issue_boolean_rejected(self):
        _, r = call(raw(cases=[record(issue=True)]))
        self.assertNotIn("summary", r)

    def test_duplicate_test_in_debt_snapshot_rejected(self):
        _, r = call(raw(cases=[record(), record()]))
        self.assertNotIn("summary", r)

    def test_unknown_expected_outcome_rejected(self):
        _, r = call(raw(cases=[record(status="approved")]))
        self.assertNotIn("summary", r)

    def test_snapshot_incomplete_flag_visible(self):
        _, r = call(raw(snapshot_complete=False))
        self.assertEqual(r["summary"]["coverage"], "INCOMPLETE")

    def test_envelope_incomplete_flag_visible(self):
        _, r = call(raw(complete=False))
        self.assertEqual(r["summary"]["coverage"], "INCOMPLETE")

    def test_two_self_attested_complete_flags_not_proof(self):
        _, r = call(raw())
        self.assertEqual(r["summary"]["coverage"], "SELF_ASSERTED_UNVERIFIED")

    def test_multiple_unittest_summaries_rejected(self):
        _, r = call(raw(left=log() + log()))
        self.assertNotIn("summary", r)

    def test_method_case_duplicate_rejected(self):
        left = log().replace("test_red ("+RED+") ... expected failure\n",
                             ("test_red ("+RED+") ... expected failure\n")*2)
        _, r = call(raw(left=left))
        self.assertNotIn("summary", r)

    def test_expected_failure_method_footer_contradiction_rejected(self):
        _, r = call(raw(left=log(suffix="OK")))
        self.assertNotIn("summary", r)

    def test_status_changed_to_unexpected_success_is_detected(self):
        _, r = call(raw(right=log(red="unexpected success")))
        self.assertEqual(r["summary"]["watched_outcome_mismatch_314"], 1)
        self.assertEqual(r["summary"]["unittest_result_314"], "FAILED")

    def test_status_changed_to_error_is_detected(self):
        _, r = call(raw(right=log(red="ERROR")))
        self.assertEqual(r["summary"]["watched_outcome_mismatch_314"], 1)
        self.assertEqual(r["summary"]["unittest_failures_314"], 0)

    def test_status_changed_to_skip_is_detected(self):
        _, r = call(raw(right=log(red="skipped 'fictional reason'")))
        self.assertEqual(r["summary"]["watched_outcome_mismatch_314"], 1)

    def test_diff_method_names_same_footer_counts_detected(self):
        renamed = log().replace("test_red ("+RED+")",
                                "test_alt (test_scope_chain.Sample.test_alt)")
        _, r = call(raw(right=renamed))
        self.assertEqual(r["summary"]["watched_missing_314"], 1)
        self.assertEqual(r["summary"]["total_different_named_methods"], 2)

    def test_json_duplicate_key_rejected(self):
        _, r = call(b'{"schema_version":1,"schema_version":1}')
        self.assertNotIn("summary", r)

    def test_nonfinite_json_value_rejected(self):
        _, r = call(raw().replace(b'"schema_version": 1', b'"schema_version": NaN'))
        self.assertNotIn("summary", r)

    def test_boolean_schema_version_rejected(self):
        d = obj()
        d["schema_version"] = True
        _, r = call(json.dumps(d).encode())
        self.assertNotIn("summary", r)

    def test_missing_top_level_property_rejected(self):
        d = obj()
        del d["complete"]
        _, r = call(json.dumps(d).encode())
        self.assertNotIn("summary", r)

    def test_extra_top_level_property_rejected(self):
        d = obj()
        d["operator_grant"] = "approved"
        _, r = call(json.dumps(d).encode())
        self.assertNotIn("summary", r)

    def test_lone_surrogate_log_is_opaque(self):
        d = obj()
        d["python_311_log"] = chr(0xD800)
        p, r = call(json.dumps(d).encode())
        self.assertEqual(p.stderr, b"")
        self.assertNotIn("summary", r)

    def test_invalid_utf8_opaque(self):
        p, r = call(b"\xff")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, b"")
        self.assertNotIn("summary", r)

    def test_large_input_is_bounded_and_opaque(self):
        _, r = call(b"x" * (2*1024*1024+131073))
        self.assertNotIn("summary", r)

    def test_no_log_token_or_test_name_echoed(self):
        secret = "do_not_echo_fictional_credential.invalid"
        p, r = call(raw(left=secret+"\n"+log()))
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(secret.encode(), p.stdout)
        self.assertNotIn(RED.encode(), p.stdout)
        self.assertEqual(r["status"], "HOLD")

    def test_every_authority_flag_is_false(self):
        _, r = call(raw())
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved", "scan_allowed"):
            self.assertIs(r[key], False)


if __name__ == "__main__":
    unittest.main()
