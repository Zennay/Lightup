"""Real CLI subprocess coverage of transition review: always HOLD, no leaks."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "scope_xfail_transition_review_20261015.py"


def row(outcome, issue=1147, name="test_source", owner=1462):
    return {"outcome": outcome, "issue": issue, "test": name, "owner_pr": owner}


def snap(rows, complete=True):
    return {"schema_version": 1, "complete": complete, "cases": rows}


def payload(before=None, after=None):
    return json.dumps({
        "schema_version": 1,
        "baseline": snap([row("expected_failure")] if before is None else before),
        "current": snap([row("passed")] if after is None else after),
    }).encode()


def run(data):
    p = subprocess.run([sys.executable, str(PATH)], input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=10, check=False)
    return p, json.loads(p.stdout)


class TransitionDebtTests(unittest.TestCase):
    def test_red_to_pass_requires_review(self):
        p, result = run(payload())
        self.assertEqual(p.returncode, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["summary"]["red_to_pass_review_required"], 1)

    def test_test_disappearance_is_visible(self):
        _, result = run(payload(after=[row("passed", name="different")]))
        self.assertEqual(result["summary"]["missing_tests"], 1)
        self.assertEqual(result["summary"]["new_tests"], 1)

    def test_expected_red_still_present(self):
        _, result = run(payload(after=[row("expected_failure")]))
        self.assertEqual(result["summary"]["red_still_red"], 1)

    def test_pass_regression_to_expected_red(self):
        _, result = run(payload(before=[row("passed")], after=[row("expected_failure")]))
        self.assertEqual(result["summary"]["passed_to_red"], 1)

    def test_unexpected_success_not_accepted(self):
        _, result = run(payload(after=[row("unexpected_success")]))
        self.assertEqual(result["summary"]["unexpected_success_current"], 1)
        self.assertFalse(result["release_evidence"])

    def test_owner_transfer_detected(self):
        _, result = run(payload(after=[row("passed", owner=999)]))
        self.assertEqual(result["summary"]["ownership_changed"], 1)

    def test_multiple_issues_unique_identity(self):
        _, result = run(payload(before=[row("expected_failure"), row("expected_failure", issue=301)],
                                after=[row("passed"), row("expected_failure", issue=301)]))
        self.assertEqual(result["summary"]["red_to_pass_review_required"], 1)
        self.assertEqual(result["summary"]["red_still_red"], 1)

    def test_unverified_completeness_never_auth(self):
        _, result = run(payload())
        self.assertEqual(result["summary"]["coverage"], "SELF_ASSERTED_UNVERIFIED")
        self.assertFalse(result["authorization_verified"])
        self.assertFalse(result["scan_allowed"])

    def test_incomplete_snapshot(self):
        obj = json.loads(payload())
        obj["baseline"]["complete"] = False
        _, result = run(json.dumps(obj).encode())
        self.assertEqual(result["summary"]["coverage"], "INCOMPLETE")

    def test_duplicate_json_key_opaque_hold(self):
        p, result = run(b'{"schema_version":1,"schema_version":1,"baseline":{},"current":{}}')
        self.assertEqual(p.returncode, 2)
        self.assertNotIn("summary", result)

    def test_duplicate_case_opaque_hold(self):
        obj = json.loads(payload())
        obj["current"]["cases"].append(obj["current"]["cases"][0])
        _, result = run(json.dumps(obj).encode())
        self.assertNotIn("summary", result)

    def test_nonfinite_value_opaque_hold(self):
        _, result = run(payload().replace(b"1147", b"Infinity"))
        self.assertNotIn("summary", result)

    def test_extra_field_opaque_hold(self):
        obj = json.loads(payload())
        obj["operator_permission"] = True
        _, result = run(json.dumps(obj).encode())
        self.assertNotIn("summary", result)

    def test_no_echo_fake_secret(self):
        p, result = run(b'{"untrusted_target":"secret.invalid"}')
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(b"secret.invalid", p.stdout)
        self.assertNotIn("summary", result)

    def test_oversized_input_opaque_hold(self):
        p, result = run(b"a" * 65537)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn("summary", result)

    def test_invalid_bool_schema_version(self):
        obj = json.loads(payload())
        obj["schema_version"] = True
        _, result = run(json.dumps(obj).encode())
        self.assertNotIn("summary", result)

    def test_every_flag_false_even_on_valid_diff(self):
        _, result = run(payload())
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved", "scan_allowed"):
            self.assertIs(result[key], False)


if __name__ == "__main__":
    unittest.main()
