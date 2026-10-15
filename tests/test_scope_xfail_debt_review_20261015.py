"""Hermetic negative/positive controls for HOLD-only expected-RED debt reviewer."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "scope_xfail_debt_review_20261015.py"
spec = importlib.util.spec_from_file_location("scope_xfail_debt_review", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def entry(outcome="expected_failure", name="test_source_red", issue=1147, owner=1462):
    return {"issue": issue, "test": name, "outcome": outcome, "owner_pr": owner}


def raw(cases=None, complete=True):
    return json.dumps({"schema_version": 1, "complete": complete,
                       "cases": cases if cases is not None else [entry()]}).encode()


class DebtReviewTests(unittest.TestCase):
    def test_expected_red_is_not_green(self):
        r = mod.receipt(mod.review(raw()))
        self.assertEqual(r["status"], "HOLD")
        self.assertEqual(r["summary"]["expected_red"], 1)
        self.assertFalse(r["release_approved"])
        self.assertFalse(r["execution_enabled"])

    def test_all_pass_cannot_authorize(self):
        r = mod.receipt(mod.review(raw([entry("passed")])))
        self.assertEqual(r["classification"], "NO_RED_REPORTED_NOT_AUTHORITY")
        self.assertFalse(r["release_evidence"])

    def test_unexpected_success_is_not_fixed_proof(self):
        r = mod.receipt(mod.review(raw([entry("unexpected_success")])))
        self.assertEqual(r["summary"]["unexpected_success"], 1)
        self.assertEqual(r["classification"], "SOURCE_RED_OR_FAILURES_PRESENT")

    def test_all_states_counted(self):
        cases = [entry(o, "test_"+o) for o in sorted(mod.OUTCOMES)]
        s = mod.review(raw(cases))
        self.assertEqual(s["cases"], 6)
        self.assertEqual(s["other_nonpassing"], 3)
        self.assertEqual(s["ordinary_pass"], 1)

    def test_incomplete_is_explicit(self):
        self.assertEqual(mod.review(raw(complete=False))["coverage"], "INCOMPLETE")

    def test_self_asserted_complete_is_never_verified(self):
        self.assertEqual(mod.review(raw())["coverage"], "SELF_ASSERTED_UNVERIFIED")

    def test_missing_owner_counted(self):
        s = mod.review(raw([entry(owner=None)]))
        self.assertEqual(s["unowned_issues"], 1)

    def test_same_name_other_issue_separate(self):
        s = mod.review(raw([entry(), entry(issue=301)]))
        self.assertEqual((s["cases"], s["issues"]), (2, 2))

    def test_duplicate_entry_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw([entry(), entry()]))

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(b'{"schema_version":1,"schema_version":1,"complete":true,"cases":[]}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw().replace(b'1147', b'NaN'))

    def test_bool_issue_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw([entry(issue=True)]))

    def test_float_owner_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw([entry(owner=1462.0)]))

    def test_extra_untrusted_field_rejected(self):
        snapshot = json.loads(raw())
        snapshot["authority"] = True
        with self.assertRaises(mod.SnapshotError):
            mod.review(json.dumps(snapshot).encode())

    def test_unicode_test_name_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw([entry(name="test_\u202E")]))
        
    def test_empty_list_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw([]))

    def test_oversized_list_rejected(self):
        cases = [entry(name="test_%04d" % i) for i in range(513)]
        with self.assertRaises(mod.SnapshotError):
            mod.review(raw(cases))

    def test_oversized_bytes_rejected(self):
        with self.assertRaises(mod.SnapshotError):
            mod.review(b"x" * (mod.MAX_BYTES+1))

    def test_no_input_echo_on_rejected(self):
        p = subprocess.run([sys.executable, str(PATH)], input=b'{"target":"secret.invalid"}',
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, b"")
        self.assertNotIn(b"secret.invalid", p.stdout)
        self.assertEqual(json.loads(p.stdout)["status"], "HOLD")

    def test_valid_cli_never_returns_success(self):
        p = subprocess.run([sys.executable, str(PATH)], input=raw(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(p.returncode, 2)
        r = json.loads(p.stdout)
        self.assertEqual(r["status"], "HOLD")
        self.assertTrue(all(r[key] is False for key in mod.RECEIPT_FALSE))


if __name__ == "__main__":
    unittest.main()
