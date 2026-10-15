"""GitHub old/new filename footprint contract, strictly offline and HOLD-only."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_rename_footprints_20261015 import InvalidSnapshot, rename_footprints

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def fixture():
    return {
        "snapshot": {"issues": [
            {"number": 101, "open": True, "lane": "scope-authorization"},
            {"number": 102, "open": True, "lane": "scope-authorization"}],
            "prs": [
                {"number": 201, "open": True, "draft": True,
                 "issues": [101], "paths": ["src/new.py"]},
                {"number": 202, "open": True, "draft": True,
                 "issues": [102], "paths": ["src/old.py"]}]},
        "pagination": {
            "issues": [{"page": 1, "numbers": [101, 102], "has_next": False}],
            "prs": [{"page": 1, "numbers": [201, 202], "has_next": False}]},
        "pr_file_pages": [
            {"pr": 201, "pages": [{"page": 1, "paths": ["src/new.py"], "has_next": False}]},
            {"pr": 202, "pages": [{"page": 1, "paths": ["src/old.py"], "has_next": False}]}],
        "pr_change_pages": [
            {"pr": 201, "pages": [{"page": 1, "has_next": False, "changes": [
                {"filename": "src/new.py", "status": "renamed", "previous_filename": "src/old.py"}]}]},
            {"pr": 202, "pages": [{"page": 1, "has_next": False, "changes": [
                {"filename": "src/old.py", "status": "modified", "previous_filename": None}]}]}]}


def evaluate(document):
    return rename_footprints(json.dumps(document).encode())


class RenameFootprintTests(unittest.TestCase):
    def test_rename_source_conflicts_with_other_pr(self):
        result = evaluate(fixture())
        self.assertEqual(result["observed_path_collisions"], [{"path": "src/old.py", "prs": [201, 202]}])

    def test_previous_path_joins_group(self):
        result = evaluate(fixture())
        self.assertEqual(result["observed_conflict_groups"][0]["prs"], [201, 202])
        self.assertEqual(result["observed_conflict_groups"][0]["review_priority"], "PATH")

    def test_canonical_present_but_never_release(self):
        result = evaluate(fixture())
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["file_change_coverage"], "SELF_ASSERTED_COMPLETE_UNVERIFIED")
        self.assertTrue(all(result[flag] is False for flag in FLAGS))
        self.assertTrue(result["candidate_list_suppressed"])

    def test_no_rename_has_no_path_conflict(self):
        d = fixture()
        d["pr_change_pages"][0]["pages"][0]["changes"][0] = {
            "filename": "src/new.py", "status": "modified", "previous_filename": None}
        self.assertEqual(evaluate(d)["observed_path_collisions"], [])
        self.assertTrue(evaluate(d)["no_conflicts_does_not_mean_free"])

    def test_duplicate_issue_still_conflicts(self):
        d = fixture()
        d["snapshot"]["prs"][1]["issues"] = [101]
        result = evaluate(d)
        self.assertEqual(result["observed_conflict_groups"][0]["duplicate_issues"], [101])

    def test_changed_new_path_must_match_original(self):
        d = fixture()
        d["pr_change_pages"][0]["pages"][0]["changes"][0]["filename"] = "src/misreported.py"
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_absent_previous_filename_rejected(self):
        d = fixture()
        d["pr_change_pages"][0]["pages"][0]["changes"][0]["previous_filename"] = None
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_same_name_rename_rejected(self):
        d = fixture()
        d["pr_change_pages"][0]["pages"][0]["changes"][0]["previous_filename"] = "src/new.py"
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_unexpected_previous_filename_rejected(self):
        d = fixture()
        d["pr_change_pages"][1]["pages"][0]["changes"][0]["previous_filename"] = "src/extra.py"
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_bad_status_rejected(self):
        d = fixture()
        d["pr_change_pages"][1]["pages"][0]["changes"][0]["status"] = "unknown"
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_malformed_bidi_previous_name_rejected(self):
        d = fixture()
        d["pr_change_pages"][0]["pages"][0]["changes"][0]["previous_filename"] = "src/ol\u202ed.py"
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_missing_one_pr_file_change_export_suppresses(self):
        d = fixture()
        d["pr_change_pages"].pop()
        result = evaluate(d)
        self.assertEqual(result["file_change_coverage"], "INCOMPLETE_NOT_EXHAUSTIVE")
        self.assertEqual(result["unclaimed_candidates_not_permission"], [])

    def test_last_has_next_true_suppresses(self):
        d = fixture()
        d["pr_change_pages"][1]["pages"][0]["has_next"] = True
        self.assertEqual(evaluate(d)["file_change_coverage"], "INCOMPLETE_NOT_EXHAUSTIVE")

    def test_duplicate_change_receipt_rejected(self):
        d = fixture()
        d["pr_change_pages"].append(d["pr_change_pages"][0].copy())
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_duplicate_filename_rejected(self):
        d = fixture()
        d["pr_change_pages"][0]["pages"][0]["changes"].append(
            d["pr_change_pages"][0]["pages"][0]["changes"][0].copy())
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_file_coverage_mismatch_rejected(self):
        d = fixture()
        d["pr_file_pages"][0]["pages"][0]["paths"] = ["src/hidden.py"]
        with self.assertRaises(InvalidSnapshot):
            evaluate(d)

    def test_cli_invalid_does_not_leak(self):
        script = ROOT / "scripts" / "scope_issue_rename_footprints_20261015.py"
        p = subprocess.run([sys.executable, str(script)], input=b'{"secret":"fictional-private-target"}',
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"fictional-private-target", p.stdout)
        self.assertEqual(json.loads(p.stdout)["status"], "HOLD")
        self.assertNotIn(b"Traceback", p.stderr)

    def test_cli_valid_never_green(self):
        script = ROOT / "scripts" / "scope_issue_rename_footprints_20261015.py"
        p = subprocess.run([sys.executable, str(script)], input=json.dumps(fixture()).encode(),
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(json.loads(p.stdout)["observed_path_collisions"][0]["path"], "src/old.py")


if __name__ == "__main__":
    unittest.main()
