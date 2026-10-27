"""Strict PR-file completeness without granting scope or work ownership."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_file_coverage_20261015 import InvalidSnapshot, file_coverage

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def receipt():
    return {
        "snapshot": {
            "issues": [{"number": 101, "open": True, "lane": "scope-authorization"},
                       {"number": 102, "open": True, "lane": "scope-authorization"}],
            "prs": [{"number": 201, "open": True, "draft": True,
                     "issues": [101], "paths": ["tests/a.py", "docs/a.md"]},
                    {"number": 202, "open": True, "draft": True,
                     "issues": [101], "paths": ["tests/a.py"]}],
        },
        "pagination": {
            "issues": [{"page": 1, "numbers": [101, 102], "has_next": False}],
            "prs": [{"page": 1, "numbers": [201, 202], "has_next": False}],
        },
        "pr_file_pages": [
            {"pr": 201, "pages": [{"page": 1, "paths": ["tests/a.py"],
                                  "has_next": True},
                                 {"page": 2, "paths": ["docs/a.md"],
                                  "has_next": False}]},
            {"pr": 202, "pages": [{"page": 1, "paths": ["tests/a.py"],
                                  "has_next": False}]},
        ],
    }


def evaluate(document):
    return file_coverage(json.dumps(document).encode())


class FilePagingCoverageTests(unittest.TestCase):
    def test_exact_complete_self_assertion_is_not_authority(self):
        result = evaluate(receipt())
        self.assertTrue(result["all_pages_self_asserted_complete"])
        self.assertEqual(result["file_collision_assessment"], "OBSERVED_ONLY_UNVERIFIED")
        self.assertFalse(result["source_provenance_verified"])
        self.assertFalse(result["worker_activity_verified"])
        self.assertEqual(result["status"], "HOLD")

    def test_every_permission_flag_remains_false(self):
        result = evaluate(receipt())
        self.assertTrue(all(result[flag] is False for flag in FLAGS))

    def test_cross_pr_collision_still_visible(self):
        result = evaluate(receipt())
        self.assertEqual(result["observed_review_groups"][0]["prs"], [201, 202])

    def test_self_asserted_complete_candidates_never_become_free(self):
        result = evaluate(receipt())
        self.assertEqual(result["unclaimed_candidates_not_permission"], [102])
        self.assertFalse(result["worker_activity_verified"])

    def test_missing_pr_files_suppress_candidates(self):
        document = receipt()
        document["pr_file_pages"].pop()
        result = evaluate(document)
        self.assertEqual(result["unclaimed_candidates_not_permission"], [])
        self.assertTrue(result["candidate_list_suppressed"])
        self.assertEqual(result["file_collision_assessment"], "INCOMPLETE_NOT_EXHAUSTIVE")
        self.assertEqual(result["pr_file_coverage"][-1]["coverage"], "MISSING_PR_FILE_EVIDENCE")

    def test_incomplete_last_file_page_suppresses_candidates(self):
        document = receipt()
        document["pr_file_pages"][1]["pages"][0]["has_next"] = True
        self.assertTrue(evaluate(document)["candidate_list_suppressed"])

    def test_incomplete_issue_page_also_suppresses_candidates(self):
        document = receipt()
        document["pagination"]["issues"][0]["has_next"] = True
        self.assertTrue(evaluate(document)["candidate_list_suppressed"])

    def test_mismatched_file_is_rejected(self):
        document = receipt()
        document["pr_file_pages"][1]["pages"][0]["paths"] = ["tests/other.py"]
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_missing_one_file_is_rejected(self):
        document = receipt()
        document["pr_file_pages"][0]["pages"].pop()
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_extra_file_is_rejected(self):
        document = receipt()
        document["pr_file_pages"][1]["pages"][0]["paths"].append("docs/unknown.md")
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_closed_pr_file_export_denied(self):
        document = receipt()
        document["snapshot"]["prs"][1]["open"] = False
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_duplicate_pr_file_receipt_denied(self):
        document = receipt()
        document["pr_file_pages"].append(document["pr_file_pages"][0].copy())
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_duplicate_file_across_pages_denied(self):
        document = receipt()
        document["pr_file_pages"][0]["pages"][1]["paths"].append("tests/a.py")
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_nonconsecutive_file_page_denied(self):
        document = receipt()
        document["pr_file_pages"][0]["pages"][1]["page"] = 3
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_bogus_has_next_string_denied(self):
        document = receipt()
        document["pr_file_pages"][0]["pages"][1]["has_next"] = "false"
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_early_stop_marker_denied(self):
        document = receipt()
        document["pr_file_pages"][0]["pages"][0]["has_next"] = False
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_bidi_path_denied(self):
        document = receipt()
        document["snapshot"]["prs"][0]["paths"][0] = "tests/a\u202e.py"
        document["pr_file_pages"][0]["pages"][0]["paths"][0] = "tests/a\u202e.py"
        with self.assertRaises(InvalidSnapshot):
            evaluate(document)

    def test_invalid_structure_remains_private(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_file_coverage_20261015.py")]
        p = subprocess.run(cmd, input=b'{"secret":"a-fake-customer"}',
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"a-fake-customer", p.stdout)
        self.assertTrue(json.loads(p.stdout)["candidate_list_suppressed"])

    def test_valid_cli_remains_hold(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_file_coverage_20261015.py")]
        p = subprocess.run(cmd, input=json.dumps(receipt()).encode(),
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        out = json.loads(p.stdout)
        self.assertEqual(out["status"], "HOLD")
        self.assertFalse(out["can_release"])


if __name__ == "__main__":
    unittest.main()
