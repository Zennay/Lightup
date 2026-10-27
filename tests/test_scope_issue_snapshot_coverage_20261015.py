"""Paged offline GitHub ownership receipts never establish authorization."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_snapshot_coverage_20261015 import InvalidSnapshot, witness

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def receipt():
    return {"snapshot": {
        "issues": [
            {"number": 12, "open": True, "lane": "scope-authorization"},
            {"number": 13, "open": True, "lane": "scope-authorization"}],
        "prs": [
            {"number": 20, "open": True, "draft": True,
             "issues": [12], "paths": ["tests/a.py"]},
            {"number": 21, "open": True, "draft": True,
             "issues": [12], "paths": ["tests/a.py"]}]},
        "pagination": {
            "issues": [{"page": 1, "numbers": [12, 13], "has_next": False}],
            "prs": [{"page": 1, "numbers": [20, 21], "has_next": False}]}
    }


def evaluate(x):
    return witness(json.dumps(x).encode())


class PaginationCoverageTests(unittest.TestCase):
    def test_self_asserted_complete_is_still_unverified(self):
        r = evaluate(receipt())
        self.assertTrue(r["all_pages_self_asserted_complete"])
        self.assertFalse(r["source_provenance_verified"])
        self.assertFalse(r["worker_activity_verified"])
        self.assertEqual(r["status"], "HOLD")

    def test_duplicate_ownership_conflicts_remain_visible(self):
        r = evaluate(receipt())
        self.assertEqual(r["group_count"], 1)
        self.assertEqual(r["review_groups"][0]["prs"], [20, 21])

    def test_self_asserted_complete_does_not_grant_free_issue(self):
        r = evaluate(receipt())
        self.assertEqual(r["unclaimed_candidates_not_permission"], [13])
        self.assertFalse(any(r[flag] for flag in FLAGS))

    def test_incomplete_pr_pagination_suppresses_candidates(self):
        x = receipt()
        x["pagination"]["prs"][0]["has_next"] = True
        r = evaluate(x)
        self.assertTrue(r["candidate_list_suppressed"])
        self.assertEqual(r["unclaimed_candidates_not_permission"], [])
        self.assertEqual(r["pagination"]["prs"], "INCOMPLETE_MORE_PAGES")
        self.assertEqual(r["group_count"], 1)

    def test_incomplete_issue_pagination_suppresses_candidates(self):
        x = receipt()
        x["pagination"]["issues"][0]["has_next"] = True
        self.assertEqual(evaluate(x)["unclaimed_candidates_not_permission"], [])

    def test_consecutive_pages_can_be_self_asserted_complete(self):
        x = receipt()
        x["pagination"]["issues"] = [
            {"page": 1, "numbers": [12], "has_next": True},
            {"page": 2, "numbers": [13], "has_next": False}]
        self.assertEqual(evaluate(x)["pagination"]["issues"], "SELF_ASSERTED_COMPLETE_UNVERIFIED")

    def test_page_gap_denied(self):
        x = receipt()
        x["pagination"]["issues"][0]["page"] = 2
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_intermediate_false_marker_denied(self):
        x = receipt()
        x["pagination"]["issues"] = [
            {"page": 1, "numbers": [12], "has_next": False},
            {"page": 2, "numbers": [13], "has_next": False}]
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_page_contents_must_match_snapshot(self):
        x = receipt()
        x["pagination"]["prs"][0]["numbers"] = [20]
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_duplicate_identity_across_pages_denied(self):
        x = receipt()
        x["pagination"]["issues"] = [
            {"page": 1, "numbers": [12], "has_next": True},
            {"page": 2, "numbers": [12, 13], "has_next": False}]
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_boolean_issue_number_denied(self):
        x = receipt()
        x["pagination"]["issues"][0]["numbers"] = [True, 13]
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_bool_page_index_denied(self):
        x = receipt()
        x["pagination"]["prs"][0]["page"] = True
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_str_has_next_denied(self):
        x = receipt()
        x["pagination"]["prs"][0]["has_next"] = "false"
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_missing_pr_page_denied(self):
        x = receipt()
        x["pagination"]["prs"] = []
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_extra_coverage_claim_denied(self):
        x = receipt()
        x["pagination"]["authenticated"] = True
        with self.assertRaises(InvalidSnapshot):
            evaluate(x)

    def test_duplicate_json_key_denied(self):
        with self.assertRaises(InvalidSnapshot):
            witness(b'{"snapshot":{},"snapshot":{},"pagination":{}}')

    def test_cli_incomplete_returns_hold(self):
        script = ROOT / "scripts" / "scope_issue_snapshot_coverage_20261015.py"
        x = receipt()
        x["pagination"]["prs"][0]["has_next"] = True
        p = subprocess.run([sys.executable, str(script)], input=json.dumps(x).encode(),
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        out = json.loads(p.stdout)
        self.assertEqual(out["status"], "HOLD")
        self.assertEqual(out["unclaimed_candidates_not_permission"], [])

    def test_cli_invalid_redacts_input(self):
        script = ROOT / "scripts" / "scope_issue_snapshot_coverage_20261015.py"
        p = subprocess.run([sys.executable, str(script)], input=b'{"secret":"client-X"}',
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"client-X", p.stdout)
        self.assertTrue(json.loads(p.stdout)["candidate_list_suppressed"])


if __name__ == "__main__":
    unittest.main()
