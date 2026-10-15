"""Regression coverage: offline scope PR head drift must never free work."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_pr_head_consistency_20261015 import InvalidSnapshot, head_consistency

SHA_A = "1" * 40
SHA_B = "2" * 40
SHA_256 = "a" * 64
FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def fixture():
    return {
        "snapshot": {
            "issues": [
                {"number": 10, "open": True, "lane": "scope-authorization"},
                {"number": 11, "open": True, "lane": "scope-authorization"},
            ],
            "prs": [
                {"number": 20, "open": True, "draft": True,
                 "issues": [10], "paths": ["src/new.py"]},
                {"number": 21, "open": True, "draft": True,
                 "issues": [11], "paths": ["src/old.py"]},
            ],
        },
        "pagination": {
            "issues": [{"page": 1, "numbers": [10, 11], "has_next": False}],
            "prs": [{"page": 1, "numbers": [20, 21], "has_next": False}],
        },
        "pr_file_pages": [
            {"pr": 20, "pages": [{"page": 1, "paths": ["src/new.py"], "has_next": False}]},
            {"pr": 21, "pages": [{"page": 1, "paths": ["src/old.py"], "has_next": False}]},
        ],
        "pr_change_pages": [
            {"pr": 20, "pages": [{"page": 1, "has_next": False,
                                  "changes": [{"filename": "src/new.py",
                                               "status": "renamed",
                                               "previous_filename": "src/old.py"}]}]},
            {"pr": 21, "pages": [{"page": 1, "has_next": False,
                                  "changes": [{"filename": "src/old.py",
                                               "status": "modified",
                                               "previous_filename": None}]}]},
        ],
        "pr_head_receipts": [
            {"pr": 20, "start_head": SHA_A, "file_page_heads": [SHA_A],
             "change_page_heads": [SHA_A], "end_head": SHA_A},
            {"pr": 21, "start_head": SHA_B, "file_page_heads": [SHA_B],
             "change_page_heads": [SHA_B], "end_head": SHA_B},
        ],
    }


def evaluate(doc):
    return head_consistency(json.dumps(doc).encode())


class PinnedHeadConsistencyTests(unittest.TestCase):
    def test_complete_stable_is_self_asserted_only(self):
        result = evaluate(fixture())
        self.assertEqual(result["review_consistency"], "SELF_ASSERTED_STABLE_UNVERIFIED")
        self.assertFalse(result["source_provenance_verified"])
        self.assertFalse(result["worker_activity_verified"])

    def test_all_permissions_always_false(self):
        result = evaluate(fixture())
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(all(result[x] is False for x in FLAGS))
        self.assertTrue(result["candidate_list_suppressed"])
        self.assertEqual(result["unclaimed_candidates_not_permission"], [])

    def test_conflict_report_is_preserved_for_stable_heads(self):
        result = evaluate(fixture())
        self.assertEqual(result["observed_conflict_groups"][0]["prs"], [20, 21])

    def test_head_change_after_files_suppresses_conflicts(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["end_head"] = SHA_B
        result = evaluate(doc)
        self.assertEqual(result["review_consistency"], "UNSTABLE_OR_INCOMPLETE")
        self.assertEqual(result["observed_conflict_groups"], [])
        self.assertTrue(result["conflicts_suppressed_for_mixed_heads"])

    def test_files_from_stale_head_suppress(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["file_page_heads"][0] = SHA_B
        result = evaluate(doc)
        self.assertEqual(result["pr_head_states"][0]["head_state"],
                         "HEAD_CHANGED_OR_MIXED_VERSIONS")
        self.assertEqual(result["observed_conflict_groups"], [])

    def test_change_pages_from_stale_head_suppress(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["change_page_heads"][0] = SHA_B
        self.assertEqual(evaluate(doc)["observed_conflict_groups"], [])

    def test_mismatched_start_end_is_hold_not_invalid(self):
        doc = fixture()
        doc["pr_head_receipts"][1]["start_head"] = SHA_A
        result = evaluate(doc)
        self.assertEqual(result["pr_head_states"][1]["head_state"],
                         "HEAD_CHANGED_OR_MIXED_VERSIONS")

    def test_missing_pr_receipt_suppresses(self):
        doc = fixture()
        doc["pr_head_receipts"].pop()
        result = evaluate(doc)
        self.assertEqual(result["pr_head_states"][-1]["head_state"], "MISSING_HEAD_EVIDENCE")
        self.assertTrue(result["conflicts_suppressed_for_mixed_heads"])

    def test_mismatched_per_page_receipt_count_suppresses(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["file_page_heads"] = []
        result = evaluate(doc)
        self.assertEqual(result["pr_head_states"][0]["head_state"],
                         "INCOMPLETE_HEAD_PAGE_EVIDENCE")

    def test_missing_change_page_evidence_suppresses(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["change_page_heads"] = []
        self.assertTrue(evaluate(doc)["conflicts_suppressed_for_mixed_heads"])

    def test_unpaged_base_suppresses(self):
        doc = fixture()
        doc["pagination"]["prs"][0]["has_next"] = True
        self.assertEqual(evaluate(doc)["review_consistency"], "UNSTABLE_OR_INCOMPLETE")

    def test_sha_256_syntactically_supported_but_not_authority(self):
        doc = fixture()
        for r in doc["pr_head_receipts"]:
            r["start_head"] = SHA_256
            r["end_head"] = SHA_256
            r["file_page_heads"] = [SHA_256]
            r["change_page_heads"] = [SHA_256]
        self.assertFalse(evaluate(doc)["can_merge"])

    def test_uppercase_sha_denied(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["start_head"] = "A" * 40
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_all_zero_sha_denied(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["end_head"] = "0" * 40
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_short_and_overlong_shas_denied(self):
        for val in ("1" * 39, "1" * 41, "x" * 40, "a" * 65, ""):
            with self.subTest(val=val[:8]):
                doc = fixture()
                doc["pr_head_receipts"][0]["start_head"] = val
                with self.assertRaises(InvalidSnapshot):
                    evaluate(doc)

    def test_duplicate_head_receipt_denied(self):
        doc = fixture()
        doc["pr_head_receipts"].append(deepcopy(doc["pr_head_receipts"][0]))
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_unknown_pr_head_receipt_denied(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["pr"] = 999
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_boolean_pr_head_number_denied(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["pr"] = True
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_extra_fields_denied(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["release_approved"] = True
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_duplicate_json_key_denied(self):
        with self.assertRaises(InvalidSnapshot):
            head_consistency(b'{"snapshot":{},"snapshot":{}}')

    def test_cli_valid_is_always_hold(self):
        script = ROOT / "scripts" / "scope_issue_pr_head_consistency_20261015.py"
        proc = subprocess.run([sys.executable, str(script)],
                              input=json.dumps(fixture()).encode(), capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 2)
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["can_release"])

    def test_cli_invalid_redacts_input(self):
        script = ROOT / "scripts" / "scope_issue_pr_head_consistency_20261015.py"
        proc = subprocess.run([sys.executable, str(script)],
                              input=b'{"fake_client_secret":"ABC123"}',
                              capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(b"ABC123", proc.stdout)
        self.assertIn(b'"status":"HOLD"', proc.stdout)
        self.assertNotIn(b"Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
