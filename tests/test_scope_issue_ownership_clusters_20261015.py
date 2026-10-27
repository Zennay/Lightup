"""Evidence-only transitive PR conflict grouping; never reserve or claim issues."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_ownership_audit_20261015 import InvalidSnapshot, audit
from scope_issue_ownership_clusters_20261015 import conflict_groups

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def fixture():
    return {
        "issues": [{"number": n, "open": True, "lane": "scope-authorization"}
                   for n in (101, 102, 103, 104)],
        "prs": [
            {"number": 201, "open": True, "draft": True, "issues": [101],
             "paths": ["tests/a.py"]},
            {"number": 202, "open": True, "draft": True, "issues": [101],
             "paths": ["tests/b.py"]},
            {"number": 203, "open": True, "draft": True, "issues": [102],
             "paths": ["tests/b.py"]},
            {"number": 204, "open": True, "draft": True, "issues": [103],
             "paths": ["tests/c.py"]},
        ],
    }


def evaluate(doc):
    return conflict_groups(audit(json.dumps(doc).encode("utf-8")))


class ConflictGroupTests(unittest.TestCase):
    def test_transitive_edges_form_one_group(self):
        result = evaluate(fixture())
        self.assertEqual(result["group_count"], 1)
        self.assertEqual(result["review_groups"][0]["prs"], [201, 202, 203])

    def test_mixed_issue_and_file_causes_are_visible(self):
        group = evaluate(fixture())["review_groups"][0]
        self.assertEqual(group["duplicate_issues"], [101])
        self.assertEqual(group["colliding_paths"], ["tests/b.py"])
        self.assertEqual(group["review_priority"], "PATH_AND_ISSUE")

    def test_no_claim_means_unknown_not_available(self):
        result = evaluate(fixture())
        self.assertEqual(result["unclaimed_candidates_not_permission"], [104])
        self.assertTrue(result["unknown_worker_activity"])
        self.assertTrue(result["no_conflict_does_not_mean_available"])
        self.assertEqual(result["source_coverage"], "UNVERIFIED_UNTRUSTED_SNAPSHOT")

    def test_all_safety_flags_false(self):
        result = evaluate(fixture())
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(all(result[flag] is False for flag in FLAGS))

    def test_closed_pr_is_excluded(self):
        doc = fixture()
        doc["prs"][1]["open"] = False
        self.assertEqual(evaluate(doc)["group_count"], 0)

    def test_empty_is_still_unknown_not_green(self):
        result = evaluate({"issues": [], "prs": []})
        self.assertEqual(result["group_count"], 0)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["unknown_worker_activity"])

    def test_file_only_conflict(self):
        doc = fixture()
        doc["prs"][1]["issues"] = []
        group = evaluate(doc)["review_groups"][0]
        self.assertEqual(group["review_priority"], "PATH")
        self.assertEqual(group["prs"], [202, 203])

    def test_issue_only_conflict(self):
        doc = fixture()
        doc["prs"][2]["paths"] = ["tests/unique.py"]
        group = evaluate(doc)["review_groups"][0]
        self.assertEqual(group["review_priority"], "ISSUE")
        self.assertEqual(group["prs"], [201, 202])

    def test_two_independent_groups(self):
        doc = fixture()
        doc["prs"].append({"number": 205, "open": True, "draft": True,
                           "issues": [103], "paths": ["tests/d.py"]})
        result = evaluate(doc)
        self.assertEqual([g["prs"] for g in result["review_groups"]],
                         [[201, 202, 203], [204, 205]])

    def test_order_independent(self):
        original = evaluate(fixture())
        doc = fixture()
        doc["prs"].reverse()
        doc["issues"].reverse()
        self.assertEqual(evaluate(doc), original)

    def test_reject_forged_green_results(self):
        valid = audit(json.dumps(fixture()).encode())
        for flag in FLAGS:
            bad = dict(valid)
            bad[flag] = True
            with self.subTest(flag=flag):
                with self.assertRaises(InvalidSnapshot):
                    conflict_groups(bad)

    def test_reject_forged_status(self):
        valid = audit(json.dumps(fixture()).encode())
        valid["status"] = "READY"
        with self.assertRaises(InvalidSnapshot):
            conflict_groups(valid)

    def test_cli_valid_remains_hold(self):
        script = ROOT / "scripts" / "scope_issue_ownership_clusters_20261015.py"
        process = subprocess.run([sys.executable, str(script)],
                                 input=json.dumps(fixture()).encode("utf-8"),
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        value = json.loads(process.stdout)
        self.assertEqual(value["group_count"], 1)
        self.assertFalse(value["can_release"])
        self.assertNotIn(b"Traceback", process.stderr)

    def test_cli_invalid_redacts_all_details(self):
        script = ROOT / "scripts" / "scope_issue_ownership_clusters_20261015.py"
        process = subprocess.run([sys.executable, str(script)], input=b'{"secret":"CLIENT-ABC"}',
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn(b"CLIENT-ABC", process.stdout)
        self.assertEqual(json.loads(process.stdout)["source_coverage"], "INVALID_OR_UNTRUSTED")

    def test_cli_duplicate_key_never_becomes_available(self):
        script = ROOT / "scripts" / "scope_issue_ownership_clusters_20261015.py"
        raw = b'{"issues":[],"issues":[],"prs":[]}'
        process = subprocess.run([sys.executable, str(script)], input=raw,
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stdout)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
