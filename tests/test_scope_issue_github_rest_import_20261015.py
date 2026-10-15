"""Real-GitHub-record-shaped fixture imports must never confer task ownership."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_github_rest_import_20261015 import InvalidSnapshot, review

SHA_A = "1" * 40
SHA_B = "2" * 40
BASE = "3" * 40
FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def issue(number, state="open"):
    return {"number": number, "state": state, "title": "synthetic issue", "body": "ignored private claim"}


def pr(number, sha, head_repo="Zennay/Lightup"):
    return {
        "number": number, "state": "open", "draft": True,
        "base": {"ref": "main", "sha": BASE, "repo": {"full_name": "Zennay/Lightup"}},
        "head": {"sha": sha, "repo": {"full_name": head_repo}},
        "body": "Claim issue #999 (untrusted! never parsed)",
    }


def fixture():
    return {
        "repository": "Zennay/Lightup",
        "scope_issue_numbers": [101, 102],
        "issue_pages": [{"page": 1, "has_next": False,
                         "records": [issue(101), issue(102)]}],
        "pr_pages": [{"page": 1, "has_next": False,
                      "records": [pr(201, SHA_A), pr(202, SHA_B)]}],
        "claims": [{"pr": 201, "issues": [101]},
                   {"pr": 202, "issues": [102]}],
        "file_pages": [
            {"pr": 201, "page": 1, "has_next": False,
             "records": [{"filename": "src/new.py", "status": "renamed",
                          "previous_filename": "src/old.py", "patch": "@@ synthetic"}]},
            {"pr": 202, "page": 1, "has_next": False,
             "records": [{"filename": "src/old.py", "status": "modified",
                          "additions": 2, "deletions": 1}]},
        ],
    }


def evaluate(doc):
    return review(json.dumps(doc, ensure_ascii=True).encode())


class GitHubRestImportTests(unittest.TestCase):
    def test_imports_real_rest_record_shape(self):
        output = evaluate(fixture())
        self.assertEqual(output["status"], "HOLD")
        self.assertTrue(output["snapshot_complete_self_asserted"])
        self.assertFalse(output["source_provenance_verified"])
        self.assertFalse(output["head_pinning_verified"])

    def test_old_rename_path_collision_is_visible(self):
        output = evaluate(fixture())
        self.assertEqual(output["observed_path_collisions"],
                         [{"path": "src/old.py", "prs": [201, 202]}])
        self.assertEqual(output["conflict_observations"][0]["prs"], [201, 202])

    def test_all_permissions_false_even_for_complete_input(self):
        result = evaluate(fixture())
        self.assertTrue(all(result[k] is False for k in FLAGS))
        self.assertTrue(result["candidate_list_suppressed"])
        self.assertEqual(result["unclaimed_candidates_not_permission"], [])

    def test_body_issue_mentions_never_create_claims(self):
        doc = fixture()
        doc["claims"] = [{"pr": 201, "issues": []},
                         {"pr": 202, "issues": []}]
        result = evaluate(doc)
        self.assertEqual(result["conflict_observations"][0]["duplicate_issues"], [])
        self.assertFalse(result["head_pinning_verified"])

    def test_missing_explicit_claim_decl_is_incomplete(self):
        doc = fixture()
        doc["claims"].pop()
        result = evaluate(doc)
        self.assertFalse(result["snapshot_complete_self_asserted"])
        self.assertEqual(result["missing_claim_declarations"], [202])

    def test_pr_from_fork_requires_review(self):
        doc = fixture()
        doc["pr_pages"][0]["records"][0]["head"]["repo"]["full_name"] = "Other/fork"
        result = evaluate(doc)
        self.assertEqual(result["open_fork_prs_require_review"], [201])
        self.assertFalse(result["can_merge"])

    def test_missing_file_page_is_incomplete(self):
        doc = fixture()
        doc["file_pages"].pop()
        result = evaluate(doc)
        self.assertFalse(result["snapshot_complete_self_asserted"])
        self.assertEqual(result["unclaimed_candidates_not_permission"], [])

    def test_incomplete_pr_pagination_is_flagged(self):
        doc = fixture()
        doc["pr_pages"][0]["has_next"] = True
        self.assertFalse(evaluate(doc)["snapshot_complete_self_asserted"])

    def test_incomplete_file_page_is_flagged(self):
        doc = fixture()
        doc["file_pages"][0]["has_next"] = True
        self.assertFalse(evaluate(doc)["snapshot_complete_self_asserted"])

    def test_both_pages_must_be_sequential(self):
        doc = fixture()
        doc["pr_pages"] = [
            {"page": 1, "has_next": True, "records": [pr(201, SHA_A)]},
            {"page": 3, "has_next": False, "records": [pr(202, SHA_B)]},
        ]
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_pr_duplication_denied(self):
        doc = fixture()
        doc["pr_pages"][0]["records"].append(pr(201, SHA_A))
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_issues_endpoint_cannot_include_pr_pseudorows(self):
        doc = fixture()
        doc["issue_pages"][0]["records"][0]["pull_request"] = {"url": "ignored"}
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_scope_issue_selection_must_exist(self):
        doc = fixture()
        doc["scope_issue_numbers"] = [999]
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_scope_selection_not_implicitly_all_issues(self):
        doc = fixture()
        doc["scope_issue_numbers"] = [101]
        self.assertEqual(evaluate(doc)["status"], "HOLD")

    def test_wrong_base_repo_denied(self):
        doc = fixture()
        doc["pr_pages"][0]["records"][0]["base"]["repo"]["full_name"] = "Other/Repo"
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_wrong_base_ref_denied(self):
        doc = fixture()
        doc["pr_pages"][0]["records"][0]["base"]["ref"] = "release"
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_missing_head_sha_denied(self):
        doc = fixture()
        del doc["pr_pages"][0]["records"][0]["head"]["sha"]
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_rename_without_old_path_denied(self):
        doc = fixture()
        del doc["file_pages"][0]["records"][0]["previous_filename"]
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_duplicate_file_across_page_denied(self):
        doc = fixture()
        doc["file_pages"][0]["records"].append(deepcopy(doc["file_pages"][0]["records"][0]))
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_conflicting_claim_rows_denied(self):
        doc = fixture()
        doc["claims"].append({"pr": 201, "issues": [102]})
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_unknown_pr_claim_denied(self):
        doc = fixture()
        doc["claims"][0]["pr"] = 888
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_bool_pr_number_denied(self):
        doc = fixture()
        doc["file_pages"][0]["pr"] = True
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_malformed_path_denied(self):
        doc = fixture()
        doc["file_pages"][0]["records"][0]["filename"] = "src/../private"
        with self.assertRaises(InvalidSnapshot):
            evaluate(doc)

    def test_duplicate_json_key_denied(self):
        with self.assertRaises(InvalidSnapshot):
            review(b'{"repository":"Zennay/Lightup","repository":"OTHER"}')

    def test_cli_complete_never_grants_or_succeeds(self):
        path = ROOT / "scripts" / "scope_issue_github_rest_import_20261015.py"
        result = subprocess.run([sys.executable, str(path)],
                                input=json.dumps(fixture()).encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        out = json.loads(result.stdout)
        self.assertEqual(out["status"], "HOLD")
        self.assertFalse(out["can_authorize"])

    def test_cli_invalid_redacts_sensitive_export(self):
        path = ROOT / "scripts" / "scope_issue_github_rest_import_20261015.py"
        result = subprocess.run([sys.executable, str(path)],
                                input=b'{"secret":"nonreal-client-key"}',
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"nonreal-client-key", result.stdout)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
