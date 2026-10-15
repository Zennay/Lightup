"""Offline PR-repository identity refuses cross-project ownership authority."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_repo_identity_20261015 import InvalidSnapshot, repo_identity_fence

SHA_A = "1" * 40
SHA_B = "2" * 40
SHA_MAIN = "3" * 40
SHA_OTHER = "4" * 40
FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def fixture():
    ids = [(201, 101, "docs/new.md", SHA_A), (202, 102, "docs/old.md", SHA_B)]
    return {
        "snapshot": {
            "issues": [{"number": i, "open": True, "lane": "scope-authorization"} for _, i, _, _ in ids],
            "prs": [{"number": pr, "open": True, "draft": True, "issues": [issue], "paths": [path]}
                    for pr, issue, path, _ in ids],
        },
        "pagination": {
            "issues": [{"page": 1, "numbers": [101, 102], "has_next": False}],
            "prs": [{"page": 1, "numbers": [201, 202], "has_next": False}],
        },
        "pr_file_pages": [
            {"pr": pr, "pages": [{"page": 1, "paths": [path], "has_next": False}]}
            for pr, _, path, _ in ids],
        "pr_change_pages": [
            {"pr": 201, "pages": [{"page": 1, "has_next": False, "changes": [
                {"filename": "docs/new.md", "status": "renamed",
                 "previous_filename": "docs/old.md"}]}]},
            {"pr": 202, "pages": [{"page": 1, "has_next": False, "changes": [
                {"filename": "docs/old.md", "status": "modified", "previous_filename": None}]}]},
        ],
        "pr_head_receipts": [
            {"pr": pr, "start_head": sha, "file_page_heads": [sha],
             "change_page_heads": [sha], "end_head": sha} for pr, _, _, sha in ids],
        "repository": {"repo": "Zennay/Lightup", "base_ref": "main", "base_sha": SHA_MAIN},
        "pr_repository_observations": [
            {"pr": pr, "base_repo": "Zennay/Lightup", "base_ref": "main",
             "base_sha": SHA_MAIN, "head_repo": "Zennay/Lightup",
             "head_sha": sha} for pr, _, _, sha in ids],
    }


def check(doc):
    return repo_identity_fence(json.dumps(doc).encode("utf-8"))


class RepositoryIdentityTests(unittest.TestCase):
    def test_valid_looking_repo_receipt_still_unverified(self):
        result = check(fixture())
        self.assertEqual(result["repository_consistency"], "SELF_ASSERTED_MATCH_UNVERIFIED")
        self.assertFalse(result["source_provenance_verified"])
        self.assertFalse(result["worker_activity_verified"])

    def test_all_permission_flags_false(self):
        result = check(fixture())
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(all(result[k] is False for k in FLAGS))
        self.assertTrue(result["candidate_list_suppressed"])

    def test_observed_conflict_remains_if_internally_consistent(self):
        self.assertEqual(check(fixture())["review_groups"][0]["prs"], [201, 202])

    def test_fork_pr_must_not_be_claimed(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["head_repo"] = "other/fork"
        result = check(doc)
        self.assertEqual(result["repository_consistency"], "MIXED_OR_INCOMPLETE")
        self.assertEqual(result["review_groups"], [])
        self.assertEqual(result["pr_repository_states"][0]["state"], "EXTERNAL_SOURCE_REQUIRES_OWNER_REVIEW")

    def test_wrong_base_repo_suppresses(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["base_repo"] = "other/Lightup"
        self.assertTrue(check(doc)["conflicts_suppressed"])

    def test_wrong_pr_base_branch_suppresses(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["base_ref"] = "production"
        self.assertEqual(check(doc)["pr_repository_states"][0]["state"], "WRONG_BASE_REPOSITORY_OR_REF")

    def test_mixed_base_sha_suppresses(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["base_sha"] = SHA_OTHER
        self.assertEqual(check(doc)["pr_repository_states"][0]["state"], "MIXED_BASE_HISTORY")

    def test_mixed_pr_head_sha_suppresses(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["head_sha"] = SHA_OTHER
        self.assertEqual(check(doc)["pr_repository_states"][0]["state"], "HEAD_RECEIPT_MISMATCH")

    def test_missing_pr_identity_suppresses(self):
        doc = fixture()
        doc["pr_repository_observations"].pop()
        result = check(doc)
        self.assertEqual(result["pr_repository_states"][-1]["state"], "MISSING_REPOSITORY_EVIDENCE")
        self.assertEqual(result["review_groups"], [])

    def test_prior_head_drift_suppresses_even_if_repo_matches(self):
        doc = fixture()
        doc["pr_head_receipts"][0]["end_head"] = SHA_OTHER
        self.assertEqual(check(doc)["review_groups"], [])

    def test_duplicate_repo_receipt_denied(self):
        doc = fixture()
        doc["pr_repository_observations"].append(deepcopy(doc["pr_repository_observations"][0]))
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_unknown_pr_denied(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["pr"] = 999
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_boolean_pr_identity_denied(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["pr"] = True
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_root_repository_mismatch_denied(self):
        doc = fixture()
        doc["repository"]["repo"] = "Other/Lightup"
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_wrong_root_base_ref_denied(self):
        doc = fixture()
        doc["repository"]["base_ref"] = "random"
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_zero_root_base_sha_denied(self):
        doc = fixture()
        doc["repository"]["base_sha"] = "0" * 40
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_unexpected_extra_field_denied(self):
        doc = fixture()
        doc["pr_repository_observations"][0]["owner_verified"] = True
        with self.assertRaises(InvalidSnapshot):
            check(doc)

    def test_cli_complete_always_returns_hold(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_repo_identity_20261015.py")]
        result = subprocess.run(cmd, input=json.dumps(fixture()).encode(),
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")

    def test_cli_bad_input_never_leaks_sensitive_metadata(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_repo_identity_20261015.py")]
        result = subprocess.run(cmd, input=b'{"account_key":"DEMO_PRIVATE_ONLY"}',
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"DEMO_PRIVATE_ONLY", result.stdout)
        self.assertIn(b'"status":"HOLD"', result.stdout)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
