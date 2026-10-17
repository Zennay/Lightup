"""Scope #1540: strict explicit file-ownership and protected-path overlay."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "review_scope_worker_ownership_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_owner", TOOL)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

PIN = "d" * 40
REPO = "Example/Lightup"


def _change(status, path, old=None):
    item = {"status": status, "filename": path}
    if old is not None:
        item["previous_filename"] = old
    return item


def _record(worker, num, head, changes):
    ref = "review/" + worker
    return {"worker": worker, "branch": ref,
            "pr": {"number": num, "state": "open", "draft": True,
                   "base_sha": PIN, "head_sha": head,
                   "head_ref": ref, "changed_files": len(changes),
                   "head_repo_full_name": REPO},
            "compare": {"base_sha": PIN, "head_sha": head,
                        "repository_full_name": REPO, "status": "ahead",
                        "ahead_by": 3, "behind_by": 0, "too_large": False,
                        "files": changes}}


def _ownership(worker, head, paths):
    return {"worker": worker, "head_sha": head, "paths": paths}


GOOD = {
    "version": 1, "repository_full_name": REPO, "base_sha": PIN,
    "protected_paths": ["src/lightup/engagements.py", "src/lightup/domain.py"],
    "reviews": [
        _record("worker-alpha", 1, "a"*40, [
            _change("renamed", "docs/alpha2.md", "docs/alpha.md")]),
        _record("worker-beta", 2, "b"*40, [
            _change("added", "tests/beta.py")]),
    ],
    "ownership": [
        _ownership("worker-alpha", "a"*40, ["docs/alpha2.md", "docs/alpha.md"]),
        _ownership("worker-beta", "b"*40, ["tests/beta.py"]),
    ],
}


def encoded(d):
    return json.dumps(d, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class WorkerOwnershipTests(unittest.TestCase):
    def test_exact_ownership_only_review(self):
        self.assertEqual(owner.check(encoded(GOOD)), "REVIEW_ONLY")

    def test_permuted_claims_still_review(self):
        doc = copy.deepcopy(GOOD)
        doc["ownership"].reverse()
        doc["ownership"][1]["paths"].reverse()
        self.assertEqual(owner.check(encoded(doc)), "REVIEW_ONLY")

    def test_unclaimed_added_or_old_rename_path_holds(self):
        for dropped in ("docs/alpha2.md", "docs/alpha.md"):
            with self.subTest(dropped=dropped):
                doc = copy.deepcopy(GOOD)
                doc["ownership"][0]["paths"].remove(dropped)
                self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_fake_extra_owned_path_and_shared_alias_hold(self):
        for extra in ("docs/fake.md", "DOCS/ALPHA.MD", "src/lightup/domain.py"):
            with self.subTest(extra=extra):
                doc = copy.deepcopy(GOOD)
                doc["ownership"][0]["paths"].append(extra)
                self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_protected_ancestor_descendant_and_case_alias_hold(self):
        for bad in ("src/lightup/domain.py", "src/lightup",
                    "src/lightup/domain.py/new", "SRC/LIGHTUP/DOMAIN.PY",
                    "src/lightup/engagements.py"):
            with self.subTest(path=bad):
                doc = copy.deepcopy(GOOD)
                doc["reviews"][1]["compare"]["files"][0]["filename"] = bad
                doc["ownership"][1]["paths"][0] = bad
                self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_siblings_under_same_directory_can_review(self):
        doc = copy.deepcopy(GOOD)
        doc["reviews"][1]["compare"]["files"][0]["filename"] = "src/lightup/offline_fake.py"
        doc["ownership"][1]["paths"][0] = "src/lightup/offline_fake.py"
        self.assertEqual(owner.check(encoded(doc)), "REVIEW_ONLY")

    def test_wrong_worker_or_head_binding_holds(self):
        for section, key, bad in (
            ("ownership", "worker", "worker-other"),
            ("ownership", "head_sha", "f"*40),
            ("ownership", "head_sha", True),
            ("ownership", "head_sha", ""),
            ("ownership", "paths", "docs/alpha.md"),
        ):
            with self.subTest(section=section, key=key, bad=bad):
                doc = copy.deepcopy(GOOD)
                doc["ownership"][0][key] = bad
                self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_duplicate_claim_owner_and_unrecognized_fields_hold(self):
        for scope in ("ownership", "root", "review"):
            doc = copy.deepcopy(GOOD)
            if scope == "ownership":
                doc["ownership"][1] = copy.deepcopy(doc["ownership"][0])
            elif scope == "root":
                doc["release_allowed"] = False
            else:
                doc["reviews"][0]["operator_approved"] = False
            self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_empty_or_invalid_protected_paths_hold(self):
        for protected in ([], ["a/.."], [".git"], ["src/a", "SRC/A"],
                          "src/a", [True], ["src/a", "src/a/deep"]):
            with self.subTest(protected=protected):
                doc = copy.deepcopy(GOOD)
                doc["protected_paths"] = protected
                self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_shrinking_or_inflating_changed_files_holds(self):
        for value in (-1, 0, 2, True, "1"):
            doc = copy.deepcopy(GOOD)
            doc["reviews"][1]["pr"]["changed_files"] = value
            self.assertEqual(owner.check(encoded(doc)), "HOLD")

    def test_unauthenticated_input_cannot_issue_permissions(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(TOOL)],
                                input=encoded(GOOD), capture_output=True,
                                timeout=8)
        self.assertEqual(result.returncode, 3, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertTrue(all(receipt[f] is False for f in owner.review.FLAGS))
        self.assertNotIn(b"domain.py", result.stdout)

    def test_cli_hold_is_private_and_exact(self):
        doc = copy.deepcopy(GOOD)
        doc["ownership"][0]["paths"] = ["secret/path/never-echo"]
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(TOOL)],
                                input=encoded(doc), capture_output=True,
                                timeout=8)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
        self.assertNotIn(b"secret", result.stdout)

    def test_no_network_or_process_required(self):
        with (mock.patch("socket.socket", side_effect=AssertionError("network")),
              mock.patch("subprocess.run", side_effect=AssertionError("process"))):
            self.assertEqual(owner.check(encoded(GOOD)), "REVIEW_ONLY")

    def test_canonical_prefix_corruption_holds(self):
        raw = encoded(GOOD)
        for n in range(len(raw)):
            with self.subTest(n=n):
                self.assertEqual(owner.check(raw[:n]), "HOLD")


if __name__ == "__main__":
    unittest.main()
