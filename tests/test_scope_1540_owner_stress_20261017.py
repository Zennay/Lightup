"""Bounded multiworker ownership and immutable HOLD oracle for issue #1540."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_worker_ownership_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_ownership_stress", SCRIPT)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
PIN = "a" * 40
REPO = "Example/Lightup"


def payload(workers=16, files_per_worker=16):
    reviews, ownership = [], []
    for i in range(workers):
        worker = f"scope-{i:02d}"
        head = f"{i+1:040x}"
        branch = "review/" + worker
        paths = [f"docs/w{i:02d}/changed-{j:02d}.md"
                 for j in range(files_per_worker)]
        files = [{"status": "added", "filename": path} for path in paths]
        reviews.append({
            "worker": worker, "branch": branch,
            "pr": {"number": i+1, "state": "open", "draft": True,
                   "base_sha": PIN, "head_sha": head,
                   "head_ref": branch, "head_repo_full_name": REPO,
                   "changed_files": len(files)},
            "compare": {"base_sha": PIN, "head_sha": head,
                        "repository_full_name": REPO, "status": "ahead",
                        "ahead_by": 1, "behind_by": 0, "too_large": False,
                        "files": files},
        })
        ownership.append({"worker": worker, "head_sha": head, "paths": paths})
    return {"version": 1, "repository_full_name": REPO,
            "base_sha": PIN, "reviews": reviews,
            "ownership": ownership, "protected_paths": [
                "src/lightup/domain.py", "src/lightup/engagements.py"]}


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class OwnershipStressTests(unittest.TestCase):
    def test_16_workers_x16_owned_files_can_be_reviewed(self):
        doc = payload()
        raw = encoded(doc)
        self.assertLessEqual(len(raw), owner.review.MAX_INPUT)
        self.assertEqual(owner.check(raw), "REVIEW_ONLY")

    def test_256_claims_exact_missing_last_file_atomic_hold(self):
        data = payload()
        data["ownership"][-1]["paths"].pop()
        self.assertEqual(owner.check(encoded(data)), "HOLD")

    def test_256_claims_one_owner_path_case_alias_holds(self):
        data = payload()
        data["ownership"][-1]["paths"][-1] = data["ownership"][-1]["paths"][-1].upper()
        self.assertEqual(owner.check(encoded(data)), "HOLD")

    def test_256_claims_protected_file_never_review(self):
        for bad in ("src/lightup/domain.py", "SRC/LIGHTUP/DOMAIN.PY",
                    "src/lightup", "src/lightup/domain.py/child"):
            with self.subTest(bad=bad):
                data = payload()
                data["reviews"][-1]["compare"]["files"][-1]["filename"] = bad
                data["ownership"][-1]["paths"][-1] = bad
                self.assertEqual(owner.check(encoded(data)), "HOLD")

    def test_reordered_ownership_entries_remain_valid(self):
        data = payload()
        data["ownership"].reverse()
        self.assertEqual(owner.check(encoded(data)), "REVIEW_ONLY")

    def test_no_allowlist_can_rewrite_protected_source(self):
        for bad in ("src/lightup/domain.py", "src/lightup"):
            data = payload(workers=2, files_per_worker=1)
            data["reviews"][0]["compare"]["files"][0]["filename"] = bad
            data["ownership"][0]["paths"][0] = bad
            self.assertEqual(owner.check(encoded(data)), "HOLD")

    def test_over_maximum_input_is_always_hold(self):
        data = payload(workers=32, files_per_worker=32)
        raw = encoded(data)
        self.assertGreater(len(raw), owner.review.MAX_INPUT)
        self.assertEqual(owner.check(raw), "HOLD")


if __name__ == "__main__":
    unittest.main()
