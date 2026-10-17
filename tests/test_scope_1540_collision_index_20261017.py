"""#1540: bounded prefix-index identity and high-volume offline acceptance."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/review_scope_worker_overlap_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_index", SOURCE)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

PIN = "c" * 40


def doc(version, worker_changes):
    key = "paths" if version == 1 else "changes"
    return {"base_sha": PIN, "version": version, "proposals": [
        {"base_sha": PIN, "branch": f"worker/{n}", key: items, "worker": f"worker-{n}"}
        for n, items in enumerate(worker_changes)]}


def as_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class PrefixIndexTests(unittest.TestCase):
    def test_index_allows_shared_directory_but_not_file_prefix(self):
        idx = review._PathIndex()
        self.assertTrue(idx.add("docs/one.md"))
        self.assertTrue(idx.add("docs/two.md"))
        for old_or_alias in ("docs/one.md", "docs", "docs/one.md/extra",
                             "DOCS/ONE.MD", "DOCS"):
            self.assertFalse(idx.add(old_or_alias), old_or_alias)
        self.assertTrue(idx.add("src/independent.py"))

    def test_rejected_index_insert_does_not_claim_new_paths(self):
        idx = review._PathIndex()
        self.assertTrue(idx.add("src/old.py"))
        self.assertFalse(idx.add("src/old.py/new"))
        self.assertTrue(idx.add("src/other.py"))

    def test_segment_exactness_never_confuses_siblings(self):
        idx = review._PathIndex()
        for entry in ("src/a", "src/aa", "src/aaa", "src/a-b", "src/aaa1"):
            self.assertTrue(idx.add(entry))
        self.assertFalse(idx.add("src/a/child"))
        self.assertTrue(idx.add("src/a2/child"))

    def test_deep_ancestor_and_descendant_both_orders(self):
        for paths in (("a/b/c", "a/b"), ("a/b", "a/b/c"),
                      ("a", "a/b/c"), ("a/b/c", "a")):
            with self.subTest(paths=paths):
                idx = review._PathIndex()
                self.assertTrue(idx.add(paths[0]))
                self.assertFalse(idx.add(paths[1]))

    def test_casefold_collapse_and_distinct_paths(self):
        idx = review._PathIndex()
        self.assertTrue(idx.add("a/Mix.py"))
        self.assertFalse(idx.add("A/mix.py"))
        self.assertTrue(idx.add("a/Mix2.py"))

    def test_v1_capacity_32_workers_64_distinct_paths_each(self):
        groups = [[f"p{w:02d}/f{p:02d}" for p in range(64)] for w in range(32)]
        value = doc(1, groups)
        raw = as_bytes(value)
        self.assertLessEqual(len(raw), review.MAX_INPUT)
        self.assertEqual(review.check(raw), "REVIEW_ONLY")

    def test_large_batch_single_alias_never_partial_review(self):
        groups = [[f"p{w:02d}/f{p:02d}" for p in range(64)] for w in range(32)]
        groups[-1][-1] = groups[0][0].swapcase()
        self.assertEqual(review.check(as_bytes(doc(1, groups))), "HOLD")

    def test_v2_multiworker_rename_and_copy_sources_indexed(self):
        groups = []
        for w in range(12):
            groups.append([{"op": "rename", "path": f"p{w}/new-{p}.py",
                            "from_path": f"p{w}/old-{p}.py"}
                           for p in range(12)])
        value = doc(2, groups)
        self.assertLessEqual(len(as_bytes(value)), review.MAX_INPUT)
        self.assertEqual(review.check(as_bytes(value)), "REVIEW_ONLY")
        groups[11][11]["from_path"] = "p0/old-0.py"
        self.assertEqual(review.check(as_bytes(doc(2, groups))), "HOLD")

    def test_every_v1_exhaustive_short_prefix_pair(self):
        candidates = ("a", "A", "a/b", "a/b/c", "a/bee", "ab",
                      "ab/c", "a-b", "x", "x/y", "y/x", "src/one.py",
                      "src/one.pyx", "src/one.py/y")
        def conflict(a, b):
            a, b = a.casefold(), b.casefold()
            return a == b or a.startswith(b + "/") or b.startswith(a + "/")
        for a in candidates:
            for b in candidates:
                with self.subTest(first=a, second=b):
                    value = doc(1, [[a], [b]])
                    self.assertEqual(review.check(as_bytes(value)),
                                     "HOLD" if conflict(a, b) else "REVIEW_ONLY")

    def test_index_receipts_never_include_path_names(self):
        confidential = "src/private-confidential-key.py"
        value = doc(1, [[confidential], [confidential]])
        self.assertEqual(review.check(as_bytes(value)), "HOLD")
        self.assertNotIn(confidential, review._receipt("HOLD"))


if __name__ == "__main__":
    unittest.main()
