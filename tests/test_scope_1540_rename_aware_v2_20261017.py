"""Issue #1540 protocol-v2: bounded rename/copy/delete cross-worker HOLD checks."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_worker_overlap_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_v2", SCRIPT)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)
PIN = "b" * 40


def change(op, path, source=None):
    value = {"op": op, "path": path}
    if source is not None:
        value["from_path"] = source
    return value


def prop(worker, changes, base=PIN):
    return {"worker": worker, "branch": "review/" + worker,
            "base_sha": base, "changes": changes}


def batch(*items, base=PIN):
    return {"version": 2, "base_sha": base, "proposals": list(items)}


def raw(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


class RenameAwareV2(unittest.TestCase):
    def test_normal_distinct_v2_changes_are_review_only(self):
        doc = batch(
            prop("scope-one", [change("rename", "src/updated.py", "src/original.py"),
                               change("add", "docs/new.md")]),
            prop("scope-two", [change("delete", "tests/old.py"),
                               change("copy", "docs/copy.md", "docs/source.md")]))
        self.assertEqual(review.check(raw(doc)), "REVIEW_ONLY")

    def test_rename_old_path_is_not_a_free_escape(self):
        for op in ("rename", "copy"):
            for other in ("src/source.py", "SRC/SOURCE.py", "src/source.py/deep"):
                with self.subTest(op=op, other=other):
                    doc = batch(prop("scope-one",
                                     [change(op, "src/dest.py", "src/source.py")]),
                                prop("scope-two", [change("modify", other)]))
                    self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_rename_destination_conflicts_even_if_old_path_distinct(self):
        for other in ("src/dest.py", "src/dest.py/child", "src"):
            doc = batch(prop("scope-one", [change("rename", "src/dest.py",
                                                   "src/original.py")]),
                        prop("scope-two", [change("add", other)]))
            self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_copy_or_rename_cannot_reuse_its_own_source(self):
        for op in ("copy", "rename"):
            for destination, source in (
                ("src/a.py", "src/a.py"),
                ("src/A.py", "src/a.py"),
                ("src/a.py/new", "src/a.py"),
                ("src/a.py", "src/a.py/deeper"),
            ):
                doc = batch(prop("scope-one", [change(op, destination, source)]),
                            prop("scope-two", [change("add", "unrelated.py")]))
                self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_source_collision_across_ops_inside_one_worker_holds(self):
        doc = batch(prop("scope-one", [
            change("rename", "src/new.py", "src/old.py"),
            change("modify", "src/OLD.py")]),
            prop("scope-two", [change("add", "docs/other.md")]))
        self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_wrong_operation_and_fields_hold(self):
        for item in (
            change("move", "new.py", "old.py"),
            change("rename", "new.py"),
            change("copy", "new.py"),
            change("delete", "old.py", "extra.py"),
            change("modify", "same.py", "same.py"),
            {"op": "add", "path": "file.py", "approved": False},
            {"op": "add", "path": "file.py", "from_path": None},
            {"op": True, "path": "file.py"},
            {"op": "rename", "path": ["a.py"], "from_path": "old.py"},
            {"op": "copy", "path": "x.py", "from_path": "../secret"},
        ):
            with self.subTest(item=item):
                doc = batch(prop("scope-one", [item]),
                            prop("scope-two", [change("add", "unrelated.py")]))
                self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_mixed_v1_v2_is_never_silent_downgrade(self):
        doc = batch(prop("scope-one", [change("add", "a.py")]),
                    prop("scope-two", [change("add", "b.py")]))
        doc["proposals"][1]["paths"] = ["b.py"]
        self.assertEqual(review.check(raw(doc)), "HOLD")
        doc["version"] = 1
        self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_unrecognized_fields_version_and_base_are_hold(self):
        doc = batch(prop("scope-one", [change("add", "a.py")]),
                    prop("scope-two", [change("add", "b.py")]))
        for change_field, value in (("version", 3), ("version", True),
                                    ("version", "2"), ("base_sha", "C" * 40),
                                    ("base_sha", "c" * 40)):
            updated = {**doc, change_field: value}
            self.assertEqual(review.check(raw(updated)), "HOLD")
        doc["proposals"][0]["base_sha"] = "a" * 40
        self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_duplicate_change_alias_and_casefold_path_hold(self):
        doc = batch(prop("scope-one", [change("delete", "src/A.py"),
                                        change("modify", "src/a.py")]),
                    prop("scope-two", [change("add", "docs/new.md")]))
        self.assertEqual(review.check(raw(doc)), "HOLD")

    def test_backward_compatible_v1_behavior(self):
        old = {"version": 1, "base_sha": PIN,
               "proposals": [
                   {"worker": "scope-one", "branch": "review/one",
                    "base_sha": PIN, "paths": ["tests/a.py"]},
                   {"worker": "scope-two", "branch": "review/two",
                    "base_sha": PIN, "paths": ["docs/b.md"]}]}
        self.assertEqual(review.check(raw(old)), "REVIEW_ONLY")
        old["proposals"][1]["paths"] = ["tests/a.py"]
        self.assertEqual(review.check(raw(old)), "HOLD")

    def test_cli_v2_output_is_never_auth(self):
        good = batch(prop("scope-one", [change("rename", "a-new.py", "a-old.py")]),
                     prop("scope-two", [change("add", "b.py")]))
        for value, expected, exit_code in ((good, "REVIEW_ONLY", 3),
                                            ({**good, "version": 99}, "HOLD", 2)):
            done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                  input=raw(value), capture_output=True,
                                  timeout=10, check=False)
            self.assertEqual(done.returncode, exit_code, done.stderr)
            self.assertEqual(done.stderr, b"")
            result = json.loads(done.stdout)
            self.assertEqual(result["status"], expected)
            self.assertEqual(set(result), {"status", *review.FLAGS})
            self.assertTrue(all(result[k] is False for k in review.FLAGS))
            self.assertNotIn(b"old.py", done.stdout)
            self.assertNotIn(b"new.py", done.stdout)

    def test_limit_on_total_proposals_and_changes(self):
        for num in (0, 1, 33):
            values = [prop("worker-" + str(i), [change("add", str(i) + ".py")])
                      for i in range(num)]
            self.assertEqual(review.check(raw(batch(*values))), "HOLD")
        for num in (0, 65):
            changes = [change("add", str(i) + ".py") for i in range(num)]
            doc = batch(prop("scope-one", changes),
                        prop("scope-two", [change("add", "other.py")]))
            self.assertEqual(review.check(raw(doc)), "HOLD")


if __name__ == "__main__":
    unittest.main()
