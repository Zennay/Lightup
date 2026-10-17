"""Real subprocess + synthetic GitHub PR snapshot review contract (#1549)."""
import io
import json
import pathlib
import random
import subprocess
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import review_scope_pr_snapshots_1549_offline as adapter

A, B, C, D, E = ["a"*40, "b"*40, "c"*40, "d"*40, "e"*40]


def entry(n, head, base=A, owner="worker-a", draft=True, state="open"):
    return {"number": n, "owner": owner, "head_sha": head, "base_sha": base,
            "draft": draft, "state": state}


def wire(entries=None, **overrides):
    data = {"version": 1, "root_sha": A, "pull_requests": [
        entry(10, B), entry(20, C, B), entry(30, D, C),
    ] if entries is None else entries}
    data.update(overrides)
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode()


class SnapshotReviewTests(unittest.TestCase):
    def hold(self, raw):
        receipt, code = adapter.evaluate(raw)
        self.assertEqual((receipt["status"], code), ("HOLD", 2))
        self.assertEqual(receipt["waves"], [])
        self.assertEqual(receipt["protocol"], "PR_SNAPSHOT_V1")
        self.assertTrue(all(receipt[name] is False for name in adapter.OFF_FLAGS))

    def review(self, raw, waves):
        receipt, code = adapter.evaluate(raw)
        self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))
        self.assertEqual(receipt["waves"], waves)
        self.assertEqual(receipt["protocol"], "PR_SNAPSHOT_V1")
        self.assertTrue(all(receipt[name] is False for name in adapter.OFF_FLAGS))

    def test_chain_inferred_from_base_and_head(self):
        self.review(wire(), [[10], [20], [30]])

    def test_independent_branches_parallel_wave(self):
        self.review(wire([entry(8, B), entry(2, C), entry(5, D)]), [[2, 5, 8]])

    def test_out_of_order_rows_stable(self):
        rng = random.Random(1549)
        rows = [entry(10, B), entry(20, C, B), entry(30, D, C)]
        for _ in range(50):
            rng.shuffle(rows)
            self.review(wire(rows), [[10], [20], [30]])

    def test_missing_predecessor_holds(self):
        self.hold(wire([entry(10, B), entry(20, C, E)]))

    def test_different_release_root_holds(self):
        self.hold(wire([entry(10, B)], root_sha=E))

    def test_cycle_holds(self):
        self.hold(wire([entry(10, B, C), entry(20, C, B)]))

    def test_duplicate_or_zero_pr_heads_hold(self):
        for rows in ([entry(10, B), entry(10, C)], [entry(10, B), entry(20, B)],
                     [entry(10, "0"*40)], [entry(10, A)]):
            with self.subTest(rows=rows):
                self.hold(wire(rows))

    def test_no_real_review_of_merged_or_closed_pr(self):
        for state, draft in (("closed", True), ("open", False),
                             ("merged", True), ("open", 1), ("open", None),
                             ("OPEN", True)):
            with self.subTest(state=state, draft=draft):
                self.hold(wire([entry(10, B, state=state, draft=draft)]))

    def test_schema_or_types_must_be_exact(self):
        for invalid in ([], None, {}, "foo", 42, True, [None], [True], [1]):
            self.hold(wire(invalid))
        self.hold(wire([entry(10, B)], version=True))
        self.hold(wire([entry(10, B)], version=2))
        self.hold(wire([entry(10, B)], unknown="RELEASE"))
        rows = [entry(10, B)]
        rows[0]["can_merge"] = True
        self.hold(wire(rows))

    def test_synthetically_int_confused_values(self):
        for n in (True, 0, "10", 1.0, -1, 2147483648):
            self.hold(wire([entry(n, B)]))

    def test_all_zero_or_uppercase_or_malformed_sha(self):
        for sha in ("0"*40, "A"*40, "b"*39, "b"*41, "z"*40, None, 123):
            self.hold(wire([entry(10, B)], root_sha=sha))
            self.hold(wire([entry(10, B, sha)]))
            self.hold(wire([entry(10, sha)]))

    def test_ambiguous_owner_names_hold(self):
        for owner in ("", "Worker-A", "worker_", "worker a", "ábc", "foo-",
                      "x"*41, 10, None):
            self.hold(wire([entry(10, B, owner=owner)]))

    def test_duplicate_json_properties_hold(self):
        raw = wire([entry(10, B)])
        self.hold(raw.replace(b'"draft":true', b'"draft":true,"draft":true'))
        self.hold(raw.replace(b'"root_sha":', b'"root_sha":"'+A.encode()+b'","root_sha":'))

    def test_unicode_escape_identity_hold(self):
        raw = wire([entry(10, B)])
        self.hold(raw.replace(b'"owner":"worker-a"', b'"owner":"worker-\\u0061"'))
        self.hold(raw.replace(b'"number"', b'"n\\u0075mber"'))

    def test_nonstandard_json_and_invalid_encoding_hold(self):
        for raw in (b"", b"{}", b"null", b"NaN", b"[]", b"\xff", b"{", b"{}", b"{\"x\":Infinity}"):
            with self.subTest(raw=raw[:20]):
                self.hold(raw)

    def test_bounded_64_rows_and_oversize(self):
        rows = [entry(i, f"{i:040x}") for i in range(1, 65)]
        self.review(wire(rows), [list(range(1, 65))])
        self.hold(wire(rows+[entry(65, f"{65:040x}")]))
        data = wire([entry(10, B)])
        self.review(data + b" "*(adapter.core.MAX_INPUT-len(data)), [[10]])
        self.hold(data + b" "*(adapter.core.MAX_INPUT-len(data)+1))

    def test_closed_loop_write_is_never_authority(self):
        script = ROOT / "scripts/review_scope_pr_snapshots_1549_offline.py"
        for raw, code in ((wire(), 3), (wire([entry(2, B, E)]), 2), (b"BAD", 2)):
            proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(script)],
                                  input=raw, capture_output=True, timeout=15)
            self.assertEqual(proc.returncode, code, proc.stderr)
            self.assertEqual(proc.stderr, b"")
            self.assertEqual(proc.stdout.count(b"\n"), 1)
            self.assertEqual(json.loads(proc.stdout)["status"],
                             "REVIEW_ONLY" if code == 3 else "HOLD")
            self.assertTrue(all(json.loads(proc.stdout)[k] is False
                                for k in adapter.OFF_FLAGS))

    def test_cli_no_options(self):
        script = ROOT / "scripts/review_scope_pr_snapshots_1549_offline.py"
        for flag in ("--authorize", "--merge", "--release", "--help", "unused"):
            proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(script), flag],
                                  input=wire(), capture_output=True, timeout=15)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")

    def test_framed_stdin_missing_eof_denies_trailing_bytes(self):
        class Chunks:
            def __init__(self, parts):
                self.parts = iter(parts)
                self.buffer = self
            def read(self, count):
                return next(self.parts, b"")
        for parts, status in (([wire()[:21], wire()[21:], b""], "REVIEW_ONLY"),
                              ([wire(), b"evil", b""], "HOLD")):
            output = io.StringIO()
            with mock.patch.object(adapter.sys, "stdin", Chunks(parts)), \
                 mock.patch.object(adapter.sys, "stdout", output), \
                 mock.patch.object(adapter.sys, "argv", ["adapter"]):
                code = adapter.main()
            self.assertEqual((json.loads(output.getvalue())["status"], code),
                             (status, 3 if status == "REVIEW_ONLY" else 2))


if __name__ == "__main__":
    unittest.main()
