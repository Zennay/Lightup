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


DEFAULT = object()


def wire(entries=DEFAULT, **overrides):
    data = {"version": 1, "root_sha": A, "pull_requests": [
        entry(10, B), entry(20, C, B), entry(30, D, C),
    ] if entries is DEFAULT else entries}
    data.update(overrides)
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode()


def repo_entry(n, head, base, base_ref, head_ref, repository="Zennay/Lightup"):
    return dict(entry(n, head, base), base_repository=repository,
                head_repository=repository, base_ref=base_ref, head_ref=head_ref)


def wire_v3(first, second, repository="Zennay/Lightup", root_ref="main"):
    return json.dumps({"version": 3, "repository": repository, "root_sha": A,
                       "root_ref": root_ref, "first_read": first,
                       "second_read": second}, separators=(",", ":")).encode()


class SnapshotReviewTests(unittest.TestCase):
    def hold(self, raw):
        receipt, code = adapter.evaluate(raw)
        self.assertEqual((receipt["status"], code), ("HOLD", 2))
        self.assertEqual(receipt["waves"], [])
        # A recognized V2 envelope retains V2 protocol even when rejected.
        # Unrecognized or malformed input remains generic V1 HOLD.
        try:
            decoded = json.loads(raw)
        except (ValueError, TypeError, UnicodeError):
            decoded = None
        is_v2 = (type(decoded) is dict and
                 type(decoded.get("version")) is int and
                 decoded["version"] == 2 and len(raw) <= adapter.core.MAX_INPUT)
        expected = "PR_SNAPSHOT_V2_DOUBLE_READ" if is_v2 else "PR_SNAPSHOT_V1"
        self.assertEqual(receipt["protocol"], expected)
        self.assertTrue(all(receipt[name] is False for name in adapter.OFF_FLAGS))

    def review(self, raw, waves):
        receipt, code = adapter.evaluate(raw)
        self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))
        self.assertEqual(receipt["waves"], waves)
        self.assertEqual(receipt["protocol"], "PR_SNAPSHOT_V1")
        self.assertTrue(all(receipt[name] is False for name in adapter.OFF_FLAGS))

    def test_snapshot_receipt_binds_exact_input_and_inferred_graph(self):
        import hashlib
        raw = wire([entry(1550, B)])
        receipt, code = adapter.evaluate(raw)
        self.assertEqual(code, 3)
        self.assertEqual(receipt["input_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertRegex(receipt["derived_graph_sha256"], r"^[0-9a-f]{64}$")
        variant = wire([entry(1550, C)])
        changed, code2 = adapter.evaluate(variant)
        self.assertEqual(code2, 3)
        self.assertEqual(receipt["waves"], changed["waves"])
        self.assertNotEqual(receipt["input_sha256"], changed["input_sha256"])
        self.assertNotEqual(receipt["derived_graph_sha256"], changed["derived_graph_sha256"])
        self.assertNotIn("input_sha256", adapter.evaluate(b"BAD")[0])
        self.assertNotIn("derived_graph_sha256", adapter.evaluate(b"BAD")[0])

    def test_chain_inferred_from_base_and_head(self):
        self.review(wire(), [[10], [20], [30]])

    def test_independent_branches_parallel_wave(self):
        self.review(wire([entry(8, B), entry(2, C), entry(5, D)]), [[2, 5, 8]])

    def test_v3_repo_and_root_branch_bound_fingerprint_changes_without_sha_change(self):
        row = repo_entry(42, B, A, "main", "feature/own")
        original, co = adapter.evaluate(wire_v3([row], [row]))
        moved = dict(row, base_ref="release")
        changed, cc = adapter.evaluate(wire_v3([moved], [moved], root_ref="release"))
        other_repo = "Another/Lightup"
        repointed = dict(row, base_repository=other_repo,
                         head_repository=other_repo)
        foreign, cf = adapter.evaluate(wire_v3(
            [repointed], [repointed], repository=other_repo))
        self.assertEqual((co, cc, cf), (3, 3, 3))
        self.assertEqual(original["waves"], changed["waves"])
        self.assertEqual(original["waves"], foreign["waves"])
        self.assertNotEqual(original["derived_graph_sha256"], changed["derived_graph_sha256"])
        self.assertNotEqual(original["derived_graph_sha256"], foreign["derived_graph_sha256"])
        for receipt in (original, changed, foreign):
            self.assertTrue(all(receipt[k] is False for k in adapter.OFF_FLAGS))

    def test_v3_64_stacked_prs_and_independent_reordered_waves(self):
        # Maximum bounded stack: each prior branch ref must be named exactly.
        rows = []
        for i in range(1, 65):
            previous_sha = A if i == 1 else f"{i-1:040x}"
            base_ref = "main" if i == 1 else f"pr-{i-1}"
            rows.append(repo_entry(i, f"{i:040x}", previous_sha,
                                   base_ref, f"pr-{i}"))
        original = wire_v3(rows, rows)
        reordered = wire_v3(list(reversed(rows)), list(reversed(rows)))
        a, ca = adapter.evaluate(original)
        b, cb = adapter.evaluate(reordered)
        self.assertEqual((ca, cb), (3, 3))
        self.assertEqual(a["waves"], [[i] for i in range(1, 65)])
        self.assertEqual(a["derived_graph_sha256"], b["derived_graph_sha256"])
        self.assertNotEqual(a["input_sha256"], b["input_sha256"])
        parallel = [repo_entry(i, f"{i:040x}", A, "main", f"pr-{i}")
                    for i in range(1, 65)]
        receipt, code = adapter.evaluate(wire_v3(parallel, list(reversed(parallel))))
        self.assertEqual(code, 3)
        self.assertEqual(receipt["waves"], [list(range(1, 65))])
        self.assertTrue(all(receipt[k] is False for k in adapter.OFF_FLAGS))

    def test_v3_invalid_repo_ref_and_schema_boundaries(self):
        good = repo_entry(10, B, A, "main", "scope/one")
        for repo in ("", "Other Repo/Lightup", "Other//Lightup",
                     "Other/..", "Other/Lightup.lock", "Zennay/lightup",
                     "../Lightup", None, 12):
            with self.subTest(repository=repo):
                self.assertEqual(adapter.evaluate(wire_v3([good], [good],
                                                          repository=repo))[1], 2)
        for ref in ("", "/main", "main/", "MAIN ", "main..next", "main//next",
                    "main.lock", ".hidden", "main/.private", "main@{test}",
                    None, 8):
            with self.subTest(root_ref=ref):
                self.assertEqual(adapter.evaluate(wire_v3([good], [good],
                                                          root_ref=ref))[1], 2)
        base = json.loads(wire_v3([good], [good]))
        for key in ("repository", "root_ref", "first_read", "second_read"):
            changed = dict(base)
            del changed[key]
            self.assertEqual(adapter.evaluate(json.dumps(changed).encode())[1], 2)
        changed = dict(base, can_merge=True)
        self.assertEqual(adapter.evaluate(json.dumps(changed).encode())[1], 2)
        raw = wire_v3([good], [good])
        self.assertEqual(adapter.evaluate(raw + b" "*(adapter.core.MAX_INPUT-len(raw)))[1], 3)
        self.assertEqual(adapter.evaluate(raw + b" "*(adapter.core.MAX_INPUT-len(raw)+1))[1], 2)

    def test_v3_real_isolated_child_process_and_no_authority_options(self):
        script = ROOT / "scripts/review_scope_pr_snapshots_1549_offline.py"
        row = repo_entry(1550, B, A, "main", "scope/own-pr")
        payload = wire_v3([row], [row])
        for argv, inp, expected in (([], payload, 3),
                                    ([], wire_v3([row], [dict(row, head_ref="new")]), 2),
                                    (["--authorize"], payload, 2),
                                    (["--merge"], payload, 2)):
            with self.subTest(argv=argv, expected=expected):
                p = subprocess.run([sys.executable, "-I", "-S", "-B", str(script), *argv],
                                   input=inp, capture_output=True, timeout=15)
                self.assertEqual(p.returncode, expected, p.stderr)
                self.assertEqual(p.stderr, b"")
                receipt = json.loads(p.stdout)
                self.assertEqual(receipt["status"], "REVIEW_ONLY" if expected == 3 else "HOLD")
                self.assertTrue(all(receipt[k] is False for k in adapter.OFF_FLAGS))

    def test_v3_same_repository_and_refs_two_reads_advisory_only(self):
        rows = [
            repo_entry(10, B, A, "main", "scope-a"),
            repo_entry(20, C, B, "scope-a", "scope-b"),
            repo_entry(30, D, C, "scope-b", "scope-c"),
        ]
        first = wire_v3(rows, list(reversed(rows)))
        second = wire_v3(list(reversed(rows)), rows)
        a, code_a = adapter.evaluate(first)
        b, code_b = adapter.evaluate(second)
        self.assertEqual((code_a, code_b), (3, 3))
        self.assertEqual(a["protocol"], "PR_SNAPSHOT_V3_REPO_BOUND_DOUBLE_READ")
        self.assertEqual(a["waves"], [[10], [20], [30]])
        self.assertEqual(a["derived_graph_sha256"], b["derived_graph_sha256"])
        self.assertNotEqual(a["input_sha256"], b["input_sha256"])
        self.assertTrue(all(a[k] is False for k in adapter.OFF_FLAGS))

    def test_v3_repository_fork_ref_and_cross_read_drift_hold(self):
        root = repo_entry(10, B, A, "main", "scope-a")
        mutations = [
            {"base_repository": "Other/Repo"},
            {"head_repository": "Other/Repo"},
            {"base_ref": "release"},
            {"head_ref": "scope-renamed"},  # Same SHA, wrong branch identity
            {"base_ref": "MAIN"},
            {"head_ref": "../scope"},
            {"head_ref": "scope..a"},
            {"head_ref": "scope/a.lock"},
        ]
        for attrs in mutations:
            changed = dict(root, **attrs)
            with self.subTest(changed=attrs):
                raw = wire_v3([root], [changed])
                receipt, code = adapter.evaluate(raw)
                self.assertEqual((receipt["status"], code), ("HOLD", 2))
                self.assertEqual(receipt["protocol"],
                                 "PR_SNAPSHOT_V3_REPO_BOUND_DOUBLE_READ")
                self.assertEqual(receipt["waves"], [])
                self.assertTrue(all(receipt[k] is False for k in adapter.OFF_FLAGS))
        self.assertEqual(adapter.evaluate(wire_v3([root], [root],
                                                   repository="Other/Repo"))[1], 2)

    def test_v3_missing_or_malformed_context_and_stacked_base_ref_hold(self):
        first = [repo_entry(10, B, A, "main", "scope-a"),
                 repo_entry(20, C, B, "scope-a", "scope-b")]
        good = wire_v3(first, first)
        self.assertEqual(adapter.evaluate(good)[1], 3)
        for key in ("head_repository", "base_repository", "base_ref", "head_ref"):
            changed = [dict(first[0]), dict(first[1])]
            changed[1].pop(key)
            with self.subTest(missing=key):
                self.assertEqual(adapter.evaluate(wire_v3(first, changed))[1], 2)
        inconsistent = [dict(first[0]), dict(first[1], base_ref="main")]
        self.assertEqual(adapter.evaluate(wire_v3(inconsistent, inconsistent))[1], 2)
        alias = [dict(first[0]), dict(first[1], head_ref="scope-a")]
        self.assertEqual(adapter.evaluate(wire_v3(alias, alias))[1], 2)
        self.assertEqual(adapter.evaluate(wire_v3(first, first,
                                                  root_ref="../main"))[1], 2)

    def test_v3_head_ref_changes_fingerprint_without_head_sha_change(self):
        row = repo_entry(10, B, A, "main", "scope-a")
        renamed = dict(row, head_ref="scope-new")
        a, ca = adapter.evaluate(wire_v3([row], [row]))
        b, cb = adapter.evaluate(wire_v3([renamed], [renamed]))
        self.assertEqual((ca, cb), (3, 3))
        self.assertEqual(a["waves"], b["waves"])
        self.assertNotEqual(a["derived_graph_sha256"], b["derived_graph_sha256"])

    def test_two_read_consistent_snapshot_accepts_reordered_rows_only(self):
        rows = [entry(10, B), entry(20, C, B), entry(30, D, C)]
        data = json.dumps({"version": 2, "root_sha": A,
                           "first_read": rows, "second_read": list(reversed(rows))}).encode()
        receipt, code = adapter.evaluate(data)
        self.assertEqual(code, 3)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["protocol"], "PR_SNAPSHOT_V2_DOUBLE_READ")
        self.assertEqual(receipt["waves"], [[10], [20], [30]])
        self.assertTrue(all(receipt[k] is False for k in adapter.OFF_FLAGS))

    def test_two_read_detects_head_base_owner_number_and_missing_changes(self):
        first = [entry(10, B), entry(20, C, B)]
        mutations = [
            [entry(10, D), entry(20, C, D)],
            [entry(10, B), entry(20, C, D)],
            [entry(10, B, owner="worker-x"), entry(20, C, B)],
            [entry(10, B), entry(21, C, B)],
            [entry(10, B)],
            [entry(10, B), entry(20, C, B, state="closed")],
            [entry(10, B), entry(20, C, B, draft=False)],
            [entry(10, B), entry(20, B)],
        ]
        for second in mutations:
            with self.subTest(rows=second):
                raw = json.dumps({"version": 2, "root_sha": A,
                                  "first_read": first, "second_read": second}).encode()
                self.hold(raw)

    def test_two_read_conflict_receipt_reports_correct_protocol_not_v1(self):
        mismatched = {"version": 2, "root_sha": A,
                      "first_read": [entry(10, B)],
                      "second_read": [entry(10, C)]}
        receipt, code = adapter.evaluate(json.dumps(mismatched).encode())
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["protocol"], "PR_SNAPSHOT_V2_DOUBLE_READ")
        self.assertTrue(all(receipt[k] is False for k in adapter.OFF_FLAGS))
        self.assertNotIn("input_sha256", receipt)
        self.assertNotIn("derived_graph_sha256", receipt)

    def test_two_read_missing_or_malformed_metadata_holds(self):
        source = {"version": 2, "root_sha": A,
                  "first_read": [entry(10, B)], "second_read": [entry(10, B)]}
        for key in ("first_read", "second_read", "root_sha"):
            changed = dict(source)
            del changed[key]
            self.hold(json.dumps(changed).encode())
        for bad in (None, [], "bad", [{"number": 10}], [False], [entry(10, B)]*2):
            changed = dict(source, second_read=bad)
            self.hold(json.dumps(changed).encode())

    def test_two_read_real_child_process_remains_hold_only_advisory(self):
        script = ROOT / "scripts/review_scope_pr_snapshots_1549_offline.py"
        snapshots = {"version": 2, "root_sha": A,
                     "first_read": [entry(10, B)], "second_read": [entry(10, B)]}
        raw = json.dumps(snapshots).encode()
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(script)],
                                input=raw, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 3, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["protocol"], "PR_SNAPSHOT_V2_DOUBLE_READ")
        self.assertFalse(receipt["merge_plan_approved"])
        self.assertFalse(receipt["source_authenticated"])

    def test_inferred_graph_fingerprint_is_stable_across_snapshot_row_order(self):
        forward = wire([entry(10, B), entry(20, C, B), entry(30, D, C)])
        reverse = wire([entry(30, D, C), entry(20, C, B), entry(10, B)])
        a, code_a = adapter.evaluate(forward)
        b, code_b = adapter.evaluate(reverse)
        self.assertEqual((code_a, code_b), (3, 3))
        self.assertEqual(a["waves"], b["waves"])
        self.assertNotEqual(a["input_sha256"], b["input_sha256"])
        self.assertEqual(a["derived_graph_sha256"], b["derived_graph_sha256"])

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
