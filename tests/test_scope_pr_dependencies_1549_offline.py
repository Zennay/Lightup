"""Standalone stdlib acceptance of synthetic PR topology review; issue #1549."""
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
import scripts.review_scope_pr_dependencies_1549_offline as checker
from scripts.review_scope_pr_dependencies_1549_offline import evaluate, MAX_INPUT, OFF_FLAGS

A, B, C, D, E = ["a"*40, "b"*40, "c"*40, "d"*40, "e"*40]
DEFAULT = object()


def item(n, head, base=A, deps=None, owner="worker-a"):
    return dict(id=n, owner=owner, head_sha=head, base_sha=base,
                depends_on=[] if deps is None else deps)


def manifest(entries=DEFAULT, **extra):
    data = dict(version=1, root_sha=A,
                entries=[item(4, B), item(2, C, B, [4]), item(9, D, C, [2])]
                if entries is DEFAULT else entries)
    data.update(extra)
    return json.dumps(data, separators=(",", ":")).encode()


class DependencyReviewTests(unittest.TestCase):
    def hold(self, data):
        receipt, exit_code = evaluate(data)
        self.assertEqual(exit_code, 2)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["waves"], [])
        self.assertEqual(set(receipt), {"status", "waves", *OFF_FLAGS})
        self.assertTrue(all(receipt[k] is False for k in OFF_FLAGS))

    def review(self, data, waves):
        receipt, exit_code = evaluate(data)
        self.assertEqual(exit_code, 3)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["waves"], waves)
        self.assertTrue(all(receipt[k] is False for k in OFF_FLAGS))

    def test_stacked_three(self):
        self.review(manifest(), [[4], [2], [9]])

    def test_independent_sorted(self):
        self.review(manifest([item(5, B), item(1, C), item(3, D)]), [[1, 3, 5]])

    def test_fan_in(self):
        self.review(manifest([item(10, B), item(11, C), item(12, D, B, [10, 11])]),
                    [[10, 11], [12]])

    def test_bad_json_and_duplicates(self):
        for data in (b"", b"not json", b"{", b"\xff", b"\xef\xbb\xbf{}",
                     b'{"x":NaN}', b"[]", b"null",
                     b'{"version":1,"version":1,"entries":[],"root_sha":"'+A.encode()+b'"}'):
            with self.subTest(data=data[:18]):
                self.hold(data)

    def test_boundaries_and_bad_envelopes(self):
        self.hold(b" " * (MAX_INPUT + 1))
        self.hold(manifest([]))
        self.hold(manifest([item(i, f"{i:040x}") for i in range(1, 66)]))
        for bad in ("text", {}, True, 1, None):
            self.hold(manifest(bad))
            self.hold(manifest([bad]))

    def test_self_missing_repeated_untyped_dependencies(self):
        for deps in ([99], [1], [2, 2], [True], [1.0], ["1"], list(range(2,19))):
            with self.subTest(deps=deps):
                self.hold(manifest([item(1, B, A, deps)]))

    def test_cycle_two_and_three(self):
        self.hold(manifest([item(1, B, C, [2]), item(2, C, B, [1])]))
        self.hold(manifest([item(1, B, D, [3]), item(2, C, B, [1]), item(3, D, C, [2])]))

    def test_duplicate_identity(self):
        self.hold(manifest([item(1, B), item(1, C)]))
        self.hold(manifest([item(1, B), item(2, B)]))

    def test_stale_or_ambiguous_base(self):
        for entries in ([item(1, B, C)], [item(1, B, A, [2]), item(2, C)],
                        [item(1, B), item(2, C, E, [1])],
                        [item(1, A)], [item(1, B, B)]):
            with self.subTest(entries=entries):
                self.hold(manifest(entries))

    def test_exact_sha_fence(self):
        for s in ("A"*40, "a"*39, "a"*41, "g"*40, 12, True, None):
            with self.subTest(sha=s):
                self.hold(manifest([item(1, s)]))
                self.hold(manifest([item(1, B, s)]))
                self.hold(manifest([item(1, B)], root_sha=s))

    def test_owner_identity_fence(self):
        for owner in ("", "Alice", "álice", "wοrker", "-bad", "bad-", "a b",
                      "a\n", "x"*41, True, None, 3):
            with self.subTest(owner=owner):
                self.hold(manifest([item(1, B, owner=owner)]))

    def test_schema_and_authority_injection(self):
        for key in ("consent", "can_merge", "release_authorized"):
            self.hold(manifest([item(1, B)], **{key: True}))
            ent = item(1, B)
            ent[key] = True
            self.hold(manifest([ent]))

    def test_exact_ints_and_versions(self):
        for val in (True, False, 1.0, "1", 0, -1, None, 2147483648):
            self.hold(manifest([item(val, B)]))
        for val in (True, "1", 1.0, None, 2):
            self.hold(manifest([item(1, B)], version=val))

    def test_nested_duplicate_json_keys(self):
        raw = manifest([item(1, B)])
        self.hold(raw.replace(b'"owner":"worker-a"', b'"owner":"worker-a","owner":"worker-b"'))
        self.hold(raw.replace(b'"entries":', b'"entries":[],"entries":'))

    def test_many_independent(self):
        self.review(manifest([item(i, f"{i:040x}") for i in range(1, 65)]),
                    [list(range(1, 65))])

    def test_repeatable_full_capacity_dependency_graph_and_negative_mutations(self):
        # Systematic synthetic 64-node chain and unrelated roots, reordered
        # without changing the review result or broadening authority.
        rng = random.Random(1549)
        for length in (1, 2, 3, 16, 32, 64):
            graph = []
            expected = []
            for i in range(1, length + 1):
                head = f"{i:040x}"
                independent = (i % 7 == 1)
                deps = [] if independent else [i - 1]
                base = A if independent else f"{i - 1:040x}"
                graph.append(item(i, head, base, deps, owner=f"worker-{i}"))
                if independent:
                    expected.append([i])
            # Independently derive levels by simple depth recurrence, not the
            # reviewer's topology routine (avoids common implementation bugs).
            levels = {}
            for entry in graph:
                levels[entry["id"]] = (
                    max((levels[d] for d in entry["depends_on"]), default=-1) + 1
                )
            waves = [[i for i in range(1, length + 1) if levels[i] == depth]
                     for depth in range(max(levels.values()) + 1)]
            for _ in range(12):
                order = graph[:]
                rng.shuffle(order)
                self.review(manifest(order), waves)
            if length >= 2:
                bad = [dict(x) for x in graph]
                bad[-1]["depends_on"] = [bad[-1]["id"]]
                self.hold(manifest(bad))
                bad = [dict(x) for x in graph]
                bad[-1]["head_sha"] = bad[0]["head_sha"]
                self.hold(manifest(bad))

    def test_maximum_bounded_valid_whitespace_and_one_extra_byte(self):
        raw = manifest([item(1, B)])
        padding = b" " * (MAX_INPUT - len(raw))
        self.review(raw + padding, [[1]])
        self.hold(raw + padding + b" ")
        self.hold(padding + raw + b" ")

    def test_zero_git_oid_and_unicode_escaped_identity_hold(self):
        zero = "0" * 40
        # A null Git OID means no object, not a legitimate pinned review.
        self.hold(manifest([item(1, B, zero)], root_sha=zero))
        self.hold(manifest([item(1, zero)]))
        raw = manifest([item(1, B)])
        escaped = (
            raw.replace(b'"owner":"worker-a"', b'"owner":"worker-\\u0061"'),
            raw.replace(b'"id":1', b'"\\u0069d":1'),
            raw.replace(b'"head_sha":"bbbb', b'"head_sha":"\\u0062bbb'),
        )
        for fixture in escaped:
            with self.subTest(fixture=fixture[:95]):
                self.hold(fixture)

    def test_fragmented_stdin_requires_complete_stream_before_review(self):
        valid = manifest()
        class SegmentedInput:
            def __init__(self, pieces):
                self.pieces = iter(pieces)
                self.calls = 0
                self.buffer = self

            def read(self, count):
                self.calls += 1
                if count <= 0:
                    raise AssertionError("invalid bounded read")
                return next(self.pieces, b"")

        for pieces, code in (
            ([valid[:19], valid[19:], b""], 3),
            ([valid, b"malicious trailing bytes", b""], 2),
            ([valid, b"\\x00", b""], 2),
            ([valid, b" " * (MAX_INPUT + 1), b""], 2),
            ([valid, b"{", b""], 2),
        ):
            with self.subTest(chunks=len(pieces), last=len(pieces[-2])):
                incoming = SegmentedInput(pieces)
                output = io.StringIO()
                with mock.patch.object(checker.sys, "stdin", incoming), \
                     mock.patch.object(checker.sys, "stdout", output), \
                     mock.patch.object(checker.sys, "argv", ["reviewer"]):
                    self.assertEqual(checker.main(), code)
                receipt = json.loads(output.getvalue())
                self.assertEqual(receipt["status"], "REVIEW_ONLY" if code == 3 else "HOLD")
                self.assertTrue(all(receipt[k] is False for k in OFF_FLAGS))
                self.assertGreaterEqual(incoming.calls, 2)

    def test_bounded_fragmented_stdin_error_is_generic_hold(self):
        valid = manifest()
        class InterruptedInput:
            buffer = None
            def __init__(self, second):
                self.calls = 0
                self.second = second
                self.buffer = self
            def read(self, count):
                self.calls += 1
                if self.calls == 1:
                    return valid
                if isinstance(self.second, Exception):
                    raise self.second
                return self.second

        for second in (OSError("synthetic read failure"), "not-bytes", bytearray(b"x")):
            with self.subTest(second=type(second).__name__):
                incoming = InterruptedInput(second)
                output = io.StringIO()
                with mock.patch.object(checker.sys, "stdin", incoming), \
                     mock.patch.object(checker.sys, "stdout", output), \
                     mock.patch.object(checker.sys, "argv", ["reviewer"]):
                    self.assertEqual(checker.main(), 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")

    def test_cli_rejects_any_unexpected_arguments(self):
        script = ROOT / "scripts/review_scope_pr_dependencies_1549_offline.py"
        for arg in ("--authorize", "--merge", "--help", "--release", "unused"):
            with self.subTest(arg=arg):
                result = subprocess.run([sys.executable, "-I", "-S", "-B", str(script), arg],
                                        input=manifest(), capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stderr, b"")
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["waves"], [])
                self.assertTrue(all(receipt[k] is False for k in OFF_FLAGS))

    def test_real_child_process_review_and_hold(self):
        script = ROOT / "scripts/review_scope_pr_dependencies_1549_offline.py"
        for data, status, code in ((manifest(), "REVIEW_ONLY", 3), (b"BAD", "HOLD", 2),
                                   (b"x"*(MAX_INPUT+200), "HOLD", 2)):
            with self.subTest(status=status, length=len(data)):
                result = subprocess.run([sys.executable, "-I", "-S", "-B", str(script)],
                                        input=data, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout.count(b"\n"), 1)
                self.assertEqual(json.loads(result.stdout)["status"], status)
                self.assertTrue(all(json.loads(result.stdout)[key] is False for key in OFF_FLAGS))


if __name__ == "__main__":
    unittest.main()
