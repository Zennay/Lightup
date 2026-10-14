"""#1424: genuine opt-in atomic offline lab literal batch safety tests."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import TestCase, main, mock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT / "src"))

from review_scope_lab_batch_1424_offline import main as batch_cli_main, review_batch_json


_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)
_SCRIPT = _ROOT / "scripts" / "review_scope_lab_batch_1424_offline.py"


def _raw(literals) -> bytes:
    return json.dumps({"literals": literals}, separators=(",", ":")).encode("utf-8")


class OfflineLabBatchReviewTests(TestCase):
    def assert_batch(self, data, status: str, count: int):
        actual = review_batch_json(data)
        self.assertIs(type(actual), tuple)
        self.assertEqual(actual, (status, count))
        return actual

    def test_valid_single_and_mixed_family_review_only(self):
        groups = (
            ["127.0.0.1"],
            ["::1"],
            ["10.0.0.1", "172.31.255.254", "192.168.1.2"],
            ["127.0.0.2", "fd00::1", "10.0.0.1", "::1"],
            [f"10.0.0.{i}" for i in range(1, 17)],
        )
        for group in groups:
            with self.subTest(group=group):
                self.assert_batch(_raw(group), "REVIEW_ONLY", len(group))

    def test_single_bad_member_invalidates_entire_batch_no_partial_success(self):
        for bad in (
            "8.8.8.8", "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "169.254.1.1", "198.18.0.1", "100.64.0.1", "::",
            "2001:db8::1", "fe80::1", "ff02::1",
            "::ffff:192.168.1.2", "FD00::1", "[fd00::1]",
            "10.0.0.1/8", "10.0.0.1:443", "localhost", "10.0.0.1 ",
            "http://10.0.0.1", "", "010.0.0.1",
        ):
            with self.subTest(bad=bad):
                self.assert_batch(_raw(["10.0.0.1", bad, "127.0.0.1"]), "HOLD", 0)

    def test_outer_block_edges_force_atomic_hold_no_partial_review(self):
        edge_literals = (
            "127.0.0.0", "127.255.255.255",
            "10.0.0.0", "10.255.255.255",
            "172.16.0.0", "172.31.255.255",
            "192.168.0.0", "192.168.255.255",
            "fc00::",
        )
        for edge in edge_literals:
            with self.subTest(edge=edge):
                self.assert_batch(_raw(["10.0.0.1", edge, "fd00::1"]), "HOLD", 0)
        self.assert_batch(
            _raw(["10.0.0.1", "127.0.0.1", "fd00::1"]),
            "REVIEW_ONLY", 3,
        )

    def test_duplicate_representations_and_limits_are_hold(self):
        groups = (
            [],
            ["10.0.0.1", "10.0.0.1"],
            ["::1", "::1"],
            ["10.0.0.1"] * 16,
            [f"10.0.0.{i}" for i in range(1, 18)],
            ["10.0.0.1", 0],
            ["10.0.0.1", False],
            ["10.0.0.1", None],
            ["10.0.0.1", {"literal": "10.0.0.2"}],
        )
        for group in groups:
            with self.subTest(group=str(group)[:120]):
                self.assert_batch(_raw(group), "HOLD", 0)

    def test_json_duplicate_keys_nonfinite_and_untrusted_shapes_hold(self):
        raw_cases = (
            b"",
            b"\xff\xfe",
            b"{",
            b"{}",
            b"[]",
            b"null",
            b'{"literals":"10.0.0.1"}',
            b'{"literals":[10]}',
            b'{"literals":[NaN]}',
            b'{"literals":[Infinity]}',
            b'{"literals":[-Infinity]}',
            b'{"literals":["10.0.0.1"],"literals":["127.0.0.1"]}',
            b'{"literals":["10.0.0.1"],"permission":true}',
            b'{"literals":["10.0.0.1"]}{"literals":["127.0.0.1"]}',
            b'{"literals":["10.0.0.1"]}\x00',
            b'{"literals":["10.0.0.1"],"ignored":{"x":1,"x":2}}',
            b" " * 4097,
            _raw(["10.0.0.1"]) + b" " * 4096,
            b'{"literals":[["10.0.0.1"]]}',
        )
        for raw in raw_cases:
            with self.subTest(size=len(raw), preview=repr(raw[:60])):
                self.assert_batch(raw, "HOLD", 0)

    def test_exact_bounded_input_byte_boundary(self):
        raw = _raw(["10.0.0.1"])
        self.assertLess(len(raw), 4096)
        padded = raw + b" " * (4096 - len(raw))
        self.assertEqual(len(padded), 4096)
        self.assert_batch(padded, "REVIEW_ONLY", 1)
        self.assert_batch(padded + b" ", "HOLD", 0)

    def test_direct_main_rejects_polymorphic_argv_before_reading_stdin(self):
        class FakeStr(str):
            def __eq__(self, _other):
                raise AssertionError("untrusted argv comparison")

        class Spy:
            @property
            def buffer(self):
                raise AssertionError("stdin must not be read without opt-in")

        for args in (
            (), ("--stdin-json",), ["--stdin-json", "--stdin-json"],
            [FakeStr("--stdin-json")], [False], [None],
            [object()], [1], [], ["--unrelated"],
        ):
            with self.subTest(type=type(args).__name__, length=len(args)):
                output = io.StringIO()
                with mock.patch("sys.stdout", output), mock.patch("sys.stdin", Spy()):
                    code = batch_cli_main(args)
                self.assertEqual(code, 2)
                receipt = json.loads(output.getvalue())
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reviewed_count"], 0)
                for key in _FLAGS:
                    self.assertIs(receipt[key], False, key)

    def test_direct_main_reads_only_bounded_bytes_under_explicit_optin(self):
        raw = _raw(["10.0.0.1", "fd00::1"])

        class TrackedBuffer(io.BytesIO):
            def __init__(self, value):
                super().__init__(value)
                self.read_limits = []

            def read(self, limit=-1):
                self.read_limits.append(limit)
                return super().read(limit)

        class FakeStdin:
            def __init__(self, value):
                self.buffer = TrackedBuffer(value)

        for data, expected_status, expected_exit in (
            (raw, "REVIEW_ONLY", 3),
            (raw + b" " * 4097, "HOLD", 2),
        ):
            with self.subTest(length=len(data)):
                stream = FakeStdin(data)
                output = io.StringIO()
                with mock.patch("sys.stdout", output), mock.patch("sys.stdin", stream):
                    code = batch_cli_main(["--stdin-json"])
                self.assertEqual(code, expected_exit)
                self.assertEqual(stream.buffer.read_limits, [4097])
                receipt = json.loads(output.getvalue())
                self.assertEqual(receipt["status"], expected_status)
                for key in _FLAGS:
                    self.assertIs(receipt[key], False, key)

    def test_nonbyte_spoofs_never_call_user_getters(self):
        class FakeBytes(bytes):
            def decode(self, *args, **kwargs):
                raise AssertionError("must not call untrusted decode")

        class Spoof:
            def __len__(self):
                raise AssertionError("must not call untrusted len")
            def __bool__(self):
                raise AssertionError("must not call untrusted truthiness")

        for raw in (True, False, None, "", 0, [], {}, FakeBytes(_raw(["10.0.0.1"])), Spoof()):
            with self.subTest(type=type(raw).__name__):
                self.assert_batch(raw, "HOLD", 0)

    def test_no_dns_network_disk_or_process_in_live_batch_review(self):
        with (
            mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS")) as dns,
            mock.patch("socket.socket", side_effect=AssertionError("socket")) as sock,
            mock.patch("builtins.open", side_effect=AssertionError("disk")) as op,
            mock.patch("os.system", side_effect=AssertionError("system")) as system,
            mock.patch("subprocess.run", side_effect=AssertionError("process")) as process,
        ):
            self.assert_batch(_raw(["10.0.0.1", "::1"]), "REVIEW_ONLY", 2)
            self.assert_batch(_raw(["10.0.0.1", "192.0.2.1"]), "HOLD", 0)
            dns.assert_not_called()
            sock.assert_not_called()
            op.assert_not_called()
            system.assert_not_called()
            process.assert_not_called()

    def test_real_cli_valid_and_invalid_receipts_never_authorize_or_leak(self):
        self.assertTrue(_SCRIPT.is_file())
        cases = (
            (["--stdin-json"], _raw(["10.0.0.1", "fd00::1"]), 3, "REVIEW_ONLY", 2),
            (["--stdin-json"], _raw(["127.0.0.1"]), 3, "REVIEW_ONLY", 1),
            (["--stdin-json"], _raw(["10.0.0.1", "192.0.2.1"]), 2, "HOLD", 0),
            (["--stdin-json"], b'{"literals":[NaN]}', 2, "HOLD", 0),
            (["--stdin-json"], b'{"literals":["10.0.0.1"],"literals":["127.0.0.1"]}', 2, "HOLD", 0),
            (["--stdin-json"], _raw(["10.0.0.1"]) + b" " * 4096, 2, "HOLD", 0),
            ([], _raw(["10.0.0.1"]), 2, "HOLD", 0),
            (["--stdin-json", "--stdin-json"], _raw(["10.0.0.1"]), 2, "HOLD", 0),
            (["--literal", "synthetic-secret-CLI"], _raw(["10.0.0.1"]), 2, "HOLD", 0),
        )
        for args, payload, code, status, count in cases:
            with self.subTest(args=args, status=status, length=len(payload)):
                result = subprocess.run(
                    [sys.executable, "-B", str(_SCRIPT), *args],
                    input=payload, capture_output=True, timeout=15, check=False,
                    env=dict(os.environ, PYTHONNOUSERSITE="1"),
                )
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout.count(b"\n"), 1)
                self.assertEqual(len(result.stdout), len(result.stdout.strip()) + 1)
                receipt = json.loads(result.stdout)
                self.assertEqual(set(receipt), {"status", "reviewed_count", *_FLAGS})
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt["reviewed_count"], count)
                self.assertIs(type(receipt["reviewed_count"]), int)
                for key in _FLAGS:
                    self.assertIs(receipt[key], False, key)
                for secret in (b"10.0.0.1", b"192.0.2.1", b"fd00::1",
                               b"127.0.0.1", b"synthetic-secret-CLI", b"literals"):
                    self.assertNotIn(secret, result.stdout)
                    self.assertNotIn(secret, result.stderr)


if __name__ == "__main__":
    main()
