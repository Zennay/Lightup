"""Offline and real-subprocess non-authority regressions for #1429."""
from __future__ import annotations

import importlib.util
import itertools
import json
import os
from pathlib import Path
import subprocess
import stat
import tempfile
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scope_self_asserted_proof_hold_1429.py"
spec = importlib.util.spec_from_file_location("scope_self_asserted_proof_hold_1429", SCRIPT)
assert spec is not None and spec.loader is not None
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

SHA = "a" * 40
LANES = (
    "hosted_python_311",
    "hosted_python_314",
    "registered_vps",
    "installed_ingress",
)
FLAGS = ("authorized", "permit", "dispatch", "merge", "deploy", "release")
RECEIPT_KEYS = frozenset({
    "schema", "status", "input_integrity",
    "unverified_self_asserted_pass_claims", "verified_evidence", *FLAGS,
})
MAX_RECEIPT_BYTES = 512


def packet(**overrides):
    item = {
        "schema": review.INPUT_SCHEMA,
        "head": SHA,
        "claims": [{"lane": lane, "head": SHA, "result": "pass"} for lane in LANES],
    }
    item.update(overrides)
    return item


def encoded(item):
    return json.dumps(item, separators=(",", ":")).encode("utf-8")


class SelfAssertedProofHoldTests(unittest.TestCase):
    def check_hold(self, payload, *, coherent=False, passing=0):
        result = review.review_bytes(payload)
        self.assertEqual(result["schema"], review.OUTPUT_SCHEMA)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["input_integrity"], "COHERENT" if coherent else "REJECTED")
        self.assertEqual(result["unverified_self_asserted_pass_claims"], passing)
        self.assertIs(result["verified_evidence"], False)
        for name in FLAGS:
            self.assertIs(result[name], False)
        self.assertEqual(set(result), RECEIPT_KEYS, "unknown receipt fields risk leaking source data")
        self.assertEqual(type(result["unverified_self_asserted_pass_claims"]), int)
        self.assertEqual(type(result["verified_evidence"]), bool)
        for flag in FLAGS:
            self.assertEqual(type(result[flag]), bool)
        wire = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        self.assertLessEqual(len(wire), MAX_RECEIPT_BYTES)
        rendered = json.dumps(result)
        self.assertNotIn(SHA, rendered)
        self.assertNotIn("hosted_python_311", rendered)
        self.assertNotIn("installed_ingress", rendered)
        return result

    def test_complete_all_pass_is_still_hold(self):
        self.check_hold(encoded(packet()), coherent=True, passing=4)

    def test_partial_claimed_pass_is_coherent_but_unverified(self):
        item = packet()
        item["claims"][1]["result"] = "queued"
        item["claims"][2]["result"] = "cancelled"
        self.check_hold(encoded(item), coherent=True, passing=2)

    def test_claim_order_does_not_confer_authority(self):
        item = packet()
        item["claims"].reverse()
        self.check_hold(encoded(item), coherent=True, passing=4)

    def test_mixed_commit_sha_rejected_atomically(self):
        item = packet()
        item["claims"][2]["head"] = "b" * 40
        self.check_hold(encoded(item))

    def test_uppercase_or_short_sha_rejected(self):
        for head in ("A" * 40, "a" * 39, "0x" + SHA, True, 42):
            with self.subTest(head=repr(head)):
                self.check_hold(encoded(packet(head=head)))

    def test_missing_unknown_duplicate_lanes_rejected(self):
        missing = packet()
        missing["claims"].pop()
        unknown = packet()
        unknown["claims"][0]["lane"] = "production_release"
        duplicate = packet()
        duplicate["claims"][1]["lane"] = duplicate["claims"][0]["lane"]
        for value in (missing, unknown, duplicate):
            with self.subTest(value=value):
                self.check_hold(encoded(value))

    def test_noncanonical_value_types_rejected(self):
        values = (
            {"claims": [*packet()["claims"][:3], {"lane": LANES[3], "head": SHA, "result": True}]},
            {"claims": "fake"},
            {"schema": True},
            {"head": ["a"] * 40},
        )
        for edit in values:
            with self.subTest(edit=edit):
                self.check_hold(encoded(packet(**edit)))

    def test_extraneous_authorization_fields_rejected(self):
        value = packet(approved=True, release=True, customer_token="SECRET-SENTINEL")
        self.check_hold(encoded(value))

    def test_duplicate_json_keys_at_any_level_rejected(self):
        raw = encoded(packet()).decode("utf-8")
        at_top = raw.replace('"schema":', '"schema":"forged","schema":', 1)
        nested = raw.replace('"result":', '"result":"pass","result":', 1)
        for case in (at_top, nested):
            with self.subTest(case=case[:40]):
                self.check_hold(case.encode())

    def test_nonfinite_invalid_json_and_utf8_rejected(self):
        for case in (b"NaN", b"Infinity", b"-Infinity", b"{", b"\xff", b"\xef\xbb\xbf" + encoded(packet())):
            with self.subTest(case=case[:30]):
                self.check_hold(case)

    def test_byte_boundary_accepts_bounded_valid_claims(self):
        self.assertLess(len(encoded(packet())), review.MAX_STDIN_BYTES)
        self.check_hold(encoded(packet()), coherent=True, passing=4)
        self.check_hold(b" " * (review.MAX_STDIN_BYTES + 1))

    def test_unknown_nested_shape_and_list_rejected(self):
        item = packet()
        item["claims"][0]["extra"] = "anything"
        self.check_hold(encoded(item))
        self.check_hold(encoded([packet()]))

    def test_no_ambient_network_or_file_reads_from_direct_review(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")), \
             patch("builtins.open", side_effect=AssertionError("file attempted")), \
             patch("subprocess.Popen", side_effect=AssertionError("process attempted")):
            self.check_hold(encoded(packet()), coherent=True, passing=4)

    def cli(self, payload, args=("--stdin-json",)):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *args],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_real_cli_success_claims_still_exit_2(self):
        child = self.cli(encoded(packet()))
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assertEqual(child.stderr, b"")
        self.assertEqual(child.stdout.count(b"\n"), 1)
        self.assertEqual(json.loads(child.stdout)["unverified_self_asserted_pass_claims"], 4)
        self.assertEqual(json.loads(child.stdout)["status"], "HOLD")

    def test_real_cli_bad_args_do_not_read_or_echo_stdin(self):
        for args in ((), ("--stdin-json", "--release"), ("--release",), ("--stdin-json", "--stdin-json")):
            with self.subTest(args=args):
                child = self.cli(b"PRIVATE-CREDENTIAL-SENTINEL", args)
                self.assertEqual(child.returncode, 2)
                self.assertNotIn(b"PRIVATE-CREDENTIAL-SENTINEL", child.stdout + child.stderr)
                self.assertEqual(json.loads(child.stdout)["input_integrity"], "REJECTED")

    def test_real_cli_overlimit_holds_without_leaking_data(self):
        child = self.cli(b"SECRET-" + b"x" * (review.MAX_STDIN_BYTES + 1))
        self.assertEqual(child.returncode, 2)
        self.assertEqual(json.loads(child.stdout)["input_integrity"], "REJECTED")
        self.assertNotIn(b"SECRET", child.stdout + child.stderr)

    def test_real_cli_invalid_utf8_no_traceback(self):
        child = self.cli(b'{"claims":"SECRET-\xff"}')
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")
        self.assertNotIn(b"SECRET", child.stdout)


    def _cli_with_unclosed_writer(self, data, args=("--stdin-json",)):
        """Exercise a real child without hiding the EOF requirement in run()."""
        proc = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            if data:
                proc.stdin.write(data)
                proc.stdin.flush()
            # Deliberately do NOT close the writing end. The reviewer must
            # fail closed on timeout/over-budget even without producer EOF.
            code = proc.wait(timeout=8)
            output = proc.stdout.read()
            errors = proc.stderr.read()
            return code, output, errors
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe:
                    pipe.close()

    def test_real_cli_stalled_partial_stdin_exits_hold_without_echo(self):
        code, output, errors = self._cli_with_unclosed_writer(b"SECRET-PARTIAL-PACKET")
        self.assertEqual(code, 2)
        self.assertEqual(errors, b"")
        self.assertNotIn(b"SECRET", output)
        self.assertEqual(json.loads(output)["input_integrity"], "REJECTED")

    def test_real_cli_full_json_without_eof_is_not_accepted(self):
        code, output, errors = self._cli_with_unclosed_writer(encoded(packet()))
        self.assertEqual(code, 2)
        self.assertEqual(errors, b"")
        self.assertEqual(json.loads(output)["input_integrity"], "REJECTED")
        self.assertEqual(json.loads(output)["unverified_self_asserted_pass_claims"], 0)

    def test_real_cli_unclosed_oversized_stream_aborts_without_echo(self):
        code, output, errors = self._cli_with_unclosed_writer(b"SECRET-" + b"x" * review.MAX_STDIN_BYTES)
        self.assertEqual(code, 2)
        self.assertEqual(errors, b"")
        self.assertNotIn(b"SECRET", output)
        self.assertEqual(json.loads(output)["input_integrity"], "REJECTED")

    def test_real_cli_invalid_argv_never_waits_for_stdin_eof(self):
        code, output, errors = self._cli_with_unclosed_writer(b"", args=("--release",))
        self.assertEqual(code, 2)
        self.assertEqual(errors, b"")
        self.assertEqual(json.loads(output)["input_integrity"], "REJECTED")

    def test_real_cli_split_valid_stdin_requires_eof(self):
        payload = encoded(packet())
        proc = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            midpoint = len(payload) // 2
            proc.stdin.write(payload[:midpoint])
            proc.stdin.flush()
            proc.stdin.write(payload[midpoint:])
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=8), 2)
            output, errors = proc.stdout.read(), proc.stderr.read()
            self.assertEqual(errors, b"")
            self.assertEqual(json.loads(output)["input_integrity"], "COHERENT")
            self.assertEqual(json.loads(output)["unverified_self_asserted_pass_claims"], 4)
            self.assertIs(json.loads(output)["release"], False)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe and not pipe.closed:
                    pipe.close()

    def test_all_625_self_asserted_status_combinations_remain_hold(self):
        """Every possible four-lane label combination remains non-authority."""
        results = ("pass", "fail", "queued", "cancelled", "unknown")
        reviewed = 0
        for choices in itertools.product(results, repeat=4):
            value = packet()
            for claim, status in zip(value["claims"], choices):
                claim["result"] = status
            self.check_hold(encoded(value), coherent=True, passing=choices.count("pass"))
            reviewed += 1
        self.assertEqual(reviewed, 625)

    def test_exact_16k_payload_boundary_and_plus_one(self):
        valid = encoded(packet())
        exact = valid + b" " * (review.MAX_STDIN_BYTES - len(valid))
        self.assertEqual(len(exact), 16384)
        self.check_hold(exact, coherent=True, passing=4)
        self.check_hold(exact + b" ")

    def test_smuggled_multiple_json_objects_and_unicode_aliases_rejected(self):
        valid = encoded(packet())
        cases = (
            valid + valid,
            valid + b" {}",
            valid + b"\x00",
            valid.replace(b'"head":', b'"he\\u0061d":' + b'"' + SHA.encode() + b'","head":', 1),
            valid.replace(b'"lane":', b'"lan\\u0435":', 1),
            valid.replace(b'"pass"', b'1e999', 1),
            valid.replace(b'"pass"', b'true', 1),
        )
        for case in cases:
            with self.subTest(case=repr(case[:60])):
                self.check_hold(case)

    def test_reader_rejects_spoofed_nonstdin_file_descriptor(self):
        from unittest.mock import MagicMock
        fake = MagicMock()
        fake.fileno.return_value = 7
        with patch.object(review.sys, "stdin", fake), \
             patch.object(review.select, "select", side_effect=AssertionError("selected alien fd")), \
             patch.object(review.os, "read", side_effect=AssertionError("read alien fd")):
            self.assertEqual(review._read_bounded_stdin(), b"")


    def test_reader_rejects_non_pipe_descriptor_kinds_before_read(self):
        from unittest.mock import MagicMock
        fake_stdin = MagicMock()
        fake_stdin.fileno.return_value = 0
        for mode in (stat.S_IFSOCK, stat.S_IFREG, stat.S_IFDIR, stat.S_IFCHR, stat.S_IFBLK):
            with self.subTest(mode=mode), \
                 patch.object(review.sys, "stdin", fake_stdin), \
                 patch.object(review.os, "fstat", return_value=MagicMock(st_mode=mode)), \
                 patch.object(review.select, "select", side_effect=AssertionError("selected non-pipe")), \
                 patch.object(review.os, "read", side_effect=AssertionError("read non-pipe")):
                self.assertEqual(review._read_bounded_stdin(), b"")

    def test_real_cli_regular_file_stdin_does_not_read_synthetic_secret(self):
        payload = encoded(packet())
        with tempfile.TemporaryFile(mode="w+b") as file:
            file.write(payload + b"SECRET-TAIL")
            file.flush()
            file.seek(0)
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                stdin=file, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(file.tell(), 0, "the inherited regular fd must not be read")
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")
        self.assertEqual(json.loads(child.stdout)["input_integrity"], "REJECTED")
        self.assertNotIn(SHA.encode(), child.stdout)
        self.assertNotIn(b"SECRET", child.stdout)

    @unittest.skipUnless(hasattr(socket, "socketpair"), "local Unix socketpair unavailable")
    def test_real_cli_unix_socket_stdin_refused_without_socket_read(self):
        # This is a synthetic local AF_UNIX descriptor, no remote traffic.
        sender, receiver = socket.socketpair()
        try:
            sender.sendall(encoded(packet()))
            sender.shutdown(socket.SHUT_WR)
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                stdin=receiver, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(child.returncode, 2)
            self.assertEqual(child.stderr, b"")
            self.assertEqual(json.loads(child.stdout)["input_integrity"], "REJECTED")
            # Parent's peer data remains unread because the child rejected fd0.
            self.assertEqual(receiver.recv(1, socket.MSG_PEEK), encoded(packet())[:1])
        finally:
            receiver.close()
            sender.close()


    def test_real_cli_single_ascii_receipt_with_no_raw_claim_details(self):
        cases = (
            encoded(packet()),
            encoded(packet(extra_secret="my-example-token", approved=True)),
            b"INVALID-SECRET" + b"x" * 200,
            encoded(packet()).replace(b'"pass"', b'"pass\u000aSECRET-TOKEN"', 1),
        )
        for payload in cases:
            with self.subTest(payload_length=len(payload)):
                child = self.cli(payload)
                self.assertEqual(child.returncode, 2)
                self.assertEqual(child.stderr, b"")
                self.assertEqual(child.stdout.count(b"\n"), 1)
                self.assertLessEqual(len(child.stdout), MAX_RECEIPT_BYTES)
                result = json.loads(child.stdout.decode("ascii"))
                self.assertEqual(set(result), RECEIPT_KEYS)
                self.assertEqual(result["status"], "HOLD")
                self.assertIs(result["verified_evidence"], False)
                for key in FLAGS:
                    self.assertIs(result[key], False)
                self.assertNotIn(b"SECRET", child.stdout)
                self.assertNotIn(SHA.encode(), child.stdout)


    def test_receipt_sender_rejects_non_stdout_fd_without_writes(self):
        from unittest.mock import MagicMock
        fake = MagicMock()
        fake.fileno.return_value = 4
        with patch.object(review.sys, "stdout", fake), \
             patch.object(review.os, "write", side_effect=AssertionError("wrote alien fd")), \
             patch.object(review.os, "fstat", side_effect=AssertionError("stat alien fd")):
            self.assertIsNone(review._emit_hold_receipt(b"{}\\n"))

    def test_receipt_sender_disallows_regular_socket_and_directory(self):
        from unittest.mock import MagicMock
        fake = MagicMock()
        fake.fileno.return_value = 1
        for mode in (stat.S_IFREG, stat.S_IFSOCK, stat.S_IFDIR, stat.S_IFBLK):
            with self.subTest(mode=mode), \
                 patch.object(review.sys, "stdout", fake), \
                 patch.object(review.os, "fstat", return_value=MagicMock(st_mode=mode)), \
                 patch.object(review.os, "set_blocking", side_effect=AssertionError("modified descriptor")), \
                 patch.object(review.os, "write", side_effect=AssertionError("wrote to forbidden sink")):
                self.assertIsNone(review._emit_hold_receipt(b"{}\\n"))

    def test_receipt_sender_rejects_more_than_512_bytes_without_touching_fd(self):
        from unittest.mock import MagicMock
        fake = MagicMock()
        fake.fileno.side_effect = AssertionError("should not access stdout")
        with patch.object(review.sys, "stdout", fake):
            self.assertIsNone(review._emit_hold_receipt(b"Q" * (review.MAX_RECEIPT_BYTES + 1)))
            self.assertIsNone(review._emit_hold_receipt(b""))

    def test_real_cli_refuses_stdout_regular_file_without_writing(self):
        with tempfile.TemporaryFile(mode="w+b") as sink:
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encoded(packet()), stdout=sink, stderr=subprocess.PIPE,
                timeout=8, check=False,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(sink.tell(), 0)
            sink.seek(0)
            self.assertEqual(sink.read(), b"")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"")

    @unittest.skipUnless(hasattr(socket, "socketpair"), "local Unix socketpair unavailable")
    def test_real_cli_refuses_stdout_unix_socket_without_transmitting(self):
        sender, receiver = socket.socketpair()
        try:
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encoded(packet()), stdout=receiver, stderr=subprocess.PIPE,
                timeout=8, check=False,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(child.returncode, 2)
            self.assertEqual(child.stderr, b"")
            sender.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                sender.recv(1)
        finally:
            receiver.close()
            sender.close()

    @unittest.skipUnless(hasattr(os, "set_blocking"), "POSIX nonblocking fd unavailable")
    def test_real_cli_full_output_pipe_does_not_wait_forever(self):
        readfd, writefd = os.pipe()
        try:
            os.set_blocking(writefd, False)
            filled = 0
            while True:
                try:
                    filled += os.write(writefd, b"Q" * 4096)
                except BlockingIOError:
                    break
            self.assertGreater(filled, 0)
            started = __import__("time").monotonic()
            proc = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encoded(packet()), stdout=writefd, stderr=subprocess.PIPE,
                timeout=8, check=False,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            elapsed = __import__("time").monotonic() - started
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr, b"")
            self.assertLess(elapsed, 6, "stalled receiver must not trap the child")
        finally:
            os.close(writefd)
            os.close(readfd)


    def test_receipt_sender_rejects_character_device_without_tty(self):
        from unittest.mock import MagicMock
        fake = MagicMock()
        fake.fileno.return_value = 1
        with patch.object(review.sys, "stdout", fake), \
             patch.object(review.os, "fstat", return_value=MagicMock(st_mode=stat.S_IFCHR)), \
             patch.object(review.os, "isatty", return_value=False) as tty_check, \
             patch.object(review.os, "set_blocking", side_effect=AssertionError("set blocked char")), \
             patch.object(review.os, "write", side_effect=AssertionError("wrote to char device")):
            self.assertIsNone(review._emit_hold_receipt(b"{}"))
            tty_check.assert_called_once_with(1)

    def test_real_cli_devnull_output_refused_and_exit_hold(self):
        child = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            input=encoded(packet()), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=8, check=False,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")


if __name__ == "__main__":
    unittest.main()
