"""Hermetic subprocess regression for a non-authorizing #931 review utility."""
from __future__ import annotations

import ast
import json
import os
import pathlib
import pty
import random
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts" / "scope_931_synthetic_identity_intake_20261016.py"
)
FALSE_FLAGS = {"authorization", "permit", "dispatch", "scan", "deploy", "release"}


class SyntheticIdentityIntakeCliTest(unittest.TestCase):
    def run_cli(self, raw: bytes, *argv: str):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), *argv],
            input=raw, capture_output=True, timeout=8, check=False,
        )
        self.assertEqual(proc.stderr, b"")
        obj = json.loads(proc.stdout)
        self.assertEqual(set(obj), FALSE_FLAGS | {"status"})
        self.assertTrue(all(obj[key] is False for key in FALSE_FLAGS))
        self.assertEqual(proc.stdout, (
            json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8"))
        self.assertIn(proc.returncode, (2, 3))
        self.assertIn(obj["status"], ("HOLD", "REVIEW_ONLY"))
        return proc.returncode, obj["status"], proc.stdout

    def assert_receipt(self, raw: bytes, status="HOLD"):
        exit_code, found, _ = self.run_cli(raw, "--offline-synthetic-only")
        self.assertEqual((exit_code, found), (3, "REVIEW_ONLY") if
                         status == "REVIEW_ONLY" else (2, "HOLD"))

    def test_offline_reviewer_imports_remain_allowlisted(self):
        """Make future network, LightUp, reflection, or CLI framework imports loud."""
        source = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        allowed = {"__future__", "json", "os", "select", "stat",
                   "sys", "time", "unicodedata"}
        discovered = []
        for node in ast.walk(source):
            if isinstance(node, ast.Import):
                discovered.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertTrue(node.module)
                self.assertTrue(all(alias.name != "*" for alias in node.names))
                discovered.append(node.module)
        self.assertEqual(set(discovered), allowed)
        self.assertEqual(len(discovered), len(allowed))

    def test_offline_reviewer_does_not_gain_dynamic_execution_or_os_capabilities(self):
        """Static tripwire only, not a runtime security sandbox."""
        source = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        forbidden_calls = {
            "eval", "exec", "compile", "__import__", "open", "input",
            "breakpoint",
        }
        allowed_os = {"fstat", "read", "write", "readlink"}
        allowed_sys = {"stdin", "stdout", "argv"}
        for node in ast.walk(source):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, forbidden_calls)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "os":
                    self.assertIn(node.attr, allowed_os)
                elif node.value.id == "sys":
                    self.assertIn(node.attr, allowed_sys)
        self.assertNotIn("http://", SCRIPT.read_text(encoding="utf-8"))
        self.assertNotIn("https://", SCRIPT.read_text(encoding="utf-8"))

    def test_valid_exact_shape_never_grants_authority(self):
        self.assert_receipt(
            b'{"prospect_id":"sample-1","organization_name":"Example Fiction"}',
            "REVIEW_ONLY",
        )

    def test_unicode_letters_allowed_without_normalization_claim(self):
        self.assert_receipt(json.dumps(
            {"prospect_id": "Fiktion-1", "organization_name": "Société Étoile"},
            ensure_ascii=False,
        ).encode("utf-8"), "REVIEW_ONLY")

    def test_nonblank_padding_not_trimmed_or_echoed(self):
        private = b'{"prospect_id":"  fictional-id  ","organization_name":" Example "}'
        code, status, stdout = self.run_cli(private, "--offline-synthetic-only")
        self.assertEqual((code, status), (3, "REVIEW_ONLY"))
        self.assertNotIn(b"fictional-id", stdout)
        self.assertNotIn(b"Example", stdout)

    def test_missing_extra_and_case_changed_keys_hold(self):
        records = (
            {}, {"prospect_id": "x"}, {"organization_name": "y"},
            {"prospect_id": "x", "organization_name": "y", "approved": True},
            {"Prospect_id": "x", "organization_name": "y"},
            {"prospect_id": "x", "organization_name": "y", "__proto__": "z"},
        )
        for record in records:
            with self.subTest(keys=tuple(record)):
                self.assert_receipt(json.dumps(record).encode("utf-8"))

    def test_non_string_identity_types_hold(self):
        poison = (None, True, False, 0, 1, 1.5, [], {}, ["x"])
        for key in ("prospect_id", "organization_name"):
            for value in poison:
                with self.subTest(key=key, value=value):
                    obj = {"prospect_id": "x", "organization_name": "y"}
                    obj[key] = value
                    self.assert_receipt(json.dumps(obj).encode("utf-8"))

    def test_empty_and_whitespace_only_hold(self):
        for key in ("prospect_id", "organization_name"):
            for val in ("", " ", " \t\n", "\u2002\u2003", "\r"):
                with self.subTest(key=key, val=repr(val)):
                    obj = {"prospect_id": "x", "organization_name": "y"}
                    obj[key] = val
                    self.assert_receipt(json.dumps(obj).encode("utf-8"))

    def test_bidi_zero_width_nul_and_controls_hold(self):
        for bad in ("A\u202eB", "A\u200bB", "A\x00B", "A\nB", "\ud800"):
            for key in ("prospect_id", "organization_name"):
                with self.subTest(key=key, bad=repr(bad)):
                    obj = {"prospect_id": "x", "organization_name": "y"}
                    obj[key] = bad
                    self.assert_receipt(json.dumps(obj).encode("utf-8"))

    def test_non_nfc_equivalent_identities_hold_without_rewriting(self):
        import unicodedata
        nfc = "Café Fiction"
        nfd = unicodedata.normalize("NFD", nfc)
        self.assertNotEqual(nfc, nfd)
        for key in ("prospect_id", "organization_name"):
            for raw_identity, expected in ((nfc, "REVIEW_ONLY"), (nfd, "HOLD")):
                with self.subTest(key=key, identity=repr(raw_identity)):
                    obj = {"prospect_id": "synthetic", "organization_name": "Fiction"}
                    obj[key] = raw_identity
                    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                    self.assert_receipt(raw, expected)

    def test_nfkc_compatibility_lookalikes_hold_in_both_identity_fields(self):
        """An NFKC alias is not the same proven legal person or prospect."""
        import unicodedata
        examples = ("Ａ", "①", "ﬃ", "𝓐", "Ⅳ", "²", "㍿")
        for lookalike in examples:
            self.assertTrue(unicodedata.is_normalized("NFC", lookalike))
            self.assertFalse(unicodedata.is_normalized("NFKC", lookalike))
            for key in ("prospect_id", "organization_name"):
                with self.subTest(key=key, glyph=hex(ord(lookalike))):
                    payload = {"prospect_id": "Fiction-1", "organization_name": "Fiction"}
                    payload[key] = "Fiction-" + lookalike
                    for ensure_ascii in (True, False):
                        self.assert_receipt(
                            json.dumps(payload, ensure_ascii=ensure_ascii)
                            .encode("utf-8"),
                            "HOLD",
                        )

    def test_canonical_noncompatibility_unicode_stays_review_only(self):
        """Do not accidentally deny ordinary accented fictional names."""
        import unicodedata
        for spelling in ("Café Fiction", "Fiktion-Å", "Αθήνα", "東京", "Zoë"):
            with self.subTest(spelling=spelling):
                self.assertTrue(unicodedata.is_normalized("NFKC", spelling))
                payload = {"prospect_id": spelling, "organization_name": spelling}
                self.assert_receipt(json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                    "REVIEW_ONLY")

    def test_compatibility_alias_cannot_be_reflected_or_normalized_into_receipt(self):
        """Receipt remains an opaque HOLD, never a rewritten identity."""
        payload = {"prospect_id": "SECRET-Ａ", "organization_name": "PRIVATE-①"}
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        code, verdict, body = self.run_cli(raw, "--offline-synthetic-only")
        self.assertEqual((code, verdict), (2, "HOLD"))
        self.assertNotIn(b"SECRET", body)
        self.assertNotIn(b"PRIVATE", body)
        self.assertNotIn(b"Fiction", body)

    def test_invisible_unicode_noncharacters_hold_for_both_fields(self):
        for scalar in (0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF,
                       0x1FFFE, 0x2FFFF, 0x10FFFF):
            for key in ("prospect_id", "organization_name"):
                with self.subTest(key=key, scalar=hex(scalar)):
                    obj = {"prospect_id": "x", "organization_name": "y"}
                    obj[key] = "A" + chr(scalar) + "B"
                    # Escaped JSON code units may decode to supplementary scalars.
                    self.assert_receipt(json.dumps(obj).encode("ascii"))

    def test_line_and_paragraph_separators_hold_without_receipt_echo(self):
        for symbol in ("\u2028", "\u2029"):
            for key in ("prospect_id", "organization_name"):
                with self.subTest(symbol=hex(ord(symbol)), key=key):
                    obj = {"prospect_id": "x", "organization_name": "y"}
                    obj[key] = "VISIBLE" + symbol + "PRIVATE"
                    code, status, out = self.run_cli(
                        json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                        "--offline-synthetic-only",
                    )
                    self.assertEqual((code, status), (2, "HOLD"))
                    self.assertNotIn(b"PRIVATE", out)

    def test_malformed_nested_duplicate_json_never_gains_authority(self):
        raw = (
            b'{"prospect_id":"synthetic","organization_name":"fiction",'
            b'"nested":{"authorization":true,"authorization":false}}'
        )
        self.assert_receipt(raw)
        for sep in (b' ', b'\n', b'\t'):
            with self.subTest(sep=sep):
                self.assert_receipt(
                    b'{"prospect_id":"synthetic","organization_name":"fiction"}'
                    + sep + b'{"authorization":true}'
                )

    def test_raw_input_ceiling_is_exact_even_for_whitespace(self):
        base = b'{"prospect_id":"x","organization_name":"y"}'
        valid = base + b" " * (4096 - len(base))
        self.assertEqual(len(valid), 4096)
        self.assert_receipt(valid, "REVIEW_ONLY")
        self.assert_receipt(valid + b" ")

    def test_duplicate_keys_even_escaped_aliases_hold(self):
        samples = (
            b'{"prospect_id":"A","prospect_id":"B","organization_name":"y"}',
            b'{"prospect_id":"A","\\u0070rospect_id":"B","organization_name":"y"}',
            b'{"prospect_id":"x","organization_name":"A","organization_name":"B"}',
        )
        for case in samples:
            with self.subTest(case=case):
                self.assert_receipt(case)

    def test_nonfinite_malformed_utf8_and_partial_json_hold(self):
        corpus = (
            b"", b"not json", b"null", b"[]", b"{}{}",
            b'{"prospect_id":"x","organization_name":NaN}',
            b'{"prospect_id":"x","organization_name":Infinity}',
            b'{"prospect_id":"x","organization_name":"y"',
            b'{"prospect_id":"\xff","organization_name":"y"}',
            b'{"prospect_id":"x","organization_name":"y"}\x00',
        )
        for raw in corpus:
            with self.subTest(raw=raw[:32]):
                self.assert_receipt(raw)

    def test_independent_length_ceiling_both_fields(self):
        for key, limit in (("prospect_id", 128), ("organization_name", 256)):
            obj = {"prospect_id": "x", "organization_name": "y"}
            obj[key] = "A" * limit
            self.assert_receipt(json.dumps(obj).encode("utf-8"), "REVIEW_ONLY")
            obj[key] += "A"
            self.assert_receipt(json.dumps(obj).encode("utf-8"))

    def test_oversize_input_holds_without_echo(self):
        raw = json.dumps(
            {"prospect_id": "SECRET-ID-" + "S" * 5000,
             "organization_name": "FICTIONAL PRIVATE CLIENT"}
        ).encode("utf-8")
        code, status, stdout = self.run_cli(raw, "--offline-synthetic-only")
        self.assertEqual((code, status), (2, "HOLD"))
        self.assertNotIn(b"SECRET", stdout)
        self.assertNotIn(b"FICTIONAL", stdout)

    def test_command_option_required_and_unknown_args_hold(self):
        raw = b'{"prospect_id":"x","organization_name":"y"}'
        for flags in ((), ("--help",), ("--allow-target",),
                      ("--offline-synthetic-only", "--deploy"),
                      ("--offline-synthetic-only", "--target", "example.test")):
            with self.subTest(flags=flags):
                code, status, _ = self.run_cli(raw, *flags)
                self.assertEqual((code, status), (2, "HOLD"))

    def test_receipt_never_exposes_input_or_error_text(self):
        secret = "FICTIONAL-NOT-FOR-OUTPUT-123456"
        raw = json.dumps({"prospect_id": secret,
                          "organization_name": "FICTIONAL-CLIENT-ID"}).encode()
        code, status, output = self.run_cli(raw, "--offline-synthetic-only")
        self.assertEqual((code, status), (3, "REVIEW_ONLY"))
        self.assertNotIn(secret.encode(), output)
        self.assertNotIn(b"FICTIONAL-CLIENT-ID", output)

    def test_deterministic_permutation_and_metameric_json(self):
        rng = random.Random(931)
        obj = {"prospect_id": "abc", "organization_name": "Example"}
        expected = None
        for _ in range(32):
            keys = list(obj)
            rng.shuffle(keys)
            raw = json.dumps({k: obj[k] for k in keys},
                             ensure_ascii=bool(rng.getrandbits(1))).encode()
            code, status, stdout = self.run_cli(raw, "--offline-synthetic-only")
            self.assertEqual((code, status), (3, "REVIEW_ONLY"))
            if expected is None:
                expected = stdout
            self.assertEqual(stdout, expected)

    def test_real_fragmented_stdin_is_equivalent_to_single_complete_document(self):
        raw = b'{"prospect_id":"synthetic","organization_name":"Fiction"}'
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for chunk in (raw[:8], raw[8:27], raw[27:]):
                proc.stdin.write(chunk)
                proc.stdin.flush()
            proc.stdin.close()
            proc.stdin = None
            stdout, stderr = proc.communicate(timeout=8)
            self.assertEqual((proc.returncode, stderr), (3, b""))
            self.assertEqual(json.loads(stdout)["status"], "REVIEW_ONLY")
            single_code, single_status, single_stdout = self.run_cli(
                raw, "--offline-synthetic-only"
            )
            self.assertEqual((single_code, single_status), (3, "REVIEW_ONLY"))
            self.assertEqual(stdout, single_stdout)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=3)

    def test_unclosed_partial_or_complete_pipe_fails_closed_on_deadline(self):
        for chunk in (b'{"prospect_id":"synthetic"', b'{"prospect_id":"x","organization_name":"Fiction"}'):
            with self.subTest(chunk=chunk[:18]):
                proc = subprocess.Popen(
                    [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    proc.stdin.write(chunk)
                    proc.stdin.flush()
                    proc.wait(timeout=6)  # stdin remains OPEN on purpose.
                    stdout, stderr = proc.stdout.read(), proc.stderr.read()
                    self.assertEqual((proc.returncode, stderr), (2, b""))
                    verdict = json.loads(stdout)
                    self.assertEqual(verdict["status"], "HOLD")
                    self.assertTrue(all(verdict[f] is False for f in FALSE_FLAGS))
                    self.assertNotIn(b"synthetic", stdout)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    proc.stdin.close()
                    proc.stdout.close()
                    proc.stderr.close()

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux procfs")
    def test_named_fifo_input_is_rejected_before_any_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            named = pathlib.Path(tmp) / "private-named-input"
            os.mkfifo(named, 0o600)
            fd = os.open(named, os.O_RDWR | os.O_NONBLOCK)
            try:
                # Even a complete document in a named FIFO is not an anonymous pipe.
                raw = b'{"prospect_id":"private","organization_name":"Fiction"}'
                os.write(fd, raw)
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                    stdin=fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=6, check=False,
                )
                self.assertEqual(
                    (proc.returncode, proc.stdout, proc.stderr), (2, b"", b"")
                )
                self.assertEqual(os.read(fd, len(raw)), raw)
            finally:
                os.close(fd)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux procfs")
    def test_named_fifo_output_is_rejected_without_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            named = pathlib.Path(tmp) / "private-named-output"
            os.mkfifo(named, 0o600)
            fd = os.open(named, os.O_RDWR | os.O_NONBLOCK)
            try:
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                    input=b'{"prospect_id":"x","organization_name":"y"}',
                    stdout=fd, stderr=subprocess.PIPE, timeout=6, check=False,
                )
                self.assertEqual((proc.returncode, proc.stderr), (2, b""))
                with self.assertRaises(BlockingIOError):
                    os.read(fd, 256)
            finally:
                os.close(fd)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux procfs")
    def test_pseudoterminal_output_is_rejected_without_receipt(self):
        master, slave = pty.openpty()
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                input=b'{"prospect_id":"x","organization_name":"y"}',
                stdout=slave, stderr=subprocess.PIPE, timeout=6, check=False,
            )
            self.assertEqual((proc.returncode, proc.stderr), (2, b""))
            os.set_blocking(master, False)
            with self.assertRaises(BlockingIOError):
                os.read(master, 256)
        finally:
            os.close(master)
            os.close(slave)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux pipe identity contract")
    def test_procfs_pipe_name_requires_exact_real_kernel_inode(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location("synthetic_review_inode", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        read_fd, write_fd = os.pipe()
        try:
            actual = os.fstat(read_fd).st_ino
            for forged in (
                "pipe:[" + str(actual + 1) + "]",
                "pipe:[" + str(actual) + "]-extra",
                "pipe:[" + str(actual).zfill(len(str(actual)) + 1) + "]extra",
                "pipe:[" + str(actual).zfill(len(str(actual)) + 1) + "]",
                "pipe:[ " + str(actual) + "]",
                "pipe:[" + str(actual) + " ]",
                "pipe:[" + str(actual) + "]\\n",
                "/tmp/pipe:[" + str(actual) + "]",
                "socket:[" + str(actual) + "]",
                "pipe:[+0]",
            ):
                with self.subTest(forged=forged):
                    with mock.patch.object(module.os, "readlink", return_value=forged):
                        self.assertFalse(module._anonymous_pipe(read_fd))
            with mock.patch.object(
                module.os, "readlink", return_value="pipe:[" + str(actual) + "]"
            ):
                self.assertTrue(module._anonymous_pipe(read_fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_procfs_identity_unavailable_is_hold_not_review(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location("synthetic_review", SCRIPT)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(
                module.os, "readlink", side_effect=OSError("procfs unavailable")
            ):
                self.assertFalse(module._anonymous_pipe(read_fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)
        # Do not print details of the simulated local procfs failure.
        _, status, receipt = self.run_cli(
            b'{"prospect_id":"x","organization_name":"y"}',
            "--offline-synthetic-only",
        )
        self.assertEqual(status, "REVIEW_ONLY")
        self.assertNotIn(b"procfs unavailable", receipt)

    def test_regular_file_stdin_is_rejected_before_read(self):
        with tempfile.TemporaryFile(mode="w+b") as source:
            source.write(
                b'{"prospect_id":"private-file","organization_name":"Fiction"}'
            )
            source.flush()
            source.seek(0)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=6, check=False,
            )
            self.assertEqual((proc.returncode, proc.stdout, proc.stderr),
                             (2, b"", b""))
            self.assertEqual(source.tell(), 0)

    def test_socket_stdin_is_rejected_without_read(self):
        with ExitStack() as stack:
            source, peer = socket.socketpair()
            stack.enter_context(source)
            stack.enter_context(peer)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=6, check=False,
            )
            self.assertEqual((proc.returncode, proc.stdout, proc.stderr),
                             (2, b"", b""))

    def test_regular_file_stdout_is_never_written(self):
        raw = b'{"prospect_id":"fiction","organization_name":"Fiction"}'
        with tempfile.TemporaryFile(mode="w+b") as dest:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                input=raw, stdout=dest, stderr=subprocess.PIPE,
                timeout=6, check=False,
            )
            self.assertEqual((proc.returncode, proc.stderr), (2, b""))
            dest.seek(0)
            self.assertEqual(dest.read(), b"")

    def test_socket_stdout_is_rejected_without_receipt(self):
        raw = b'{"prospect_id":"fiction","organization_name":"Fiction"}'
        with ExitStack() as stack:
            dest, peer = socket.socketpair()
            stack.enter_context(dest)
            stack.enter_context(peer)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                input=raw, stdout=dest, stderr=subprocess.PIPE,
                timeout=6, check=False,
            )
            self.assertEqual((proc.returncode, proc.stderr), (2, b""))
            dest.close()
            peer.settimeout(2)
            self.assertEqual(peer.recv(1024), b"")

    @unittest.skipUnless(hasattr(os, "pipe"), "requires local pipes")
    def test_same_pipe_input_output_alias_never_echoes_to_stdin(self):
        read_fd, write_fd = os.pipe()
        try:
            proc = subprocess.Popen(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                stdin=read_fd, stdout=write_fd, stderr=subprocess.PIPE,
            )
            try:
                self.assertEqual(proc.wait(timeout=6), 2)
                self.assertEqual(proc.stderr.read(), b"")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)
                proc.stderr.close()
        finally:
            os.close(read_fd)
            os.close(write_fd)

    @unittest.skipUnless(hasattr(os, "set_blocking"), "requires nonblocking pipes")
    def test_full_stdout_pipe_does_not_block_or_emit_partial_receipt(self):
        read_fd, write_fd = os.pipe()
        try:
            os.set_blocking(write_fd, False)
            while True:
                try:
                    os.write(write_fd, b"x" * 4096)
                except BlockingIOError:
                    break
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline-synthetic-only"],
                input=b'{"prospect_id":"x","organization_name":"y"}',
                stdout=write_fd, stderr=subprocess.PIPE, timeout=6,
                check=False,
            )
            self.assertEqual((proc.returncode, proc.stderr), (2, b""))
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_classifying_payload_cannot_promote_to_release_receipt(self):
        raw = b'{"prospect_id":"fake","organization_name":"Fiction"}'
        for content in (
            raw, raw.replace(b'"fake"', b'"APPROVED"'),
            raw.replace(b'"Fiction"', b'"Permit Grant release scan"')
        ):
            exit_code, status, output = self.run_cli(
                content, "--offline-synthetic-only"
            )
            self.assertEqual((exit_code, status), (3, "REVIEW_ONLY"))
            self.assertNotIn(b"APPROVED", output)
            self.assertNotIn(b"Grant", output)


if __name__ == "__main__":
    unittest.main()
