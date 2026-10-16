"""Opt-in exact-byte offline subprocess tests for fictional-only #1503 CLI."""
from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

from lightup import fictional_packet_cli_1503 as cli
from lightup.fictional_packet_copy_1503 import CopyReview, build_fictional_copy_packet

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src"
GOOD = build_fictional_copy_packet(
    "alpha.example.test", "REVIEW_REQUIRED", ("metadata_read", "report_preview")
)
BAD_COPY = build_fictional_copy_packet(
    "beta.example.test", "REVIEW_REQUIRED", ("metadata_read", "report_preview")
)
assert type(GOOD) is bytes and type(BAD_COPY) is bytes


def request(original=GOOD, copies=(GOOD,)):
    return json.dumps(
        {"schema": "lightup-fictional-cli-v1",
         "original": original.decode("ascii"),
         "copies": [c.decode("ascii") for c in copies]},
        ensure_ascii=True, separators=(",", ":"), sort_keys=False,
    ).encode("ascii")


def process(payload, args=()):
    env = {**os.environ, "PYTHONPATH": str(PACKAGE), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "lightup.fictional_packet_cli_1503", *args],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=ROOT, timeout=15, check=False,
    )


class FictionalCliTests(unittest.TestCase):
    def assert_hold(self, payload):
        verdict = cli._parse_request(payload)
        self.assertEqual(verdict.status, "HOLD")
        self.assertIsNone(verdict.sha256)
        output = cli._render(verdict)
        self.assertEqual(output, cli._HOLD)
        self.assertNotIn(b"alpha.example.test", output)
        self.assertNotIn(b"beta.example.test", output)
        self.assertIs(verdict.authorized, False)
        self.assertIs(verdict.consent_verified, False)
        self.assertIs(verdict.dispatch_allowed, False)
        self.assertIs(verdict.release_allowed, False)

    def test_valid_single_copy_nonzero_exit_and_literal_false_flags(self):
        result = process(request())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"")
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "REVIEW_ONLY")
        self.assertEqual(data["sha256"], hashlib.sha256(GOOD).hexdigest())
        self.assertIs(data["authorized"], False)
        self.assertIs(data["consent_verified"], False)
        self.assertIs(data["dispatch_allowed"], False)
        self.assertIs(data["release_allowed"], False)
        self.assertNotIn(b"alpha.example.test", result.stdout)

    def test_valid_sixteen_copies_subprocess(self):
        result = process(request(copies=(GOOD,) * 16))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'"status":"REVIEW_ONLY"', result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_changed_last_copy_atomic_hold_subprocess(self):
        result = process(request(copies=(GOOD,) * 15 + (BAD_COPY,)))
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, cli._HOLD)
        self.assertEqual(result.stderr, b"")

    def test_checked_in_cli_fixtures_exact_no_newline_and_subprocess(self):
        folder = ROOT / "docs" / "examples"
        valid = (folder / "fictional-copy-cli-1503.json").read_bytes()
        held = (folder / "fictional-copy-cli-held-1503.json").read_bytes()
        self.assertEqual(valid, request(copies=(GOOD,) * 2))
        self.assertEqual(held, request(copies=(GOOD, BAD_COPY)))
        for raw, code, marker in (
            (valid, 2, b'"status":"REVIEW_ONLY"'),
            (held, 3, b'"status":"HOLD"'),
        ):
            with self.subTest(code=code):
                result = process(raw)
                self.assertEqual((result.returncode, result.stderr), (code, b""))
                self.assertIn(marker, result.stdout)
                self.assertNotIn(b".example.test", result.stdout)

    def test_changed_not_reparsed_with_whitespace_or_trailing_newline(self):
        self.assert_hold(b" " + request())
        self.assert_hold(request() + b"\n")
        self.assert_hold(request().replace(b":", b": ", 1))

    def test_extra_missing_duplicate_reordered_fields_hold(self):
        valid = request()
        self.assert_hold(valid[:-1] + b',"unknown":"approval"}')
        self.assert_hold(valid.replace(b'"copies":', b'"new_copies":'))
        self.assert_hold(valid[:-1] + b',"schema":"lightup-fictional-cli-v1"}')
        self.assert_hold(valid.replace(
            b'{"schema":"lightup-fictional-cli-v1","original":',
            b'{"original":'
        ))

    def test_invalid_envelope_types_fenced(self):
        valid = json.loads(request())
        for key, bad in (
            ("schema", None), ("schema", True), ("original", 1),
            ("original", None), ("copies", "not-a-list"),
            ("copies", {}), ("copies", []), ("copies", [GOOD.decode()] * 17),
            ("copies", [GOOD.decode(), None]),
        ):
            with self.subTest(key=key, bad=str(bad)[:20]):
                changed = dict(valid)
                changed[key] = bad
                self.assert_hold(json.dumps(
                    changed, separators=(",", ":"), ensure_ascii=True,
                ).encode("ascii"))

    def test_noncanonical_subpacket_held_without_partial_hash(self):
        for other in (
            GOOD + b" ", GOOD.replace(b"alpha", b"client"),
            GOOD.replace(b"false", b"true"),
            GOOD.replace(b"alpha", b"\\u0061lpha"),
        ):
            with self.subTest(other=other[:10]):
                self.assert_hold(request(copies=(other,)))

    def test_oversize_non_ascii_and_polymorphic_stdin_hold(self):
        class AlienBytes(bytes):
            pass
        for payload in (
            None, "", b"", bytearray(request()), AlienBytes(request()),
            b"x" * 8193, b'{"schema":"a","original":"\xff","copies":[]}',
            b"{" * 2500,
        ):
            with self.subTest(typ=type(payload).__name__):
                self.assert_hold(payload)

    def test_nans_unicode_alias_and_control_held(self):
        self.assert_hold(request().replace(b'"copies":', b'"copies":NaN,"unused":'))
        self.assert_hold(request().replace(b"alpha", b"\\u0061lpha"))
        self.assert_hold(request().replace(b"alpha", "álpha".encode("utf-8")))
        self.assert_hold(b"\xef\xbb\xbf" + request())

    def test_cli_parser_one_byte_mutation_never_yields_review(self):
        original = request()
        for index in range(len(original)):
            replacement = (original[index] + 1) % 256
            altered = original[:index] + bytes((replacement,)) + original[index + 1:]
            self.assertEqual(cli._parse_request(altered).status, "HOLD")

    def test_result_renderer_does_not_trust_polymorphic_or_poisoned_records(self):
        class AlienCopyReview(CopyReview):
            pass
        good = cli._parse_request(request())
        self.assertEqual(good.status, "REVIEW_ONLY")
        self.assertEqual(cli._render(AlienCopyReview("REVIEW_ONLY", good.sha256)),
                         cli._HOLD)
        object.__setattr__(good, "authorized", True)
        self.assertEqual(cli._render(good), cli._HOLD)
        object.__setattr__(good, "authorized", False)
        object.__setattr__(good, "sha256", "fake")
        self.assertEqual(cli._render(good), cli._HOLD)

    def test_real_subprocess_bad_input_is_generic_hold_and_nonzero(self):
        for payload in (
            b"", b"garbage", b"{", b"{" * 8300,
            request(copies=(GOOD, BAD_COPY)), request() + b"\n",
        ):
            result = process(payload)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, cli._HOLD)
            self.assertEqual(result.stderr, b"")

    def test_render_output_is_bounded_and_never_contains_source_values(self):
        for payload in (
            request(), request(copies=(BAD_COPY,)), b"secret-password",
        ):
            rendered = cli._render(cli._parse_request(payload))
            self.assertLessEqual(len(rendered), 200)
            self.assertTrue(rendered.endswith(b"\n"))
            self.assertNotIn(b"secret", rendered)
            self.assertNotIn(b".example.test", rendered)

    def test_unwired_cli_absent_from_production_source_modules(self):
        for path in (PACKAGE / "lightup").rglob("*.py"):
            if path.name in ("fictional_packet_cli_1503.py",
                             "fictional_packet_copy_1503.py"):
                continue
            self.assertNotIn("fictional_packet_cli_1503",
                             path.read_text(encoding="utf-8"))

    def test_cli_holds_on_stdin_oserror_and_does_not_echo(self):
        class BadStdin:
            class buffer:
                @staticmethod
                def read(_amount):
                    raise OSError("fictional secret")
        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()
        o = Out()
        with patch.object(cli.sys, "stdin", BadStdin()), patch.object(cli.sys, "stdout", o):
            self.assertEqual(cli.main(), 3)
        self.assertEqual(o.buffer.getvalue(), cli._HOLD)

    def test_cli_fails_nonzero_on_broken_stdout(self):
        class Input:
            def __init__(self, payload):
                self.buffer = io.BytesIO(payload)
        class Broken:
            class buffer:
                @staticmethod
                def write(_data):
                    raise BrokenPipeError("disconnected")
        with patch.object(cli.sys, "stdin", Input(request())), \
             patch.object(cli.sys, "stdout", Broken()):
            self.assertEqual(cli.main(), 3)


    def test_unknown_commandline_flags_never_promote_review(self):
        for args in (
            ("--approve",), ("--grant", "yes"), ("--output", "approval.json"),
            ("--help",), ("--unsafe",), ("file.json",),
        ):
            with self.subTest(args=args):
                result = process(request(), args=args)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(result.stdout, cli._HOLD)
                self.assertEqual(result.stderr, b"")

    def test_incomplete_or_noninteger_stdout_write_always_exits_three(self):
        class Input:
            def __init__(self, raw):
                self.buffer = io.BytesIO(raw)
        class Out:
            def __init__(self, result):
                self.result = result
                self.buffer = self
                self.output = []
            def write(self, data):
                self.output.append(bytes(data))
                return self.result
            def flush(self):
                pass
        for wrote in (0, 1, None, True, False, -1, len(cli._HOLD)):
            with self.subTest(wrote=wrote):
                out = Out(wrote)
                with patch.object(cli.sys, "argv", ["fictional_packet_cli_1503.py"]), \
                     patch.object(cli.sys, "stdin", Input(request())), \
                     patch.object(cli.sys, "stdout", out):
                    self.assertEqual(cli.main(), 3)
                self.assertTrue(out.output)
                self.assertTrue(out.output[0].startswith(b'{"status":"REVIEW_ONLY"'))

    def test_successful_stdout_write_requires_full_length(self):
        class Input:
            def __init__(self):
                self.buffer = io.BytesIO(request())
        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()
        out = Out()
        with patch.object(cli.sys, "argv", ["fictional_packet_cli_1503.py"]), \
             patch.object(cli.sys, "stdin", Input()), \
             patch.object(cli.sys, "stdout", out):
            self.assertEqual(cli.main(), 2)
        self.assertTrue(out.buffer.getvalue().endswith(b"\\n"))
        self.assertNotIn(b".example.test", out.buffer.getvalue())



if __name__ == "__main__":
    unittest.main()
