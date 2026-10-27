"""Offline/fiction-only canonical CLI acceptance for scope issue #1511."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fictional_lab_capability_cli_1511 import decide_stdin_bytes_1511

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "fictional_lab_capability_cli_1511.py"


def _valid_bytes():
    return b'{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline","tls-baseline"]}'


def _run(data):
    return subprocess.run(
        [sys.executable, str(_SCRIPT)],
        input=data,
        cwd=_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


class FictionalLabCapabilityCLITests1511(unittest.TestCase):
    def test_valid_synthetic_consistency_never_exits_zero(self):
        payload = _valid_bytes()
        self.assertEqual(decide_stdin_bytes_1511(payload), "REVIEW_ONLY")
        process = _run(payload)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"REVIEW_ONLY\n")
        self.assertEqual(process.stderr, b"")

    def test_mismatch_is_generic_hold(self):
        payload = _valid_bytes().replace(b'"requested":"web-baseline"', b'"requested":"other-id"')
        self.assertEqual(decide_stdin_bytes_1511(payload), "HOLD")
        process = _run(payload)
        self.assertEqual((process.returncode, process.stdout, process.stderr), (3, b"HOLD\n", b""))

    def test_malformed_and_overlong_inputs_hold(self):
        for payload in (b"", b" ", b"null", b"[]", b"{}",
                        b'{"schema":', _valid_bytes() + b"\n",
                        _valid_bytes() + b"{}", _valid_bytes() + b" ",
                        b"\xff", b"[" * 4097,
                        b"\xef\xbb\xbf" + _valid_bytes()):
            with self.subTest(payload_len=len(payload)):
                self.assertEqual(decide_stdin_bytes_1511(payload), "HOLD")

    def test_duplicate_schema_and_requested_keys_hold(self):
        payloads = (
            _valid_bytes().replace(b'"schema":', b'"schema":"fictional_lab_capability_v1","schema":'),
            _valid_bytes().replace(b'"requested":', b'"requested":"web-baseline","requested":'),
        )
        for payload in payloads:
            self.assertEqual(decide_stdin_bytes_1511(payload), "HOLD")

    def test_whitespace_unicode_escaping_and_field_order_hold(self):
        normal = _valid_bytes()
        payloads = (
            normal.replace(b',"requested"', b', "requested"'),
            normal.replace(b"web-baseline", b"web\\u002dbaseline"),
            normal.replace(b"web-baseline", b"w\\u0065b-baseline"),
            normal.replace(b'"schema":"fictional_lab_capability_v1",', b""),
            b'{"requested":"web-baseline","schema":"fictional_lab_capability_v1","allowlist":["web-baseline"]}',
            b'{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"],"extra":1}',
        )
        for payload in payloads:
            with self.subTest(payload=payload[:45]):
                self.assertEqual(decide_stdin_bytes_1511(payload), "HOLD")

    def test_noncanonical_id_and_untrusted_allowlist_hold(self):
        for payload in (
            _valid_bytes().replace(b'"requested":"web-baseline"', b'"requested":false'),
            _valid_bytes().replace(b'"requested":"web-baseline"', b'"requested":123'),
            _valid_bytes().replace(b'"requested":"web-baseline"', b'"requested":"WEB-baseline"'),
            _valid_bytes().replace(b'"allowlist":["web-baseline","tls-baseline"]', b'"allowlist":[]'),
            _valid_bytes().replace(b'"allowlist":["web-baseline","tls-baseline"]', b'"allowlist":["web-baseline","web-baseline"]'),
            _valid_bytes().replace(b'"allowlist":["web-baseline","tls-baseline"]', b'"allowlist":"web-baseline"'),
        ):
            self.assertEqual(decide_stdin_bytes_1511(payload), "HOLD")

    def test_poisoned_builtin_inputs_hold(self):
        for value in (None, True, False, 12, "text", bytearray(_valid_bytes()), memoryview(_valid_bytes())):
            self.assertEqual(decide_stdin_bytes_1511(value), "HOLD")

    def test_actual_cli_rejects_binary_hostile_input_without_echo(self):
        payload = b"SECRET_CANARY_DO_NOT_ECHO=" + b"\x00" * 32
        result = _run(payload)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"HOLD\n")
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"SECRET_CANARY", result.stdout + result.stderr)

    def test_every_single_byte_fixture_corruption_is_not_authority(self):
        original = _valid_bytes()
        for i in range(len(original)):
            sample = original[:i] + b"\x00" + original[i + 1:]
            self.assertEqual(decide_stdin_bytes_1511(sample), "HOLD")

    def test_no_cli_path_can_grant_authority(self):
        for payload in (b"", _valid_bytes(), _valid_bytes() + b"{}",
                        _valid_bytes().replace(b"web-baseline", b"unknown-id")):
            result = _run(payload)
            self.assertIn(result.returncode, (2, 3))
            self.assertIn(result.stdout, (b"HOLD\n", b"REVIEW_ONLY\n"))
            self.assertNotIn(b"AUTH", result.stdout)
            self.assertNotIn(b"GRANT", result.stdout)
            self.assertNotIn(b"PERMIT", result.stdout)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
