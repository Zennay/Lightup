"""True-subprocess review-only CLI acceptance, fictional input only (#1520)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
CMD = [sys.executable, "-m", "scripts.scope_parameter_schema_cli_1520"]
FLAGS = {
    "authorized": False,
    "consent_verified": False,
    "dispatch_allowed": False,
    "release_allowed": False,
}


def _payload(parameters):
    return json.dumps({"parameters": parameters}, separators=(",", ":")).encode("ascii")


def _parameter(name, kind="string", required=True):
    return {"name": name, "kind": kind, "required": required}


def _run(payload):
    return subprocess.run(
        CMD, input=payload, cwd=ROOT, env=ENV, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=15, check=False,
    )


class ParameterSchemaCli1520Tests(unittest.TestCase):
    def assert_decision(self, result, expected):
        self.assertEqual(result.returncode, 2 if expected == "REVIEW_ONLY" else 3)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout,
            (json.dumps({"status": expected, **FLAGS}, separators=(",", ":")) + "\n").encode("ascii"),
        )

    def test_accept_canonical_empty_and_valid_schema_without_authority(self):
        for raw in (_payload([]), _payload([_parameter("asset"), _parameter("retry", "integer", False)])):
            with self.subTest(raw=raw):
                self.assert_decision(_run(raw), "REVIEW_ONLY")

    def test_hold_duplicate_names_even_when_parameter_kinds_match(self):
        self.assert_decision(_run(_payload([_parameter("a"), _parameter("a")])), "HOLD")
        self.assert_decision(
            _run(_payload([_parameter("a", "number"), _parameter("a", "boolean")])), "HOLD"
        )

    def test_hold_noncanonical_name_and_types(self):
        invalid = [
            _payload([_parameter("A")]),
            _payload([_parameter("asset", required=0)]),
            _payload([_parameter("asset", kind="wrong")]),
            _payload([{"name": "asset", "kind": "string", "required": True, "extra": 1}]),
            _payload([{"name": "asset", "kind": "string"}]),
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                self.assert_decision(_run(raw), "HOLD")

    def test_hold_duplicate_json_object_key_before_projection(self):
        for raw in (
            b'{"parameters":[],"parameters":[]}',
            b'{"parameters":[{"name":"x","name":"y","kind":"string","required":true}]}',
        ):
            self.assert_decision(_run(raw), "HOLD")

    def test_hold_unicode_alias_escape_and_nonascii_byte(self):
        for raw in (
            b'{"parameters":[{"name":"\\u0061","kind":"string","required":true}]}',
            '{"parameters":[{"name":"é","kind":"string","required":true}]}'.encode("utf-8"),
            b'{"parameters":[{"name":"a\\u0000b","kind":"string","required":true}]}',
        ):
            self.assert_decision(_run(raw), "HOLD")

    def test_hold_nonstandard_numbers_and_noncanonical_json(self):
        for raw in (
            b'{"parameters":NaN}',
            b'{"parameters":Infinity}',
            b'{"parameters":-Infinity}',
            b'{ "parameters":[]}',
            b'{"parameters":[] }',
            b'{"parameters":[] }\n',
            b'{"parameters":null}',
            b'{"parameters":{}}',
        ):
            self.assert_decision(_run(raw), "HOLD")

    def test_hold_empty_nul_and_oversized_stdin(self):
        for raw in (b"", b"\x00", b"x" * 8193):
            self.assert_decision(_run(raw), "HOLD")

    def test_exact_count_limit(self):
        self.assert_decision(_run(_payload([_parameter("p" + str(i)) for i in range(32)])), "REVIEW_ONLY")
        self.assert_decision(_run(_payload([_parameter("p" + str(i)) for i in range(33)])), "HOLD")

    def test_deep_json_is_generic_hold_not_traceback(self):
        self.assert_decision(_run(b'{"parameters":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}"), "HOLD")

    def test_real_fragmented_stdin_yields_same_review(self):
        raw = _payload([_parameter("asset")])
        process = subprocess.Popen(
            CMD, cwd=ROOT, env=ENV, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertIsNotNone(process.stdin)
        for octet in raw:
            process.stdin.write(bytes((octet,)))
        process.stdin.close()
        self.assertEqual(process.wait(timeout=15), 2)
        self.assert_decision(
            subprocess.CompletedProcess(CMD, 2, process.stdout.read(), process.stderr.read()),
            "REVIEW_ONLY",
        )


if __name__ == "__main__":
    unittest.main()
