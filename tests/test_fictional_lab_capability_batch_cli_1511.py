"""Offline subprocess and canonical JSON matrix for #1511 cohort CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fictional_lab_capability_batch_cli_1511 import decide_batch_stdin_bytes_1511

_SCRIPT = ROOT / "scripts" / "fictional_lab_capability_batch_cli_1511.py"


def _encode(requested, allowlist):
    return json.dumps(
        {"schema": "fictional_lab_capability_batch_v1",
         "requested": requested, "allowlist": allowlist},
        ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")


def _run(input_bytes):
    return subprocess.run(
        [sys.executable, str(_SCRIPT)], input=input_bytes,
        cwd=ROOT, capture_output=True, check=False, timeout=10,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


class FictionalLabCapabilityBatchCLI1511Tests(unittest.TestCase):
    def test_two_canonical_fictional_ids_are_review_only_never_success(self):
        data = _encode(["web-baseline", "tls-baseline"],
                       ["tls-baseline", "web-baseline"])
        self.assertEqual(decide_batch_stdin_bytes_1511(data), "REVIEW_ONLY")
        result = _run(data)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, b"REVIEW_ONLY\n", b""))

    def test_one_missing_fictional_id_denies_whole_batch(self):
        for requested in (
            ["missing", "web-baseline"], ["web-baseline", "missing"],
            ["web-baseline", "tls-baseline", "missing"],
        ):
            data = _encode(requested, ["web-baseline", "tls-baseline"])
            self.assertEqual(decide_batch_stdin_bytes_1511(data), "HOLD")
            result = _run(data)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (3, b"HOLD\n", b""))

    def test_replay_duplicate_candidate_and_scope_hold(self):
        for requested, allowlist in (
            (["web-baseline", "web-baseline"], ["web-baseline"]),
            (["web-baseline"], ["web-baseline", "web-baseline"]),
            ([], ["web-baseline"]), (["web-baseline"], []),
        ):
            self.assertEqual(decide_batch_stdin_bytes_1511(_encode(requested, allowlist)), "HOLD")

    def test_wrong_schema_or_single_cli_envelope_cannot_be_cross_accepted(self):
        examples = (
            b'{"schema":"fictional_lab_capability_v1","requested":["web-baseline"],"allowlist":["web-baseline"]}',
            b'{"schema":"fictional_lab_capability_batch_v1","requested":"web-baseline","allowlist":["web-baseline"]}',
            b'{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline"],"allowlist":"web-baseline"}',
            b'{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline"]}',
            b'{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline"],"allowlist":["web-baseline"],"extra":false}',
        )
        for sample in examples:
            self.assertEqual(decide_batch_stdin_bytes_1511(sample), "HOLD")

    def test_alias_duplicate_keys_whitespace_wrong_order_trailing_hold(self):
        good = _encode(["web-baseline"], ["web-baseline"])
        variations = (
            good.replace(b'"schema":', b'"schema":"fictional_lab_capability_batch_v1","schema":'),
            good.replace(b'"schema":', b'"\\u0073chema":"fictional_lab_capability_batch_v1","schema":'),
            good.replace(b'"schema":', b'"schema":"fictional_lab_capability_batch_v1","\\u0073chema":'),
            good.replace(b',"requested":', b', "requested":'),
            good.replace(b'"web-baseline"', b'"web\\u002dbaseline"'),
            good.replace(b'"web-baseline"', b'"w\\u0065b-baseline"'),
            good + b" ", good + b"\n", good + b"{}",
            b'{"requested":["web-baseline"],"schema":"fictional_lab_capability_batch_v1","allowlist":["web-baseline"]}',
        )
        for sample in variations:
            with self.subTest(sample=sample[:35]):
                self.assertEqual(decide_batch_stdin_bytes_1511(sample), "HOLD")

    def test_every_fixture_prefix_and_null_corruption_is_hold(self):
        good = _encode(["web-baseline", "tls-baseline"],
                       ["tls-baseline", "web-baseline"])
        self.assertEqual(decide_batch_stdin_bytes_1511(good), "REVIEW_ONLY")
        for offset in range(len(good)):
            self.assertEqual(decide_batch_stdin_bytes_1511(good[:offset]), "HOLD")
            broken = good[:offset] + b"\x00" + good[offset + 1:]
            self.assertEqual(decide_batch_stdin_bytes_1511(broken), "HOLD")

    def test_size_bounds_and_malicious_shapes_hold(self):
        good = _encode(["web-baseline"], ["web-baseline"])
        for candidate in (
            None, False, True, 42, good.decode(), bytearray(good),
            b"", b"null", b"[]", b"{}", b"\xff",
            good + b" " * (4096 - len(good)), good + b"x" * 4097,
            b"[" * 1500 + b"0" + b"]" * 1500,
        ):
            self.assertEqual(decide_batch_stdin_bytes_1511(candidate), "HOLD")

    def test_poisoned_candidate_id_shapes_hold_without_echo(self):
        suspicious = (
            None, True, False, 1, 3.1, "", " ", "Web-baseline",
            "web baseline", "web--baseline", "web_baseline", "é",
            "ｗｅｂ", "a" * 65,
        )
        for value in suspicious:
            with self.subTest(kind=type(value).__name__):
                self.assertEqual(
                    decide_batch_stdin_bytes_1511(
                        _encode(["web-baseline", value], ["web-baseline"])
                    ),
                    "HOLD",
                )

    def test_json_special_numbers_and_malformed_numeric_values_hold(self):
        good = _encode(["web-baseline"], ["web-baseline"])
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1e9999",
                      b"1e-9999", b"100000000000000000000000000000000000"):
            malformed = good.replace(b'["web-baseline"]', b'["web-baseline",' + token + b"]", 1)
            self.assertEqual(decide_batch_stdin_bytes_1511(malformed), "HOLD")

    def test_subprocess_private_marker_never_appears_in_output(self):
        sample = b'{"schema":"fictional_lab_capability_batch_v1","requested":["PRIVATE_DO_NOT_ECHO"'
        result = _run(sample)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (3, b"HOLD\n", b""))
        self.assertNotIn(b"PRIVATE_DO_NOT_ECHO", result.stdout + result.stderr)

    def test_no_subprocess_success_return_code_for_adversarial_inputs(self):
        valid = _encode(["web-baseline"], ["web-baseline"])
        for sample in (valid, b"", valid[:-1], valid + b" ", b"\xff",
                       _encode(["missing"], ["web-baseline"])):
            p = _run(sample)
            self.assertIn(p.returncode, (2, 3))
            self.assertIn(p.stdout, (b"HOLD\n", b"REVIEW_ONLY\n"))
            self.assertEqual(p.stderr, b"")
            self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
