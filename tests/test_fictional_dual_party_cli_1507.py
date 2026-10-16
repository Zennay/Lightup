"""Real opt-in CLI process and hostile synthetic-JSON tests for #1507."""
from __future__ import annotations

import json
import os
from pathlib import Path
import random
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
VALID = (FIXTURES / "fictional_dual_party_valid_1507.json").read_bytes()
REVOKED = (FIXTURES / "fictional_dual_party_revoked_1507.json").read_bytes()
COMMAND = (sys.executable, "-m", "lightup.fictional_dual_party_cli_1507")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def cli(data):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(COMMAND, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, cwd=ROOT, timeout=15)


class FictionalDualPartyCLITests(unittest.TestCase):
    def assert_verdict(self, data, status="HOLD"):
        result = cli(data)
        self.assertIn(result.returncode, (2, 3))
        self.assertEqual(result.returncode, 2 if status == "REVIEW_ONLY" else 3)
        self.assertEqual(result.stdout, (status + "\n").encode("ascii"))
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"sandbox.example.test", result.stdout)
        self.assertNotIn(b"fictional-client-demo1", result.stdout)

    def test_genuine_valid_json_fixture(self):
        self.assertEqual(VALID, canonical(json.loads(VALID)))
        self.assert_verdict(VALID, "REVIEW_ONLY")

    def test_genuine_revoked_fixture_is_hold(self):
        self.assertEqual(REVOKED, canonical(json.loads(REVOKED)))
        self.assert_verdict(REVOKED)

    def test_strict_stdin_no_extra_trailing_or_prepended_bytes(self):
        for data in (VALID + b"\n", b" " + VALID, VALID + b" ", VALID + VALID,
                     VALID + b"{}", b"{}" + VALID, VALID + b"\x00"):
            with self.subTest(data=data[:15]):
                self.assert_verdict(data)

    def test_empty_broken_and_oversized_input(self):
        for data in (b"", b"\x00", b"not-json", b"[]", b"{}",
                     b"{" + b"a"*4100 + b"}", b" "*4097):
            with self.subTest(data=data[:12]):
                self.assert_verdict(data)

    def test_reject_non_ascii_and_encoded_confusables(self):
        for data in (VALID.replace(b"sandbox", b"\xc3\xa9"),
                     VALID.replace(b"sandbox", b"\xe2\x80\xae"),
                     VALID.replace(b"sandbox", b"\\u0073andbox"),
                     VALID.replace(b"sandbox", b"\\u202e"),
                     VALID.replace(b"demo1", b"DEMO1")):
            with self.subTest(data=data[:60]):
                self.assert_verdict(data)

    def test_duplicate_keys_not_last_write_wins(self):
        for data in (VALID.replace(b'"schema":', b'"schema":"fictional_dual_party_v1","schema":'),
                     VALID.replace(b'"risk":2', b'"risk":2,"risk":2'),
                     VALID.replace(b'"actor_id":', b'"actor_id":"x","actor_id":', 1)):
            with self.subTest(data=data[:80]):
                self.assert_verdict(data)

    def test_malformed_datetime_or_numeric_values_hold(self):
        for changed in (
            ("2030-04-15T11:00:00Z", "2030-04-15T11:00:00+00:00"),
            ("2030-04-15T13:00:00Z", "2030-04-15T13:00:00.1Z"),
            ("2030-04-15T12:00:00Z", "2030-04-15T09:00:00Z"),
            ("2030-04-15T11:00:00Z", "2030-4-15T11:00:00Z"),
        ):
            with self.subTest(changed=changed):
                self.assert_verdict(VALID.replace(changed[0].encode(), changed[1].encode()))
        for value in (b"true", b"null", b"2.0", b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(value=value):
                self.assert_verdict(VALID.replace(b'"risk":2', b'"risk":'+value))

    def test_reject_extra_missing_fields_and_forged_scope(self):
        root = json.loads(VALID)
        for bad in (
            dict(root, extra="authorized"),
            dict(root, schema="fictional_dual_party_v2"),
            dict(root, claims=[]),
            dict(root, review_at="2030-04-15T13:00:00Z"),
        ):
            with self.subTest(bad=list(bad)):
                self.assert_verdict(canonical(bad))
        for key, value in (("asset", "real.example.com"),
                           ("role", "admin"), ("decision", "approved"),
                           ("risk", 5), ("capabilities", ["execute"]),
                           ("revoked", True)):
            p = json.loads(VALID)
            p["claims"][1][key] = value
            with self.subTest(key=key):
                self.assert_verdict(canonical(p))

    def test_full_fragmented_pipe_reassembles_to_eof(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        for index in (1, 7, len(VALID)//2, len(VALID)-1):
            with self.subTest(index=index):
                process = subprocess.Popen(COMMAND, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env=env, cwd=ROOT)
                process.stdin.write(VALID[:index])
                process.stdin.flush()
                process.stdin.write(VALID[index:])
                process.stdin.close()
                result = process.stdout.read()
                error = process.stderr.read()
                self.assertEqual(process.wait(timeout=15), 2)
                self.assertEqual(result, b"REVIEW_ONLY\n")
                self.assertEqual(error, b"")

    def test_null_corruption_of_every_16th_fixture_byte_is_hold(self):
        for i in range(0, len(VALID), 16):
            with self.subTest(i=i):
                changed = bytearray(VALID)
                changed[i] = 0
                self.assert_verdict(bytes(changed))

    def test_deterministic_random_bit_flips_do_not_confer_authority(self):
        rng = random.Random(1507)
        for _ in range(48):
            changed = bytearray(VALID)
            offset = rng.randrange(len(changed))
            changed[offset] ^= 1 << rng.randrange(8)
            result = cli(bytes(changed))
            self.assertIn(result.returncode, (2, 3))
            self.assertEqual(result.stdout, (b"HOLD\n" if result.returncode == 3
                                             else b"REVIEW_ONLY\n"))
            self.assertNotIn(b"sandbox.example.test", result.stdout)

    def test_cli_status_never_zero_even_on_coordinated_fake_pair(self):
        data = json.loads(VALID)
        for claim in data["claims"]:
            claim["case_id"] = "case-coordinatedfake"
            claim["asset"] = "imposter.example.test"
        self.assert_verdict(canonical(data), "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
