"""Offline stdlib-only scope lab-address review acceptance tests."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_literal_offline import review_literal  # noqa: E402

SCRIPT = ROOT / "scripts" / "check_scope_lab_literal_offline.py"
_FLAGS = (
    "authorization_verified",
    "permit_issued",
    "execution_enabled",
    "merge_approved",
    "release_approved",
)


class LabLiteralReviewTests(unittest.TestCase):
    def assertNoAuthority(self, receipt):
        self.assertEqual(receipt["schema_version"], 1)
        self.assertTrue(all(receipt[flag] is False for flag in _FLAGS))
        self.assertNotIn("address", receipt)
        self.assertEqual(set(receipt), {"schema_version", "status", "reason",
                                         "address_class", *_FLAGS})

    def test_canonical_loopback_is_review_only(self):
        for value in ("127.0.0.1", "127.99.88.77", "::1"):
            with self.subTest(value=value):
                result = review_literal(value)
                self.assertEqual(result["status"], "REVIEW_ONLY")
                self.assertEqual(result["address_class"], "loopback")
                self.assertNoAuthority(result)

    def test_rfc1918_is_shape_only(self):
        for value in ("10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.2.5"):
            with self.subTest(value=value):
                result = review_literal(value)
                self.assertEqual(result["status"], "REVIEW_ONLY")
                self.assertEqual(result["address_class"], "rfc1918")
                self.assertNoAuthority(result)

    def test_ipv6_locally_assigned_ula_is_shape_only(self):
        for value in ("fd00::1", "fd12:3456::abcd"):
            with self.subTest(value=value):
                result = review_literal(value)
                self.assertEqual(result["status"], "REVIEW_ONLY")
                self.assertEqual(result["address_class"], "ula")
                self.assertNoAuthority(result)

    def test_denies_special_use_private_looking_ipv4(self):
        for value in (
            "0.0.0.0", "0.1.2.3", "169.254.2.3", "192.0.2.1",
            "198.18.0.1", "198.51.100.1", "203.0.113.5",
            "224.0.0.1", "240.0.0.1", "255.255.255.255", "100.64.0.1",
        ):
            with self.subTest(value=value):
                result = review_literal(value)
                self.assertEqual(result["status"], "HOLD")
                self.assertNoAuthority(result)

    def test_denies_special_use_ipv6(self):
        for value in (
            "::", "fe80::1", "ff02::1", "2001:db8::1",
            "fc00::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3",
        ):
            with self.subTest(value=value):
                result = review_literal(value)
                self.assertEqual(result["status"], "HOLD")
                self.assertNoAuthority(result)

    def test_denies_public_and_outside_specific_private_nets(self):
        for value in ("8.8.8.8", "1.1.1.1", "172.15.255.255",
                      "172.32.0.1", "192.169.1.1", "2001:4860::8888"):
            with self.subTest(value=value):
                self.assertEqual(review_literal(value)["status"], "HOLD")

    def test_denies_url_authority_and_cidr_confusion(self):
        for value in (
            "http://127.0.0.1", "https://10.1.2.3", "127.0.0.1:80",
            "[::1]", "[::1]:443", "10.0.0.0/8", "fd00::1%eth0",
            "localhost", "127.0.0.1.", "127.0.0.1@evil.example",
        ):
            with self.subTest(value=value):
                result = review_literal(value)
                self.assertEqual(result["status"], "HOLD")
                self.assertNoAuthority(result)

    def test_denies_noncanonical_and_non_ascii_literals(self):
        for value in (
            "", " 127.0.0.1", "127.0.0.1\n", "127.0.0.1\x00",
            "010.0.0.1", "127.000.000.001", "１２７.0.0.1",
            "127.0.0.1\t", "127.0.0.1" + " " * 140,
        ):
            with self.subTest(value=repr(value)[:30]):
                result = review_literal(value)
                self.assertEqual(result["status"], "HOLD")
                self.assertNoAuthority(result)

    def test_denies_polymorphic_string_and_nonstring(self):
        class EvilStr(str):
            def strip(self):
                raise AssertionError("subclass method must not be called")
        for value in (EvilStr("127.0.0.1"), 123, None, b"127.0.0.1", []):
            result = review_literal(value)
            self.assertEqual(result["status"], "HOLD")
            self.assertNoAuthority(result)

    def test_receipt_never_echoes_original_literal(self):
        for value in ("private.example.test", "127.0.0.1", "8.8.8.8"):
            serialized = json.dumps(review_literal(value))
            self.assertNotIn(value, serialized)

    def _cli(self, data: bytes, *arguments: str):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            input=data, capture_output=True, check=False, timeout=5,
        )

    def test_cli_review_only_is_non_authorizing(self):
        process = self._cli(b"10.2.3.4\n")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNoAuthority(json.loads(process.stdout))
        self.assertIn(b"REVIEW_ONLY", process.stdout)

    def test_cli_hold_returns_nonzero_and_fixed_privacy_receipt(self):
        marker = b"private-target-secret.example"
        process = self._cli(marker)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertNoAuthority(json.loads(process.stdout))
        self.assertNotIn(marker, process.stdout + process.stderr)

    def test_cli_rejects_oversized_input_without_echo(self):
        marker = b"PRIVATE-MARKER-" + b"x" * 500
        process = self._cli(marker)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stdout)["reason"], "INPUT_TOO_LARGE")
        self.assertNotIn(marker, process.stdout + process.stderr)

    def test_cli_nonascii_and_argv_fail_closed(self):
        for data, args in ((b"\xff\xfe", ()), (b"127.0.0.1", ("--permit",))):
            process = self._cli(data, *args)
            self.assertEqual(process.returncode, 2)
            self.assertNoAuthority(json.loads(process.stdout))


if __name__ == "__main__":
    unittest.main()
