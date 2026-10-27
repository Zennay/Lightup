"""End-to-end no-authority CLI validation for #294; no real target I/O."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "scripts")
sys.path.insert(0, SCRIPTS)

from scope_294_collection_review_cli import _MAX_INPUT_BYTES, review_private_manifest

SCRIPT = os.path.join(SCRIPTS, "scope_294_collection_review_cli.py")
FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "scan_approved", "merge_approved", "release_approved",
)


def _invoke(data: bytes):
    # The only subprocess is the *offline* CLI itself; no tools/targets used.
    child = subprocess.run(
        [sys.executable, "-B", SCRIPT],
        input=data,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if child.stderr:
        raise AssertionError(f"offline CLI emitted stderr: {child.stderr[:200]!r}")
    receipt = json.loads(child.stdout.decode("utf-8"))
    return child.returncode, receipt, child.stdout


class OfflineScopeCollectionManifestCliTests(unittest.TestCase):
    def assert_no_authority(self, code, receipt, output):
        self.assertEqual(set(receipt), {"status", "reason", *FLAGS})
        for flag in FLAGS:
            self.assertIs(receipt[flag], False)
        self.assertIn(code, (2, 3))
        self.assertNotIn(b"fixture.example.test", output)
        self.assertNotIn(b"8.8.8.0/24", output)
        self.assertNotIn(b"password", output)

    def test_bounded_valid_manifest_returns_nonzero_review_only(self):
        data = b'{"hosts":["fixture.example.test"],"networks":["8.8.8.0/24"]}'
        code, receipt, output = _invoke(data)
        self.assertEqual(code, 3)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["reason"], "canonical_collections")
        self.assert_no_authority(code, receipt, output)

    def test_invalid_shapes_and_extra_fields_hold_without_echo(self):
        cases = (
            b"{}",
            b'{"hosts":"fixture.example.test","networks":[]}',
            b'{"hosts":[],"networks":{}}',
            b'{"hosts":[],"networks":[],"authorization":true}',
            b'{"hosts":[1],"networks":[]}',
            b'{"hosts":[],"networks":["bad-network"]}',
            b'["fixture.example.test"]',
            b"null",
        )
        for data in cases:
            with self.subTest(raw=data[:30]):
                code, receipt, output = _invoke(data)
                self.assertEqual(code, 2)
                self.assertEqual(receipt["status"], "HOLD")
                self.assert_no_authority(code, receipt, output)

    def test_duplicate_outer_and_nested_keys_are_rejected(self):
        cases = (
            b'{"hosts":[],"hosts":["fixture.example.test"],"networks":[]}',
            b'{"hosts":[],"networks":[],"meta":{"x":1,"x":2}}',
        )
        for data in cases:
            with self.subTest(raw=data[:35]):
                code, receipt, output = _invoke(data)
                self.assertEqual(code, 2)
                self.assertEqual(receipt["reason"], "invalid_collections")
                self.assert_no_authority(code, receipt, output)

    def test_nonfinite_invalid_utf8_and_nonjson_inputs_hold(self):
        cases = (
            b'{"hosts":[],"networks":[],"risk":NaN}',
            b'{"hosts":[],"networks":[],"risk":Infinity}',
            b"\xff\xfe\x80",
            b"{",
            b"",
            b" " * 200,
        )
        for data in cases:
            with self.subTest(raw=data[:20]):
                code, receipt, output = _invoke(data)
                self.assertEqual(code, 2)
                self.assertEqual(receipt["status"], "HOLD")
                self.assert_no_authority(code, receipt, output)

    def test_oversized_payload_refused_without_parsing(self):
        data = b" " * (_MAX_INPUT_BYTES + 1)
        code, receipt, output = _invoke(data)
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "HOLD")
        self.assert_no_authority(code, receipt, output)

    def test_128_and_129_member_boundaries(self):
        data = lambda n: json.dumps(
            {"hosts": [f"host-{i}.example.test" for i in range(n)], "networks": []}
        ).encode("utf-8")
        for n, expected in ((128, "REVIEW_ONLY"), (129, "HOLD")):
            with self.subTest(n=n):
                code, receipt, output = _invoke(data(n))
                self.assertEqual(receipt["status"], expected)
                self.assertEqual(code, 3 if n == 128 else 2)
                self.assert_no_authority(code, receipt, output)

    def test_receipts_are_deterministic_and_input_private(self):
        data = b'{"hosts":["secret.fixture.example.test"],"networks":["8.8.8.0/24"]}'
        first = _invoke(data)
        second = _invoke(data)
        self.assertEqual(first, second)
        self.assert_no_authority(*first)

    def test_python_api_never_grants_for_shape_success(self):
        r = review_private_manifest(
            b'{"hosts":["fixture.example.test"],"networks":["8.8.8.0/24"]}'
        )
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assertIs(bool(r), False)
        self.assert_no_authority(3, r.to_public_dict(), json.dumps(r.to_public_dict()).encode())


if __name__ == "__main__":
    unittest.main()
