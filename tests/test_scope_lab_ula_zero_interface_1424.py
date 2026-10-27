"""#1424: offline IPv6 ULA /64 zero-IID candidate-identity regression.

These are in-memory review classifications, never authorization or scans.
"""
from __future__ import annotations

from ipaddress import IPv6Address
import json
from pathlib import Path
import random
import subprocess
import sys
from unittest import TestCase, main

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

from lightup.scope_lab_literal_review_1424 import review_lab_literal
from review_scope_lab_batch_1424_offline import review_batch_json


_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


class UlaZeroInterfaceReviewTests(TestCase):
    def assert_review(self, literal: str, status: str, classification: str):
        result = review_lab_literal(literal)
        self.assertEqual(result.status, status, literal)
        self.assertEqual(result.classification, classification, literal)
        for flag in _FLAGS:
            self.assertIs(getattr(result, flag), False, (literal, flag))

    def test_explicit_zero_interface_id_candidates_and_adjacency(self):
        prefixes = (
            "fc00:0:0:0", "fc00:0:0:1",
            "fcaa:1234:5678:9abc", "fd00:0:0:0",
            "fd12:3456:789a:bcde", "fdff:ffff:ffff:ffff",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                root = IPv6Address(prefix + "::")
                boundary = str(root)
                after = str(IPv6Address(int(root) + 1))
                self.assert_review(boundary, "HOLD", "UNTRUSTED")
                self.assert_review(after, "REVIEW_ONLY", "PRIVATE_USE")
        # IPv6 ::1 is independent loopback, not a ULA /64 endpoint.
        self.assert_review("::1", "REVIEW_ONLY", "LOOPBACK")

    def test_seeded_ula_subnets_review_only_for_nonzero_iid(self):
        rng = random.Random(14240064)
        for _ in range(96):
            upper = rng.randrange(0xFC << 56, 0xFE << 56)
            root = upper << 64
            for offset in (0, 1, 0x1234, (1 << 64) - 1):
                literal = str(IPv6Address(root | offset))
                with self.subTest(prefix=hex(upper), offset=offset):
                    if offset == 0:
                        self.assert_review(literal, "HOLD", "UNTRUSTED")
                    else:
                        self.assert_review(literal, "REVIEW_ONLY", "PRIVATE_USE")

    def test_single_ula_zero_iid_forces_atomic_batch_hold(self):
        for zero in ("fd00::", "fc00:0:0:1::", "fd12:3456:789a:bcde::"):
            raw = json.dumps({"literals": ["10.0.0.1", zero, "fd00::1"]}).encode()
            with self.subTest(zero=zero):
                self.assertEqual(review_batch_json(raw), ("HOLD", 0))
        safe = json.dumps({"literals": ["10.0.0.1", "fd00::1"]}).encode()
        self.assertEqual(review_batch_json(safe), ("REVIEW_ONLY", 2))

    def test_real_single_and_batch_clis_keep_flags_false_and_nonzero(self):
        cases = (
            ("review_scope_lab_literal_1424_offline.py", ["--literal", "fd00::"], None, 2, "HOLD"),
            ("review_scope_lab_literal_1424_offline.py", ["--literal", "fd00::1"], None, 3, "REVIEW_ONLY"),
            ("review_scope_lab_batch_1424_offline.py", ["--stdin-json"], b'{"literals":["10.0.0.1","fd00::"]}', 2, "HOLD"),
            ("review_scope_lab_batch_1424_offline.py", ["--stdin-json"], b'{"literals":["10.0.0.1","fd00::1"]}', 3, "REVIEW_ONLY"),
        )
        for script, args, stdin, returncode, expected in cases:
            with self.subTest(script=script, expected=expected):
                result = subprocess.run(
                    [sys.executable, "-B", str(_ROOT / "scripts" / script), *args],
                    input=stdin, capture_output=True, timeout=15, check=False,
                )
                self.assertEqual(result.returncode, returncode, result.stderr)
                self.assertEqual(result.stderr, b"")
                record = json.loads(result.stdout)
                self.assertEqual(record["status"], expected)
                for flag in _FLAGS:
                    self.assertIs(record[flag], False)
                self.assertNotIn(b"fd00::", result.stdout)
                self.assertNotIn(b"10.0.0.1", result.stdout)


if __name__ == "__main__":
    main()
