"""Offline, synthetic, fail-closed acceptance for issue #1514."""
from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
from fictional_protocol_floor_review_1514 import (
    FictionalFrame as Frame,
    ReviewReceipt,
    review_protocol_floor as review,
)
from fictional_protocol_floor_cli_1514 import _review_raw


def pair():
    return (Frame(3, "case-alpha.example.test", 1),
            Frame(3, "case-alpha.example.test", 2))


def encoded(frames=None, version=3, floor=3):
    if frames is None:
        frames = [
            {"version": 3, "case_id": "case-alpha.example.test", "sequence": 1},
            {"version": 3, "case_id": "case-alpha.example.test", "sequence": 2},
        ]
    return json.dumps(
        {"expected_version": version, "minimum_version": floor, "frames": frames},
        ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


class PureProtocolReviewTests(unittest.TestCase):
    def assert_no_authority(self, receipt, status):
        self.assertIs(type(receipt), ReviewReceipt)
        self.assertEqual(receipt.status, status)
        for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(receipt, name), False)

    def test_consistent_synthetic_cohort_is_only_review(self):
        self.assert_no_authority(review(pair(), 3, 3), "REVIEW_ONLY")

    def test_floor_below_expected_is_allowed_but_no_fallback(self):
        self.assert_no_authority(review(pair(), 3, 2), "REVIEW_ONLY")
        self.assert_no_authority(review((Frame(2, "case-alpha.example.test", 1),), 3, 2), "HOLD")

    def test_floor_higher_than_expected_is_hold(self):
        self.assert_no_authority(review(pair(), 3, 4), "HOLD")

    def test_future_unsupported_schema_is_hold(self):
        self.assert_no_authority(review((Frame(4, "case-alpha.example.test", 1),), 3, 3), "HOLD")

    def test_reject_mixed_schema_versions_and_rollback(self):
        for candidate in (
            (Frame(3, "case-alpha.example.test", 1), Frame(2, "case-alpha.example.test", 2)),
            (Frame(2, "case-alpha.example.test", 1), Frame(3, "case-alpha.example.test", 2)),
            (Frame(4, "case-alpha.example.test", 1), Frame(3, "case-alpha.example.test", 2)),
        ):
            with self.subTest(candidate=candidate):
                self.assert_no_authority(review(candidate, 3, 2), "HOLD")

    def test_reject_gap_duplicate_and_reordering(self):
        for indices in ((1, 1), (1, 3), (2, 1), (0, 1), (2, 2)):
            with self.subTest(indices=indices):
                frames = tuple(Frame(3, "case-alpha.example.test", i) for i in indices)
                self.assert_no_authority(review(frames, 3, 3), "HOLD")

    def test_reject_cross_case_splice(self):
        frames = (Frame(3, "case-alpha.example.test", 1),
                  Frame(3, "case-beta.example.test", 2))
        self.assert_no_authority(review(frames, 3, 3), "HOLD")

    def test_reject_noncanonical_case_identifiers(self):
        for value in ("case-a.example.test.", "CASE-a.example.test",
                      "case-a.evil.test", "case-á.example.test",
                      "case-.example.test", "case-a@example.test",
                      "", "case-abcdefghijklmnopqrstuvwxy.example.test",
                      None, b"case-a.example.test", True):
            with self.subTest(value=value):
                self.assert_no_authority(review((Frame(3, value, 1),), 3, 3), "HOLD")

    def test_reject_frames_not_exact_builtin_tuple(self):
        for value in ([], tuple(), (Frame(3, "case-a.example.test", 1),) * 33,
                      "anything", None, (object(),)):
            with self.subTest(kind=type(value).__name__):
                self.assert_no_authority(review(value, 3, 3), "HOLD")

    def test_reject_version_and_sequence_type_confusion(self):
        for value in (True, False, 3.0, "3", None, object(), -1, 0, 17):
            with self.subTest(value=str(type(value))):
                self.assert_no_authority(review(pair(), value, 3), "HOLD")
                self.assert_no_authority(review(pair(), 3, value), "HOLD")
                self.assert_no_authority(
                    review((Frame(value, "case-a.example.test", 1),), 3, 3), "HOLD")
                self.assert_no_authority(
                    review((Frame(3, "case-a.example.test", value),), 3, 3), "HOLD")

    def test_reject_primitive_subclasses(self):
        class IntSub(int):
            pass
        class StrSub(str):
            pass
        class FrameSub(Frame):
            pass
        self.assert_no_authority(review(pair(), IntSub(3), 3), "HOLD")
        self.assert_no_authority(review((Frame(IntSub(3), "case-a.example.test", 1),), 3, 3), "HOLD")
        self.assert_no_authority(review((Frame(3, StrSub("case-a.example.test"), 1),), 3, 3), "HOLD")
        self.assert_no_authority(review((FrameSub(3, "case-a.example.test", 1),), 3, 3), "HOLD")

    def test_receipt_is_frozen_and_constructor_cannot_grant(self):
        receipt = review(pair(), 3, 3)
        with self.assertRaises(FrozenInstanceError):
            receipt.authorized = True
        with self.assertRaises(TypeError):
            ReviewReceipt("REVIEW_ONLY", authorized=True)
        with self.assertRaises((ValueError, TypeError)):
            replace(receipt, consent_verified=True)
        object.__setattr__(receipt, "authorized", True)
        self.assert_no_authority(review(pair(), 3, 3), "REVIEW_ONLY")

    def test_pure_review_does_not_perform_file_or_network_io(self):
        with patch("builtins.open", side_effect=AssertionError("file I/O")), \
             patch.object(socket, "socket", side_effect=AssertionError("network I/O")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process I/O")):
            self.assert_no_authority(review(pair(), 3, 3), "REVIEW_ONLY")
            self.assert_no_authority(review(pair(), 2, 2), "HOLD")


class ProtocolCliTests(unittest.TestCase):
    def test_canonical_review_only_and_bounded_exit(self):
        self.assertEqual(_review_raw(encoded()), "REVIEW_ONLY")
        result = subprocess.run(
            [sys.executable, str(TOOLS / "fictional_protocol_floor_cli_1514.py")],
            input=encoded(), capture_output=True, check=False, timeout=10
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"REVIEW_ONLY\n")
        self.assertEqual(result.stderr, b"")

    def test_canonical_downgrade_hold_without_echo(self):
        rows = [{"version": 2, "case_id": "case-private.example.test", "sequence": 1}]
        result = subprocess.run(
            [sys.executable, str(TOOLS / "fictional_protocol_floor_cli_1514.py")],
            input=encoded(rows), capture_output=True, check=False, timeout=10
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"HOLD\n")
        self.assertNotIn(b"private", result.stdout + result.stderr)

    def test_duplicate_unicode_alias_and_out_of_order_json_hold(self):
        valid = encoded()
        for altered in (
            b'{"expected_version":3,"expected_version":3,"minimum_version":3,"frames":[]}',
            valid.replace(b"expected_version", b"expected_versi\\u006fn"),
            valid.replace(b"minimum_version", b"minimum_versi\\u006fn"),
            valid.replace(b'"version":3', b'"version":3,"version":3'),
            valid.replace(b'"case_id"', b'"case_\\u0069d"'),
            valid.replace(b',"minimum_version":3', b', "minimum_version":3'),
            valid.replace(b'"expected_version":3,"minimum_version":3',
                          b'"minimum_version":3,"expected_version":3'),
            valid + b"\n", valid + b"{}",
        ):
            with self.subTest(altered=altered[:50]):
                self.assertEqual(_review_raw(altered), "HOLD")

    def test_invalid_json_numbers_and_utf8_hold(self):
        for raw in (b'NaN', b'Infinity', b'-Infinity',
                    encoded().replace(b'"version":3', b'"version":NaN'),
                    encoded().replace(b'"sequence":1', b'"sequence":1e0'),
                    encoded() + "\N{SNOWMAN}".encode("utf-8"), b"\x00"):
            with self.subTest(raw=raw[:40]):
                self.assertEqual(_review_raw(raw), "HOLD")

    def test_schema_alias_extra_fields_bool_and_empty_cohort_hold(self):
        good = encoded()
        for raw in (
            good.replace(b'"version":3', b'"version":true'),
            good.replace(b'"sequence":1', b'"sequence":true'),
            good.replace(b'"expected_version":3', b'"expected_version":true'),
            good.replace(b'"version":3', b'"version":3,"legacy":true'),
            encoded([]),
            good.replace(b'"minimum_version":3', b'"minimum_version":4'),
        ):
            with self.subTest(raw=raw[:40]):
                self.assertEqual(_review_raw(raw), "HOLD")

    def test_cli_eof_truncated_oversize_no_unsafe_exit(self):
        raw = encoded()
        for b in (b"", b"{", raw[:-1], b" " * 4097):
            with self.subTest(n=len(b)):
                result = subprocess.run(
                    [sys.executable, str(TOOLS / "fictional_protocol_floor_cli_1514.py")],
                    input=b, capture_output=True, check=False, timeout=10)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(result.stdout, b"HOLD\n")
                self.assertEqual(result.stderr, b"")

    def test_exact_32_record_cohort_and_33_record_hold(self):
        records = tuple(Frame(3, "case-alpha.example.test", i) for i in range(1, 33))
        self.assertEqual(review(records, 3, 3).status, "REVIEW_ONLY")
        self.assertEqual(review(records + (Frame(3, "case-alpha.example.test", 33),), 3, 3).status, "HOLD")
        rows = [{"version": 3, "case_id": "case-alpha.example.test", "sequence": i}
                for i in range(1, 33)]
        self.assertLessEqual(len(encoded(rows)), 4096)
        self.assertEqual(_review_raw(encoded(rows)), "REVIEW_ONLY")
        self.assertEqual(_review_raw(encoded(rows + [rows[-1]])), "HOLD")

    def test_actual_fragmented_pipe_and_eof_finalization(self):
        raw = encoded()
        # Read-ahead and split writes must not turn an incomplete JSON prefix into a decision.
        with subprocess.Popen(
            [sys.executable, str(TOOLS / "fictional_protocol_floor_cli_1514.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            for fragment in (raw[:1], raw[1:4], raw[4:19], raw[19:48], raw[48:]):
                process.stdin.write(fragment)
                process.stdin.flush()
            process.stdin.close()
            output = process.stdout.read()
            errors = process.stderr.read()
            self.assertEqual(process.wait(timeout=10), 2)
            self.assertEqual(output, b"REVIEW_ONLY\n")
            self.assertEqual(errors, b"")

    def test_encoded_combining_mark_and_case_alias_hold(self):
        for variant in ("case-a" + chr(0x301) + ".example.test", "case-A.example.test",
                        "case-a.example.test.", "case-a.example.tesT"):
            rows = [{"version": 3, "case_id": variant, "sequence": 1}]
            self.assertEqual(_review_raw(encoded(rows)), "HOLD")

    def test_deeply_nested_hostile_json_is_generic_hold_without_traceback(self):
        # 1,600 levels fit the input byte cap and can trigger json decoder recursion.
        hostile = b"[" * 1600 + b"0" + b"]" * 1600
        self.assertLessEqual(len(hostile), 4096)
        self.assertEqual(_review_raw(hostile), "HOLD")
        result = subprocess.run(
            [sys.executable, str(TOOLS / "fictional_protocol_floor_cli_1514.py")],
            input=hostile, capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"HOLD\\n".replace(b"\\n", b"\n"))
        self.assertEqual(result.stderr, b"")

    def test_cli_all_one_byte_corruptions_do_not_authorize(self):
        valid = encoded()
        for i in range(len(valid)):
            modified = valid[:i] + b"\x00" + valid[i + 1:]
            self.assertEqual(_review_raw(modified), "HOLD")


if __name__ == "__main__":
    unittest.main()
