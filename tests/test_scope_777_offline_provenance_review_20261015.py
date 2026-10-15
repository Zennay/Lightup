"""Independent standard-library tests; no product target or DB dependencies."""
from __future__ import annotations

import json
import socket
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scope_777_review_provenance_offline as review

SCRIPT = Path(__file__).parents[1] / "scripts" / "scope_777_review_provenance_offline.py"
OK = b'{"approved_by":"fictional-operator","reference":"ROE-FICTIONAL"}'
FALSE_FLAGS = {key: False for key in review.AUTHORITY_FLAGS}


class SyntheticProvenanceReviewTests(unittest.TestCase):
    def assert_receipt(self, data: bytes, expected: str):
        result = review.review_bytes(data)
        self.assertEqual(result, {"status": expected, **FALSE_FLAGS})
        self.assertNotIn("fictional-operator", str(result))
        self.assertNotIn("ROE-FICTIONAL", str(result))

    def test_valid_is_review_only_never_authorized(self):
        self.assert_receipt(OK, "REVIEW_ONLY")

    def test_invalid_payloads_uniform_hold(self):
        invalid = (
            b"", b"{}", b"[]", b"null", b"false", b"5", b"not-json",
            b"\xef\xbb\xbf" + OK, OK + b"{}", b"\xff", b"[" * 1200,
            b'{}' + b' ' * (review.MAX_INPUT_BYTES - 1),
            b'{"approved_by":"a","approved_by":"b","reference":"x"}',
            b'{"approved_by":"a","\\u0061pproved_by":"b","reference":"x"}',
            b'{"approved_by":"x","reference":"z","approved":true}',
            b'{"approved_by":"x","reference":"z","status":"PASS"}',
            b'{"approved_by":"x","reference":"z","num":NaN}',
            b'{"approved_by":"x","reference":"z","num":Infinity}',
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate[:40]):
                self.assert_receipt(candidate, "HOLD")

    def test_malformed_field_variants_uniform_hold(self):
        for field in ("approved_by", "reference"):
            for value in (None, True, False, 0, 2.5, [], {}, "", "  ", " test", "test ",
                          "\n", "\u200b", "x\u200by", "x\u202e", "a" * 129):
                with self.subTest(field=field, value=str(value)[:18]):
                    payload = {"approved_by": "fictional-operator", "reference": "ROE-FICTIONAL"}
                    payload[field] = value
                    self.assert_receipt(json.dumps(payload).encode("utf8"), "HOLD")

    def test_exact_input_limit(self):
        tail = review.MAX_INPUT_BYTES - len(OK)
        self.assert_receipt(OK + b" " * tail, "REVIEW_ONLY")
        self.assert_receipt(OK + b" " * (tail + 1), "HOLD")

    def test_exact_value_limit(self):
        for size, status in ((128, "REVIEW_ONLY"), (129, "HOLD")):
            data = json.dumps({"approved_by": "a" * size, "reference": "ref"}).encode()
            self.assert_receipt(data, status)

    def test_nonbytes_inputs_hold(self):
        for value in (None, "{}", bytearray(OK), memoryview(OK), 7, True):
            self.assertEqual(review.review_bytes(value), {"status": "HOLD", **FALSE_FLAGS})

    def test_real_subprocess_valid_and_invalid_nonzero(self):
        for data, expected, exit_code in ((OK, "REVIEW_ONLY", 3), (b'{"bad":true}', "HOLD", 2)):
            with self.subTest(status=expected):
                p = subprocess.run([sys.executable, str(SCRIPT)], input=data,
                                   capture_output=True, timeout=3)
                self.assertEqual(p.returncode, exit_code)
                self.assertEqual(p.stderr, b"")
                self.assertEqual(json.loads(p.stdout), {"status": expected, **FALSE_FLAGS})
                self.assertLess(len(p.stdout), 250)

    def test_disallow_extra_cli_arguments(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--approved"],
                           input=OK, capture_output=True, timeout=3)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")
        self.assertEqual(p.stderr, b"")


    def test_field_order_and_json_whitespace_cannot_grant_authority(self):
        for actor, ref in (("fictional-operator", "ROE-FICTIONAL"),
                           ("operator-é", "fictional-reference")):
            variants = (
                json.dumps({"approved_by": actor, "reference": ref}),
                json.dumps({"reference": ref, "approved_by": actor}, ensure_ascii=False),
                json.dumps({"approved_by": actor, "reference": ref}, ensure_ascii=True,
                           indent=2, sort_keys=True),
            )
            for encoded in variants:
                with self.subTest(case=encoded[:42]):
                    self.assert_receipt(encoded.encode("utf-8"), "REVIEW_ONLY")

    def test_spoofed_permit_fields_are_always_hold(self):
        for forbidden in ("authorization_verified", "permit_issued", "dispatch_enabled",
                          "merge_approved", "deploy_approved", "release_approved", "status",
                          "proof", "grant_id", "scope", "client_id", "target"):
            with self.subTest(field=forbidden):
                payload = {"approved_by": "fictional-operator", "reference": "ROE-FICTIONAL",
                           forbidden: True}
                self.assert_receipt(json.dumps(payload).encode(), "HOLD")

    def test_subprocess_rejects_oversize_and_duplicate_escaped_key(self):
        payloads = (
            OK + b" " * (review.MAX_INPUT_BYTES + 1),
            b'{"approved_by":"x","reference":"y","\\u0072eference":"z"}',
        )
        for payload in payloads:
            with self.subTest(size=len(payload)):
                p = subprocess.run([sys.executable, str(SCRIPT)], input=payload,
                                   capture_output=True, timeout=3)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(p.stderr, b"")
                self.assertEqual(json.loads(p.stdout), {"status": "HOLD", **FALSE_FLAGS})

    def test_parse_never_mutates_input_buffer(self):
        original = OK
        first = review.review_bytes(original)
        second = review.review_bytes(original)
        self.assertEqual(first, second)
        self.assertEqual(original, OK)
        self.assertEqual(first, {"status": "REVIEW_ONLY", **FALSE_FLAGS})


    def test_rejects_socket_stdin_without_consuming_or_reporting(self):
        left, right = socket.socketpair()
        try:
            with subprocess.Popen([sys.executable, str(SCRIPT)], stdin=left,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                left.close()
                right.sendall(OK)
                right.shutdown(socket.SHUT_WR)
                out, err = proc.communicate(timeout=3)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(out, b"")
                self.assertEqual(err, b"")
        finally:
            left.close()
            right.close()

    def test_rejects_file_stdout_without_writing_receipt(self):
        with tempfile.TemporaryFile() as destination:
            p = subprocess.run([sys.executable, str(SCRIPT)], input=OK,
                               stdout=destination, stderr=subprocess.PIPE, timeout=3)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(p.stderr, b"")
            destination.seek(0)
            self.assertEqual(destination.read(), b"")


if __name__ == "__main__":
    unittest.main()
