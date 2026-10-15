"""Independent standard-library tests; no product target or DB dependencies."""
from __future__ import annotations

import json
import os
import random
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

    def test_rejects_socket_stdout_with_no_bytes(self):
        left, right = socket.socketpair()
        try:
            with subprocess.Popen([sys.executable, str(SCRIPT)], stdin=subprocess.PIPE,
                                  stdout=left, stderr=subprocess.PIPE) as proc:
                left.close()
                _, err = proc.communicate(input=OK, timeout=3)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(err, b"")
                right.settimeout(3)
                self.assertEqual(right.recv(4096), b"")
        finally:
            left.close()
            right.close()

    def test_accepts_regular_file_stdin_as_review_only(self):
        with tempfile.TemporaryFile() as source:
            source.write(OK)
            source.seek(0)
            p = subprocess.run([sys.executable, str(SCRIPT)], stdin=source,
                               capture_output=True, timeout=3)
            self.assertEqual(p.returncode, 3)
            self.assertEqual(p.stderr, b"")
            self.assertEqual(json.loads(p.stdout), {"status": "REVIEW_ONLY", **FALSE_FLAGS})

    def test_open_pipe_times_out_to_generic_hold(self):
        with subprocess.Popen([sys.executable, str(SCRIPT)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            assert proc.stdin is not None
            proc.stdin.write(OK)
            proc.stdin.flush()  # deliberately do not close: no EOF
            self.assertEqual(proc.wait(timeout=5), 2)
            assert proc.stdout is not None and proc.stderr is not None
            self.assertEqual(json.loads(proc.stdout.read()), {"status": "HOLD", **FALSE_FLAGS})
            self.assertEqual(proc.stderr.read(), b"")
            proc.stdin.close()

    def test_full_stdout_pipe_cannot_stall_process(self):
        read_fd, write_fd = os.pipe()
        try:
            os.set_blocking(write_fd, False)
            try:
                while True:
                    os.write(write_fd, b"Z" * 4096)
            except BlockingIOError:
                pass
            with subprocess.Popen([sys.executable, str(SCRIPT)], stdin=subprocess.PIPE,
                                  stdout=write_fd, stderr=subprocess.PIPE) as proc:
                self.assertEqual(proc.communicate(input=OK, timeout=3)[1], b"")
                self.assertEqual(proc.returncode, 2)
        finally:
            os.close(read_fd)
            os.close(write_fd)


    def test_seeked_regular_file_input_is_hold(self):
        with tempfile.TemporaryFile() as source:
            source.write(b'X' + OK)
            source.seek(1)
            p = subprocess.run([sys.executable, str(SCRIPT)], stdin=source,
                               capture_output=True, timeout=3)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(json.loads(p.stdout), {"status": "HOLD", **FALSE_FLAGS})
            self.assertEqual(p.stderr, b"")

    def test_oversized_regular_file_is_hold(self):
        with tempfile.TemporaryFile() as source:
            source.write(OK + b" " * (review.MAX_INPUT_BYTES + 1))
            source.seek(0)
            p = subprocess.run([sys.executable, str(SCRIPT)], stdin=source,
                               capture_output=True, timeout=3)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(json.loads(p.stdout), {"status": "HOLD", **FALSE_FLAGS})

    def test_empty_regular_file_is_hold(self):
        with tempfile.TemporaryFile() as source:
            p = subprocess.run([sys.executable, str(SCRIPT)], stdin=source,
                               capture_output=True, timeout=3)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(json.loads(p.stdout), {"status": "HOLD", **FALSE_FLAGS})

    def test_file_snapshot_modified_after_read_is_hold(self):
        from unittest.mock import patch
        # Deterministic mutation witness at the boundary, without flaky threads.
        import scope_777_review_provenance_offline as module
        with tempfile.TemporaryFile() as source:
            source.write(OK)
            source.seek(0)
            before = os.fstat(source.fileno())
            snapshot = (before.st_dev, before.st_ino, before.st_mode,
                        before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            with patch.object(module.os, "fstat", wraps=os.fstat) as mocked:
                # Different metadata after a real independent write, not a fake pass.
                source.write(b" ")
                source.flush()
                with self.assertRaises(ValueError):
                    module._verify_regular_input(source.fileno(), snapshot, len(OK))
                self.assertGreaterEqual(mocked.call_count, 1)



    def test_descriptor_rebinding_is_rejected_with_pinned_original_unchanged(self):
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        original = os.dup(r1)
        try:
            self.assertEqual(review._fd_identity(original), review._fd_identity(r1))
            self.assertIsNone(review._assert_original_fd_is_pinned(original, r1))
            os.dup2(r2, original)
            with self.assertRaises(ValueError):
                review._assert_original_fd_is_pinned(original, r1)
            os.write(w1, b"a")
            self.assertEqual(os.read(r1, 1), b"a")
        finally:
            for fd in (r1, w1, r2, w2, original):
                os.close(fd)

    def test_pin_failure_does_not_leak_duplicated_fds(self):
        from unittest.mock import patch
        with patch.object(review.os, "dup", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                review._pin_checked_fds()

    def test_safe_pin_matches_actual_runtime_descriptors(self):
        # The test-runner fds are not necessarily admitted (CI may redirect
        # stdout), so independently assert the checked pin equality invariant.
        r, w = os.pipe()
        pinned = os.dup(r)
        try:
            self.assertIsNone(review._assert_original_fd_is_pinned(r, pinned))
        finally:
            os.close(pinned)
            os.close(r)
            os.close(w)



    def test_second_descriptor_pin_failure_closes_first_copy(self):
        from unittest.mock import patch
        real_dup, real_close = os.dup, os.close
        made = []
        closed = []

        def controlled_dup(fd):
            if len(made) == 1:
                raise OSError("synthetic second dup failure")
            new_fd = real_dup(fd)
            made.append(new_fd)
            return new_fd

        def controlled_close(fd):
            closed.append(fd)
            return real_close(fd)

        with patch.object(review.os, "dup", side_effect=controlled_dup):
            with patch.object(review.os, "close", side_effect=controlled_close):
                with self.assertRaises(OSError):
                    review._pin_checked_fds()
        self.assertEqual(len(made), 1)
        self.assertEqual(closed, made)
        with self.assertRaises(OSError):
            os.fstat(made[0])

    def test_changed_output_fd_refuses_original_destination(self):
        source_read, source_write = os.pipe()
        other_read, other_write = os.pipe()
        replaceable = os.dup(source_write)
        pinned = os.dup(replaceable)
        try:
            os.dup2(other_write, replaceable)
            with self.assertRaises(ValueError):
                review._assert_original_fd_is_pinned(replaceable, pinned)
            # The nonauthorizing process would return 2 without writing a
            # receipt; do not write to either destination in this test.
            for fd in (source_read, other_read):
                os.set_blocking(fd, False)
                with self.assertRaises(BlockingIOError):
                    os.read(fd, 1)
        finally:
            for fd in (source_read, source_write, other_read, other_write,
                       replaceable, pinned):
                os.close(fd)


    def test_seeded_untrusted_bytes_never_produce_authority(self):
        rng = random.Random(777)
        expected_keys = {"status", *FALSE_FLAGS}
        for index in range(2048):
            data = rng.randbytes(rng.randrange(0, 4170))
            receipt = review.review_bytes(data)
            with self.subTest(case=index):
                self.assertEqual(set(receipt), expected_keys)
                self.assertIn(receipt["status"], ("REVIEW_ONLY", "HOLD"))
                self.assertEqual({key: receipt[key] for key in FALSE_FLAGS}, FALSE_FLAGS)

    def test_seeded_attached_trailing_bytes_always_hold(self):
        rng = random.Random(1777)
        alphabet = b"AZ09{}_[],:+x!@#"
        for size in (1, 2, 17, 31, 257, 1024):
            for variant in range(32):
                suffix = bytes(alphabet[rng.randrange(len(alphabet))] for _ in range(size))
                with self.subTest(size=size, variant=variant):
                    self.assert_receipt(OK + suffix, "HOLD")


    def test_noncanonical_unicode_aliases_are_hold_without_authority(self):
        cases = ("Jose\u0301",  # decomposed precomposable accent
                 "fictional\u00a0operator",  # non-breaking space
                 "fictional\u2028operator",  # line separator
                 "fictional\u2029operator",  # paragraph separator
                 "fictional\u2007operator",  # figure space
                 "fictional\u034foperator",  # invisible grapheme joiner
                 "fictional\ue000operator",  # private-use character
                 "fictional\ufdd0operator",  # Unicode noncharacter
                 "fictional\ufffeoperator")  # Unicode noncharacter
        for field in ("approved_by", "reference"):
            for value in cases:
                with self.subTest(field=field, candidate=repr(value)):
                    payload = {"approved_by": "fictional-operator", "reference": "ROE-FICTIONAL"}
                    payload[field] = value
                    self.assert_receipt(json.dumps(payload).encode("utf-8"), "HOLD")

    def test_precomposed_unicode_and_ascii_internal_spaces_review_only(self):
        cases = ("Jos\u00e9", "Fictional Lab Operator", "caf\u00e9-ROE-7")
        for value in cases:
            with self.subTest(value=value):
                payload = {"approved_by": value, "reference": "ROE-FICTIONAL"}
                self.assert_receipt(json.dumps(payload).encode("utf-8"), "REVIEW_ONLY")

    def test_unicode_noncanonical_real_cli_uniform_hold(self):
        payloads = ("fictional\u034foperator", "fictional\u00a0operator", "Jose\u0301")
        for name in payloads:
            with self.subTest(name=repr(name)):
                payload = json.dumps({"approved_by": name, "reference": "ROE-FICTIONAL"}).encode()
                proc = subprocess.run([sys.executable, str(SCRIPT)], input=payload,
                                      capture_output=True, timeout=3)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(json.loads(proc.stdout), {"status": "HOLD", **FALSE_FLAGS})


    def test_compatibility_unicode_identity_spoofs_are_hold(self):
        candidates = ("\uff26\uff49\uff43\uff54\uff49\uff4f\uff4e\uff41\uff4c",  # FULLWIDTH
                      "\ufb01ctional",  # ligature fi
                      "\u24d0pprover",  # circled a
                      "\u212aey-owner",  # Kelvin sign
                      "\u2163-operator",  # Roman numeral four
                      "grant-\u2460")  # circled digit
        for field in ("approved_by", "reference"):
            for value in candidates:
                with self.subTest(field=field, value=repr(value)):
                    claims = {"approved_by": "fictional-operator", "reference": "ROE-FICTIONAL"}
                    claims[field] = value
                    self.assert_receipt(json.dumps(claims).encode("utf-8"), "HOLD")

    def test_multibyte_utf8_exact_boundary(self):
        for n, expected in ((64, "REVIEW_ONLY"), (65, "HOLD")):
            payload = json.dumps({"approved_by": "\u00e9" * n,
                                  "reference": "ROE-FICTIONAL"}).encode("utf-8")
            self.assert_receipt(payload, expected)


    def test_real_cli_malformed_secret_claims_share_identical_hold_receipt(self):
        secret = "PRIVATE-DO-NOT-ECHO-customer-secret-123"
        malformed = (
            b"{}", b"[]", b"null", b"", b"\xff", b"not-json",
            b"{" + (b"x" * 5000) + b"}",
            json.dumps({"approved_by": secret, "reference": ""}).encode(),
            json.dumps({"approved_by": "", "reference": secret}).encode(),
            json.dumps({"approved_by": secret, "reference": secret,
                        "release_approved": True}).encode(),
            json.dumps({"approved_by": secret, "reference": secret,
                        "grant_id": "G-" + secret}).encode(),
            b'{"approved_by":"a","approved_by":"b","reference":"r"}',
            b'{"approved_by":"a","reference":"r","\\u0072eference":"s"}',
            json.dumps({"approved_by": "X\u200b" + secret,
                        "reference": "ROE-FICTIONAL"}).encode(),
        )
        receipts = set()
        for data in malformed:
            with self.subTest(first_bytes=repr(data[:30])):
                proc = subprocess.run([sys.executable, str(SCRIPT)], input=data,
                                      capture_output=True, timeout=4)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr, b"")
                self.assertNotIn(secret.encode(), proc.stdout)
                self.assertEqual(json.loads(proc.stdout), {"status": "HOLD", **FALSE_FLAGS})
                receipts.add(proc.stdout)
        self.assertEqual(len(receipts), 1, "all failed intakes must be byte-identical")

if __name__ == "__main__":
    unittest.main()
