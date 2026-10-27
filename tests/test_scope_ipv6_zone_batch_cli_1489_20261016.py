"""Actual pure batch and subprocess CLI contracts for fictional IPv6 zone #1489."""
import builtins
import json
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.ipv6_zone_batch_cli_1489 import (
    MAX_AUTHORITIES,
    MAX_INPUT_BYTES,
    SCHEMA,
    main,
    review_ipv6_zone_batch,
    review_stdin_document,
)
from lightup.ipv6_zone_review_1489 import ZoneReviewStatus


class SyntheticBatchTests(unittest.TestCase):
    def hold(self, value):
        result = review_ipv6_zone_batch(value)
        self.assertIs(result.status, ZoneReviewStatus.HOLD)
        self.assertIs(result.execution_allowed, False)
        self.assertIs(result.permit_allowed, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def review(self, value):
        result = review_ipv6_zone_batch(value)
        self.assertIs(result.status, ZoneReviewStatus.REVIEW_ONLY)
        self.assertIs(result.execution_allowed, False)
        self.assertIs(result.permit_allowed, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_two_distinct_canonical_fictional_ips_review_only(self):
        self.review(["[::1]", "https://[fd00::1]/"])

    def test_duplicate_same_literal_is_atomic_hold(self):
        self.hold(["[::1]", "[::1]"])

    def test_duplicate_wrapped_same_host_is_atomic_hold(self):
        self.hold(["[::1]", "http://[::1]"])
        self.hold(["https://[fd00::1]/", "http://[fd00::1]"])

    def test_reject_zone_amid_otherwise_canonical_cohort(self):
        for offender in ("[::1%lo]", "[fd00::1%eth0]", "http://[fe80::1%25en0]/"):
            with self.subTest(offender=offender):
                self.hold(["[::1]", offender, "[fd00::2]"])

    def test_reject_empty_nonlist_and_subclasses(self):
        class Impostor(list):
            pass
        for value in ([], (), {}, None, True, 10, "[::1]", Impostor(["[::1]"])):
            with self.subTest(type=type(value).__name__):
                self.hold(value)

    def test_reject_too_many_claims_before_parsing(self):
        self.hold(["[::1]"] * (MAX_AUTHORITIES + 1))

    def test_64_distinct_canonical_literal_shapes_are_review_only(self):
        self.review(["[fd00::%x]" % i for i in range(1, MAX_AUTHORITIES + 1)])

    def test_types_and_aliases_fail_atomic_before_any_release(self):
        for entry in (True, 123, b"[::1]", ["[::1]"], "[::ffff:192.0.2.1]"):
            with self.subTest(type=type(entry).__name__):
                self.hold(["[::1]", entry, "[fd00::1]"])

    def test_does_not_mutate_caller_inputs(self):
        records = ["[::1]", "https://[fd00::1]/"]
        original = records.copy()
        self.review(records)
        self.assertEqual(records, original)

    def test_forbid_file_socket_dns_db_subprocess_during_review(self):
        with (
            patch.object(builtins, "open", side_effect=AssertionError("file")),
            patch.object(os, "open", side_effect=AssertionError("os file")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")),
            patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        ):
            self.review(["[::1]", "[fd00::2]"])
            self.hold(["[::1]", "[::1%lo]"])

    def test_deterministic_permutation_replay(self):
        left = ["[::1]", "[fd00::1]", "[fd00::2]"]
        original = review_ipv6_zone_batch(left)
        for _ in range(256):
            self.assertEqual(review_ipv6_zone_batch(left[::-1]), original)
        self.assertEqual(left, ["[::1]", "[fd00::1]", "[fd00::2]"])


class StrictDocumentTests(unittest.TestCase):
    def document(self, authorities, **kwargs):
        return json.dumps({"schema": SCHEMA, "authorities": authorities, **kwargs}).encode()

    def test_valid_exact_schema_is_only_review_shape(self):
        result = review_stdin_document(self.document(["[::1]", "[fd00::2]"]))
        self.assertIs(result.status, ZoneReviewStatus.REVIEW_ONLY)
        self.assertIs(result.execution_allowed, False)

    def test_wrong_schema_rejected(self):
        raw = json.dumps({"schema": "LIGHTUP-FICTIONAL-IPV6-ZONE-REVIEW-V2", "authorities": ["[::1]"]}).encode()
        self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)

    def test_added_claimed_authority_is_rejected(self):
        for marker in ("consent", "operator", "grant", "dispatch_allowed", "release_allowed"):
            with self.subTest(marker=marker):
                raw = self.document(["[::1]"], **{marker: True})
                self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)

    def test_duplicate_json_keys_rejected(self):
        for raw in (
            b'{"schema":"a","schema":"b","authorities":["[::1]"]}',
            b'{"schema":"LIGHTUP-FICTIONAL-IPV6-ZONE-REVIEW-V1","authorities":[],"authorities":["[::1]"]}',
        ):
            self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)

    def test_nonfinite_json_tokens_rejected(self):
        for token in (b'NaN', b'Infinity', b'-Infinity'):
            raw = b'{"schema":"LIGHTUP-FICTIONAL-IPV6-ZONE-REVIEW-V1","authorities":' + token + b'}'
            self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)

    def test_non_utf8_and_invalid_json_rejected(self):
        for raw in (b'\xff', b'{', b'', b'[]', b'null', b'{}'):
            self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)

    def test_exact_input_byte_budget(self):
        self.assertIs(review_stdin_document(b' ' * (MAX_INPUT_BYTES + 1)).status, ZoneReviewStatus.HOLD)
        self.assertIs(review_stdin_document(self.document(["[::1]"])).status, ZoneReviewStatus.REVIEW_ONLY)

    def test_reject_string_subclass_and_other_top_level_types(self):
        class BytesSubclass(bytes):
            pass
        for raw in (BytesSubclass(self.document(["[::1]"])), "[::1]", None, 99):
            with self.subTest(type=type(raw).__name__):
                self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)

    def test_deep_json_is_held_without_recursion_crash(self):
        raw = b'[' * 1200 + b'0' + b']' * 1200
        self.assertIs(review_stdin_document(raw).status, ZoneReviewStatus.HOLD)


class SubprocessCliTests(unittest.TestCase):
    def invoke(self, raw, args=("--synthetic-only",)):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
        result = subprocess.run(
            [sys.executable, "-m", "lightup.ipv6_zone_batch_cli_1489", *args],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env=env,
        )
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(
            set(payload),
            {"status", "execution_allowed", "permit_allowed", "dispatch_allowed", "release_allowed"},
        )
        self.assertTrue(all(payload[key] is False for key in (
            "execution_allowed", "permit_allowed", "dispatch_allowed", "release_allowed"
        )))
        self.assertNotIn(b"fd00", result.stdout)
        self.assertNotIn(b"::1", result.stdout)
        self.assertEqual(result.stderr, b"")
        return result.returncode, payload

    def test_real_cli_valid_never_exits_zero(self):
        code, payload = self.invoke(json.dumps({"schema": SCHEMA, "authorities": ["[::1]", "[fd00::2]"]}).encode())
        self.assertEqual(code, 3)
        self.assertEqual(payload["status"], "REVIEW_ONLY")

    def test_real_cli_scoped_or_noncanonical_ipv6_hold_nonzero(self):
        for value in ("[fd00::1%eth0]", "HTTP://[::1]", "http://[::1]?", "http://[::1]#"):
            with self.subTest(value=value):
                code, payload = self.invoke(json.dumps({"schema": SCHEMA, "authorities": [value]}).encode())
                self.assertEqual(code, 2)
                self.assertEqual(payload["status"], "HOLD")

    def test_real_cli_default_no_args_refuses(self):
        code, payload = self.invoke(b"", args=())
        self.assertEqual(code, 2)
        self.assertEqual(payload["status"], "HOLD")

    def test_real_cli_unknown_flags_refuse(self):
        code, payload = self.invoke(b"", args=("--synthetic-only", "--release"))
        self.assertEqual(code, 2)
        self.assertEqual(payload["status"], "HOLD")

    def test_real_cli_oversize_stdin_hold(self):
        code, payload = self.invoke(b' ' * (MAX_INPUT_BYTES + 10))
        self.assertEqual(code, 2)
        self.assertEqual(payload["status"], "HOLD")

    def test_real_cli_malformed_and_duplicate_json_hold(self):
        for raw in (b'{', b'{"schema":"x","schema":"x"}'):
            code, payload = self.invoke(raw)
            self.assertEqual(code, 2)
            self.assertEqual(payload["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
