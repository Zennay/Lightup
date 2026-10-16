"""Offline stdin-only fictional LAB review CLI proof (#1487)."""
import builtins
from datetime import datetime, timezone
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.lab_session_lineage_cli_1487 import main, review_synthetic_json

DATE = "2030-01-01T12:00:00Z"
START = "2030-01-01T11:00:00Z"
END = "2030-01-01T13:00:00Z"


def packet(**updates):
    claim = {
        "lab_reference": "LAB-SYNTH-001",
        "operator_id": "ACTOR-SYNTH-001",
        "session_id": "SESSION-SYNTH-001",
        "engagement_id": "ENG-SYNTH-001",
        "asset_id": "ASSET-LOOPBACK-001",
        "capability_id": "CAP-REVIEW-ONLY",
        "starts_at": START,
        "expires_at": END,
        "revoked": False,
    }
    claim.update(updates)
    return {"schema": "FICTIONAL-LAB-LINEAGE-V1", "assessment_time": DATE, "claims": [claim]}


def encode(doc):
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


class SyntheticLineageStdinCli1487(unittest.TestCase):
    def assert_preview(self, value, expected):
        self.assertIs(type(value), str)
        self.assertEqual(value, expected)
        self.assertNotIn("ASSET-", value)
        self.assertNotIn("ACTOR-", value)
        self.assertNotIn("LAB-", value)
        self.assertNotIn("CONSENT-", value)

    @staticmethod
    def invoke(argv, payload):
        stream = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
        output = io.StringIO()
        with patch.object(sys, "stdin", stream), patch.object(sys, "stdout", output):
            code = main(argv)
        return code, output.getvalue()

    def test_exact_synthetic_packet_review_only_never_authorized(self):
        self.assert_preview(review_synthetic_json(encode(packet())), "REVIEW_ONLY")

    def test_revoked_and_expired_synthetic_packet_hold(self):
        for updated in ({"revoked": True}, {"expires_at": "2029-12-31T23:59:59Z"}):
            self.assert_preview(review_synthetic_json(encode(packet(**updated))), "HOLD")

    def test_malformed_json_never_leaks_input(self):
        for raw in (b"", b"bad", b"{", b"null", b"123", b"[]", b'""'):
            self.assert_preview(review_synthetic_json(raw), "HOLD")

    def test_requires_exact_envelope_fields(self):
        for corrupted in (
            {"claims": []},
            {"assessment_time": DATE},
            {"assessment_time": DATE, "claims": [], "allow": True},
            {"assessment_time": DATE, "claims": [], "debug": "PII"},
        ):
            self.assert_preview(review_synthetic_json(encode(corrupted)), "HOLD")

    def test_requires_exact_claim_fields(self):
        value = packet()
        value["claims"][0]["allow"] = True
        self.assert_preview(review_synthetic_json(encode(value)), "HOLD")
        value = packet()
        del value["claims"][0]["operator_id"]
        self.assert_preview(review_synthetic_json(encode(value)), "HOLD")

    def test_reject_duplicate_top_level_json_keys(self):
        obj = encode(packet()).decode("utf-8")
        duplicate = obj[:-1] + ',"assessment_time":"2030-01-01T12:00:00Z"}'
        self.assert_preview(review_synthetic_json(duplicate.encode()), "HOLD")

    def test_reject_duplicate_claim_json_keys(self):
        obj = encode(packet()).decode("utf-8")
        duplicate = obj.replace(
            '"revoked":false',
            '"revoked":false,"revoked":false',
            1,
        )
        self.assert_preview(review_synthetic_json(duplicate.encode()), "HOLD")

    def test_nonstandard_nan_infinity_are_rejected(self):
        for raw in (
            b'{"assessment_time":NaN,"claims":[]}',
            b'{"assessment_time":Infinity,"claims":[]}',
            b'{"assessment_time":-Infinity,"claims":[]}',
        ):
            self.assert_preview(review_synthetic_json(raw), "HOLD")

    def test_decode_is_strict_utf8(self):
        for raw in (b"\xff", b"{\xff}", b'{"claims":"\xc0\xaf"}'):
            self.assert_preview(review_synthetic_json(raw), "HOLD")

    def test_max_payload_is_bounded_in_bytes_not_characters(self):
        self.assert_preview(review_synthetic_json(b" " * 16385), "HOLD")
        self.assert_preview(review_synthetic_json(("é" * 9000).encode("utf-8")), "HOLD")
        self.assert_preview(review_synthetic_json(b" " * 16384), "HOLD")

    def test_nonbytes_payload_never_coerced(self):
        for raw in (None, "{}", bytearray(b"{}"), memoryview(b"{}"), 1, True):
            self.assert_preview(review_synthetic_json(raw), "HOLD")

    def test_time_must_be_exact_utc_text_no_conversion(self):
        for bad in (
            "2030-01-01 12:00:00Z",
            "2030-01-01T12:00:00+00:00",
            "2030-01-01T12:00:00.000Z",
            "2030-01-01T12:00:00z",
            "2030-13-01T12:00:00Z",
            "2030-01-01T12:00:00Z ",
            1,
            None,
            True,
        ):
            value = packet()
            value["assessment_time"] = bad
            self.assert_preview(review_synthetic_json(encode(value)), "HOLD")
            for field in ("starts_at", "expires_at"):
                value = packet(**{field: bad})
                self.assert_preview(review_synthetic_json(encode(value)), "HOLD")

    def test_bad_actor_or_asset_claim_is_hold(self):
        for bad in ("ACTOR-🔥", "ACTOR-OTHER/ORG", "", 1, None):
            self.assert_preview(
                review_synthetic_json(encode(packet(operator_id=bad))), "HOLD"
            )

    def test_duplicate_claim_session_is_hold(self):
        value = packet()
        value["claims"].append(dict(value["claims"][0]))
        self.assert_preview(review_synthetic_json(encode(value)), "HOLD")

    def test_bounded_claim_count(self):
        value = packet()
        value["claims"] = [
            dict(value["claims"][0], lab_reference=f"LAB-SYNTH-{i:03d}",
                 session_id=f"SESSION-SYNTH-{i:03d}")
            for i in range(64)
        ]
        self.assert_preview(review_synthetic_json(encode(value)), "HOLD")
        # The input itself exceeds 16 KiB, so the CLI declines it, even though
        # the underlying in-memory review supports up to 64 synthetic claims.
        value["claims"] = [value["claims"][0]]
        self.assert_preview(review_synthetic_json(encode(value)), "REVIEW_ONLY")

    def test_exit_code_never_means_permission(self):
        rc, output = self.invoke(["--synthetic-only"], encode(packet()))
        self.assertEqual(rc, 3)
        record = json.loads(output)
        self.assertEqual(record["status"], "REVIEW_ONLY")
        for flag in ("grants_authority", "can_issue_permit", "can_dispatch", "can_release"):
            self.assertIs(record[flag], False)
        self.assertIs(record["synthetic_only"], True)

    def test_hold_exit_code_remains_nonzero(self):
        rc, output = self.invoke(["--synthetic-only"], encode(packet(revoked=True)))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(output)["status"], "HOLD")

    def test_no_flag_fails_closed_without_consuming_input_or_echoing_args(self):
        rc, output = self.invoke(["--UNSAFE-SECRET-LAB-EXAMPLE"], encode(packet()))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(output)["status"], "HOLD")
        self.assertNotIn("UNSAFE", output)

    def test_stdout_does_not_reveal_client_identifiers(self):
        value = packet(operator_id="ACTOR-CLIENTPRIVATE-123")
        rc, output = self.invoke(["--synthetic-only"], encode(value))
        self.assertEqual(rc, 3)
        self.assertNotIn("CLIENTPRIVATE", output)
        self.assertNotIn("ACTOR-", output)
        self.assertNotIn("ASSET-", output)

    def test_no_network_file_sqlite_or_process_for_pure_parser(self):
        payload = encode(packet())
        with patch.object(builtins, "open", side_effect=AssertionError("file")), (
            patch.object(os, "open", side_effect=AssertionError("fd"))
        ), (
            patch.object(socket, "socket", side_effect=AssertionError("network"))
        ), (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS"))
        ), (
            patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite"))
        ), (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process"))
        ), (
            patch.object(os, "system", side_effect=AssertionError("shell"))
        ):
            self.assert_preview(review_synthetic_json(payload), "REVIEW_ONLY")
            self.assert_preview(review_synthetic_json(encode(packet(revoked=True))), "HOLD")


if __name__ == "__main__":
    unittest.main()
