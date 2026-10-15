"""Synthetic-only CLI tests for #737: bounded, duplicate-safe and HOLD."""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from scripts import scope_737_revocation_review_cli as cli


def row(at=None, actor=None, reason=None):
    return {"revoked_at": at, "revoked_by": actor, "revocation_reason": reason}


def encoded(rows, version=1):
    return json.dumps({"schema_version": version, "records": rows}).encode("utf-8")


def review(raw):
    result, status = cli._review_bytes(raw)
    assert type(result) is dict
    assert result["decision"] == "HOLD"
    assert result["can_authorize"] is False
    assert result["can_dispatch"] is False
    assert result["can_release"] is False
    assert status in (0, 2)
    return result, status


class RevocationReviewCliAcceptance(unittest.TestCase):
    def test_empty_valid_unrevoked_still_hold(self):
        r, status = review(encoded([row()]))
        self.assertEqual(status, 0)
        self.assertEqual(r["result"], "review_only")
        self.assertEqual(r["class_counts"][-1],
                         {"classification": "no_revocation_claim", "count": 1})

    def test_canonical_utc_revocation_still_hold(self):
        r, status = review(encoded([row("2026-10-15T10:15:30Z", "fictional-actor", "fixture")]))
        self.assertEqual(status, 0)
        self.assertEqual(r["class_counts"][1],
                         {"classification": "revocation_recorded", "count": 1})

    def test_stale_actor_reason_denied_as_inconsistent(self):
        r, status = review(encoded([row(actor="fictional-actor", reason="fixture")]))
        self.assertEqual(status, 0)
        self.assertEqual(r["class_counts"][0],
                         {"classification": "inconsistent", "count": 1})

    def test_all_three_classes_counted_without_echo(self):
        r, status = review(encoded([
            row(), row(actor="fictional-actor"),
            row("2026-10-15T10:15:30Z", "fictional-actor", "fixture"),
        ]))
        self.assertEqual(status, 0)
        self.assertEqual([x["count"] for x in r["class_counts"]], [1, 1, 1])
        self.assertNotIn("fictional-actor", json.dumps(r))

    def test_bool_version_rejected_as_not_exact_integer(self):
        for version in (True, False, 1.0, "1", None, 0, 2):
            with self.subTest(v=version):
                r, status = review(encoded([row()], version))
                self.assertEqual(status, 2)
                self.assertEqual(r["reason_codes"], ["invalid_schema_version"])

    def test_noncanonical_top_level_rejected(self):
        for data in (b"[]", b"null", b"false", b"1", b'"fictional"', b'{}'):
            with self.subTest(data=data):
                r, status = review(data)
                self.assertEqual(status, 2)
                self.assertEqual(r["result"], "invalid_input")

    def test_top_level_extra_key_rejected(self):
        r, status = review(b'{"schema_version":1,"records":[],"secret":"fictional"}')
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_top_schema"])
        self.assertNotIn("fictional", repr(r))

    def test_top_level_missing_key_rejected(self):
        r, status = review(b'{"schema_version":1}')
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_top_schema"])

    def test_duplicate_top_level_key_rejected_before_review(self):
        r, status = review(b'{"schema_version":1,"schema_version":1,"records":[]}')
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_json"])

    def test_duplicate_record_key_rejected_before_review(self):
        raw = b'{"schema_version":1,"records":[{"revoked_at":null,"revoked_at":null,"revoked_by":null,"revocation_reason":null}]}'
        r, status = review(raw)
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_json"])

    def test_unicode_escape_duplicate_is_still_duplicate(self):
        raw = b'{"schema_version":1,"records":[{"revoked_at":null,"revoked_by":null,"revocation_reason":null,"revoked\\u005fat":null}]}'
        r, status = review(raw)
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_json"])

    def test_unsupported_json_constants_rejected(self):
        for raw in (b'NaN', b'Infinity', b'-Infinity'):
            with self.subTest(constant=raw):
                r, status = review(b'{"schema_version":1,"records":[{"revoked_at":' + raw +
                                   b',"revoked_by":null,"revocation_reason":null}]}')
                self.assertEqual(status, 2)
                self.assertEqual(r["reason_codes"], ["invalid_json"])

    def test_malformed_json_never_echoes_source(self):
        secret = "fictional-private-identifier"
        for raw in (b"{", secret.encode(), b"not-json " + secret.encode()):
            r, status = review(raw)
            self.assertEqual(status, 2)
            self.assertNotIn(secret, repr(r))

    def test_invalid_utf8_fails_closed(self):
        r, status = review(b'{"schema_version":1,"records":[]}\xff')
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_json"])

    def test_nonbytes_in_memory_input_rejected(self):
        for raw in (None, False, "", bytearray(b"{}"), {}, 0):
            with self.subTest(t=type(raw).__name__):
                r, status = review(raw)
                self.assertEqual(status, 2)
                self.assertEqual(r["reason_codes"], ["noncanonical_input_bytes"])

    def test_oversize_input_fails_before_parsing(self):
        raw = b'{"fictional_secret":' + b'a' * cli._MAX_INPUT_BYTES
        r, status = review(raw)
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["input_too_large"])
        self.assertEqual(r["class_counts"], [])

    def test_one_byte_at_limit_not_oversize(self):
        r, status = review(b" " * cli._MAX_INPUT_BYTES)
        self.assertEqual(status, 2)
        self.assertEqual(r["reason_codes"], ["invalid_json"])

    def test_zero_and_over64_records_rejected(self):
        for rows in ([], [row()] * 65):
            r, status = review(encoded(rows))
            self.assertEqual(status, 2)
            self.assertEqual(r["reason_codes"], ["invalid_record_count"])

    def test_64_canonical_rows_are_structurally_accepted(self):
        r, status = review(encoded([row() for _ in range(64)]))
        self.assertEqual(status, 0)
        self.assertEqual(r["class_counts"][-1]["count"], 64)

    def test_records_must_be_exact_list_not_string_or_null(self):
        for records in (None, (), "fake", 0, False, {}):
            with self.subTest(t=type(records).__name__):
                raw = json.dumps({"schema_version": 1, "records": records}).encode()
                r, status = review(raw)
                self.assertEqual(status, 2)
                self.assertEqual(r["reason_codes"], ["invalid_record_count"])

    def test_one_invalid_entry_rejects_entire_batch_atomically(self):
        for invalid in (None, [], "fictional", False, {"revoked_at": None},
                        dict(row(), extra_secret="fictional-sensitive")):
            with self.subTest(t=type(invalid).__name__):
                r, status = review(encoded([row(), invalid, row()]))
                self.assertEqual(status, 2)
                self.assertEqual(r["class_counts"], [])
                self.assertEqual(r["reason_codes"], ["invalid_record_schema"])
                self.assertNotIn("fictional-sensitive", repr(r))

    def test_whitespace_trimmed_provenance_does_not_silently_authorize(self):
        r, status = review(encoded([row("2026-10-15T10:00:00Z", " fictional ", "reason")]))
        self.assertEqual(status, 0)
        self.assertEqual(r["class_counts"][0]["count"], 1)

    def test_bare_iso_datetime_is_noncanonical_not_promoted(self):
        for stamp in ("2026-10-15", "2026-10-15T10:00:00+00:00",
                      "2026-10-15T10:00:00", "2026-10-15T10:00:00z",
                      "2026-10-15T10:00:00.1Z", "2026-1-15T10:00:00Z"):
            with self.subTest(stamp=stamp):
                r, status = review(encoded([row(stamp, "fictional", "reason")]))
                self.assertEqual(status, 0)
                self.assertEqual(r["class_counts"][0]["count"], 1)

    def test_nonexistent_utc_calendar_datetime_is_noncanonical(self):
        for stamp in ("2026-02-30T10:00:00Z", "2026-13-01T10:00:00Z",
                      "2026-10-15T25:00:00Z", "2026-10-15T10:61:00Z"):
            with self.subTest(stamp=stamp):
                r, status = review(encoded([row(stamp, "fictional", "reason")]))
                self.assertEqual(status, 0)
                self.assertEqual(r["class_counts"][0]["count"], 1)

    def test_json_unicode_actor_not_reflected_in_output(self):
        secret = "private-actor-\u2764-" + "X" * 14
        r, status = review(encoded([row("2026-10-15T10:00:00Z", secret, "fictional")]))
        self.assertEqual(status, 0)
        self.assertNotIn(secret, json.dumps(r, ensure_ascii=False))

    def test_output_is_fixed_schema_and_no_raw_values(self):
        private = "fictional-client-secret-cannot-appear"
        r, status = review(encoded([row(actor=private)]))
        self.assertEqual(status, 0)
        self.assertEqual(set(r), {
            "schema_version", "decision", "result", "reason_codes",
            "class_counts", "can_authorize", "can_dispatch", "can_release",
        })
        self.assertNotIn(private, repr(r))

    def test_cli_main_stdin_stdout_roundtrip_success(self):
        fake_stdin = io.TextIOWrapper(io.BytesIO(encoded([row()])), encoding="utf-8")
        fake_stdout = io.StringIO()
        with patch.object(cli.sys, "stdin", fake_stdin), patch.object(cli.sys, "stdout", fake_stdout):
            self.assertEqual(cli.main(), 0)
        data = json.loads(fake_stdout.getvalue())
        self.assertEqual(data["decision"], "HOLD")
        self.assertIs(data["can_authorize"], False)
        self.assertEqual(fake_stdout.getvalue().count("\n"), 1)

    def test_cli_main_stdin_stdout_roundtrip_invalid(self):
        fake_stdin = io.TextIOWrapper(io.BytesIO(b"fictional-private-data"), encoding="utf-8")
        fake_stdout = io.StringIO()
        with patch.object(cli.sys, "stdin", fake_stdin), patch.object(cli.sys, "stdout", fake_stdout):
            self.assertEqual(cli.main(), 2)
        self.assertNotIn("fictional-private-data", fake_stdout.getvalue())
        self.assertEqual(json.loads(fake_stdout.getvalue())["decision"], "HOLD")


if __name__ == "__main__":
    unittest.main()
