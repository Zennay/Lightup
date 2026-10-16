"""Display-only strict JSON consumer acceptance for fictional notice #1495."""
from __future__ import annotations

import builtins
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.synthetic_scope_notice_consumer_1495 import (
    FictionalNoticeView, decode_fictional_notice_for_display,
)
from lightup.synthetic_scope_notice_1495 import _HOLD
from lightup.synthetic_scope_notice_cli_1495 import _INVALID_MESSAGE

INPUT = {
    "review_at": "2026-10-16T12:00:00Z",
    "proposals": [{
        "asset": "desk.example.test", "capability": "inventory_read", "risk": 4,
        "valid_from": "2026-10-16T11:00:00Z", "valid_until": "2026-10-16T13:00:00Z",
    }],
}


def run_cli(*flags, data=None, raw=None):
    return subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
         "--synthetic-only", *flags],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        input=(json.dumps(INPUT if data is None else data).encode() if raw is None else raw),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False,
    )


def canonical():
    result = run_cli("--format", "json")
    assert result.returncode == 2, result.stderr
    return json.loads(result.stdout)


def encoded(data):
    return json.dumps(data, ensure_ascii=True).encode()


class DisplayOnlyEnvelope1495(unittest.TestCase):
    def assert_no_authority(self, view):
        self.assertIsNotNone(view)
        self.assertIs(view.authorized, False)
        self.assertIs(view.consent_verified, False)
        self.assertIs(view.dispatch_allowed, False)
        self.assertIs(view.release_allowed, False)
        self.assertIn("NOT AUTHORIZED", view.notice)

    def test_real_cli_english_roundtrip(self):
        result = run_cli("--format", "json")
        self.assertEqual(result.returncode, 2)
        view = decode_fictional_notice_for_display(result.stdout)
        self.assertEqual(view.status, "REVIEW_ONLY")
        self.assertEqual(view.reviewed, 1)
        self.assertTrue(view.elevated_risk)
        self.assertIn("desk.example.test", view.notice)
        self.assert_no_authority(view)

    def test_real_cli_dutch_roundtrip(self):
        result = run_cli("--lang", "nl", "--format", "json")
        self.assertEqual(result.returncode, 2)
        view = decode_fictional_notice_for_display(result.stdout)
        self.assertEqual(view.status, "REVIEW_ONLY")
        self.assertIn("NIET GEAUTORISEERD", view.notice)
        self.assert_no_authority(view)

    def test_real_cli_hold_roundtrip_no_echo(self):
        result = run_cli("--format", "json", raw=b'{"asset":"secret.customer.com"}')
        self.assertEqual(result.returncode, 3)
        view = decode_fictional_notice_for_display(result.stdout)
        self.assertEqual(view.status, "HOLD")
        self.assertEqual(view.reviewed, 0)
        self.assertFalse(view.elevated_risk)
        self.assertNotIn("secret.customer.com", view.notice)
        self.assert_no_authority(view)

    def test_allowed_pure_hold_text(self):
        template = canonical()
        template.update(status="HOLD", notice=_HOLD, reviewed=0, elevated_risk=False)
        self.assert_no_authority(decode_fictional_notice_for_display(encoded(template)))

    def test_exact_invalid_cli_hold_text(self):
        template = canonical()
        template.update(status="HOLD", notice=_INVALID_MESSAGE, reviewed=0, elevated_risk=False)
        self.assert_no_authority(decode_fictional_notice_for_display(encoded(template)))

    def test_wrong_container_or_data_type_never_coerces(self):
        for raw in (None, {}, [], "{}", bytearray(b"{}"), memoryview(b"{}"),
                    123, True):
            with self.subTest(type=type(raw)):
                self.assertIsNone(decode_fictional_notice_for_display(raw))

    def test_invalid_utf8_and_surrogate_rejected(self):
        self.assertIsNone(decode_fictional_notice_for_display(b"\xff"))
        x = canonical()
        x["notice"] += "\ud800"
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_oversized_bytes_and_empty_are_rejected_preparse(self):
        for raw in (b"", b"X"*65537):
            self.assertIsNone(decode_fictional_notice_for_display(raw))

    def test_duplicate_json_keys_denied_even_when_equal(self):
        raw = run_cli("--format", "json").stdout
        self.assertIsNone(decode_fictional_notice_for_display(
            raw.replace(b'"authorized":false', b'"authorized":false,"authorized":false', 1)
        ))

    def test_any_true_authority_field_denied(self):
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            with self.subTest(key=key):
                x = canonical()
                x[key] = True
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_any_null_or_nonboolean_authority_field_denied(self):
        for value in (None, 0, 1, "false", [], {}):
            with self.subTest(value=value):
                x = canonical()
                x["authorized"] = value
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_unknown_or_missing_fields_denied_atomically(self):
        for key in canonical():
            with self.subTest(missing=key):
                x = canonical()
                del x[key]
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))
        x = canonical()
        x["override"] = False
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_invalid_status_or_type_denied(self):
        for value in ("APPROVED", "AUTHORIZED", "RELEASE", "", None, 1, True):
            with self.subTest(status=value):
                x = canonical()
                x["status"] = value
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_reviewed_requires_exact_int_with_correct_bounds(self):
        for value in (True, False, 0, -1, 33, "1", 1.0, None):
            with self.subTest(value=value):
                x = canonical()
                x["reviewed"] = value
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_elevated_risk_requires_bool(self):
        for value in (1, 0, "false", None, []):
            with self.subTest(value=value):
                x = canonical()
                x["elevated_risk"] = value
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_refuse_fake_hold_that_echoes_untrusted_target(self):
        x = canonical()
        x.update(status="HOLD", notice="HOLD — NOT AUTHORIZED — client.customer.com",
                 reviewed=0, elevated_risk=False)
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_hold_with_positive_count_or_risk_denied(self):
        for key, value in (("reviewed", 1), ("elevated_risk", True)):
            with self.subTest(key=key):
                x = canonical()
                x.update(status="HOLD", notice=_HOLD, reviewed=0, elevated_risk=False)
                x[key] = value
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_review_only_requires_exact_fictional_prefix(self):
        x = canonical()
        for prefix in ("AUTHORIZED", "REVIEW_ONLY", "NOT AUTHORIZED\n", "HOLD — NOT AUTHORIZED"):
            with self.subTest(prefix=prefix):
                candidate = x.copy()
                candidate["notice"] = prefix + candidate["notice"][len("NOT AUTHORIZED"):]
                self.assertIsNone(decode_fictional_notice_for_display(encoded(candidate)))

    def test_mismatched_count_denied(self):
        x = canonical()
        x["reviewed"] = 2
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_removed_warning_statement_denied(self):
        x = canonical()
        x["notice"] = x["notice"].replace(
            "No client consent, operator identity", "Client consent, operator identity"
        )
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_removed_non_authority_disclaimer_denied(self):
        x = canonical()
        x["notice"] = x["notice"].replace("This is NOT a grant, consent record", "This is a grant, consent record")
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_control_code_and_bidi_overrides_denied(self):
        for marker in ("\x00", "\x1b", "\r", "\u202e", "\u2066"):
            with self.subTest(marker=repr(marker)):
                x = canonical()
                x["notice"] += marker
                self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_unicode_dutch_lone_surrogate_denied(self):
        x = json.loads(run_cli("--lang", "nl", "--format", "json").stdout)
        x["notice"] += "\udfff"
        self.assertIsNone(decode_fictional_notice_for_display(encoded(x)))

    def test_views_immutable_and_never_runtime_permission(self):
        view = decode_fictional_notice_for_display(run_cli("--format", "json").stdout)
        self.assertIsInstance(view, FictionalNoticeView)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            view.authorized = True
        self.assert_no_authority(view)

    def test_no_files_network_database_or_subprocess_during_decoder(self):
        raw = run_cli("--format", "json").stdout
        with patch.object(builtins, "open", side_effect=AssertionError("file")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite")), \
             patch.object(subprocess, "run", side_effect=AssertionError("process")):
            view = decode_fictional_notice_for_display(raw)
            denied = decode_fictional_notice_for_display(b"{}")
        self.assert_no_authority(view)
        self.assertIsNone(denied)

    def test_schema_declares_zero_authority_and_exact_fields(self):
        with (ROOT/"schemas"/"fictional_scope_notice_1495.schema.json").open(encoding="utf-8") as f:
            schema = json.load(f)
        expected = {
            "status", "notice", "reviewed", "elevated_risk",
            "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
        }
        self.assertEqual(set(schema["properties"]), expected)
        self.assertEqual(set(schema["required"]), expected)
        self.assertIs(schema["additionalProperties"], False)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(schema["properties"][key]["const"], False)
        self.assertIn("NOT AUTHORIZED", schema["properties"]["notice"]["pattern"])


if __name__ == "__main__":
    unittest.main()
