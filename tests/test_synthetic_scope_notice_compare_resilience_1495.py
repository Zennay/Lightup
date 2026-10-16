"""Bounded, side-effect-free fictional comparison resilience tests (#1495)."""
from __future__ import annotations

import builtins
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

from lightup.synthetic_scope_notice_compare_1495 import compare_fictional_scope_envelopes


def fixture():
    input_doc = {
        "review_at": "2026-10-16T12:00:00Z",
        "proposals": [{
            "asset": "sample.example.test",
            "capability": "inventory_read",
            "risk": 4,
            "valid_from": "2026-10-16T11:00:00Z",
            "valid_until": "2026-10-16T13:00:00Z",
        }],
    }
    p = subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
         "--synthetic-only", "--format", "json"],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        input=json.dumps(input_doc).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=12, check=False,
    )
    assert p.returncode == 2, p.stderr
    return json.loads(p.stdout)


def encode_pair(a, b):
    return json.dumps({"before": a, "after": b}, ensure_ascii=True).encode()


class FictionalPairResilience1495(unittest.TestCase):
    def assert_hold_without_scope(self, output):
        self.assertEqual(output.status, "HOLD")
        self.assertEqual(output.compared, 0)
        self.assertEqual(output.changes, 0)
        self.assertNotIn("sample.example.test", output.html)
        self.assertNotIn("<table", output.html)
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIn(flag + "=false", output.html)
            self.assertIs(getattr(output, flag), False)

    def test_valid_pair_does_no_disk_dns_net_sqlite_or_process(self):
        source = fixture()
        raw = encode_pair(source, source)
        with patch.object(builtins, "open", side_effect=AssertionError("file")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("db")), \
             patch.object(subprocess, "run", side_effect=AssertionError("process")):
            result = compare_fictional_scope_envelopes(raw)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.changes, 0)
        self.assertIs(result.authorized, False)

    def test_bad_pair_does_no_disk_dns_net_sqlite_or_process(self):
        with patch.object(builtins, "open", side_effect=AssertionError("file")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("db")), \
             patch.object(subprocess, "run", side_effect=AssertionError("process")):
            result = compare_fictional_scope_envelopes(b'{"before": "live.example.com"}')
        self.assert_hold_without_scope(result)

    def test_type_confusion_outer_shape_is_atomic_hold(self):
        src = fixture()
        for b in (None, True, False, 0, 1, "", "{}", [], [src]):
            with self.subTest(typ=type(b)):
                output = compare_fictional_scope_envelopes(encode_pair(src, b))
                self.assert_hold_without_scope(output)

    def test_type_confusion_inner_field_is_atomic_hold(self):
        src = fixture()
        for bad in (True, False, 1, 0, 2.5, None, "1", [], {}):
            with self.subTest(typ=type(bad), repr=str(bad)[:30]):
                corrupt = dict(src, reviewed=bad)
                self.assert_hold_without_scope(
                    compare_fictional_scope_envelopes(encode_pair(src, corrupt))
                )

    def test_all_four_fake_authority_claims_are_denied(self):
        src = fixture()
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            with self.subTest(key=key):
                corrupt = dict(src)
                corrupt[key] = True
                self.assert_hold_without_scope(
                    compare_fictional_scope_envelopes(encode_pair(src, corrupt))
                )

    def test_malformed_nonfinite_json_values_are_rejected(self):
        raw = encode_pair(fixture(), fixture())
        for marker in (b"NaN", b"Infinity", b"-Infinity"):
            # Inject a JSON non-finite number in otherwise valid structure.
            prefix = b'{"before":'
            forged = prefix + marker + b',"after":' + json.dumps(fixture()).encode() + b"}"
            self.assert_hold_without_scope(compare_fictional_scope_envelopes(forged))
        self.assertEqual(compare_fictional_scope_envelopes(raw).status, "REVIEW_ONLY")

    def test_unicode_bidi_and_control_payloads_quarantined(self):
        original = fixture()
        for marker in ("\x00", "\x1b", "\r", "\u202e", "\u2066", "\ud800"):
            with self.subTest(marker=repr(marker)):
                corrupt = dict(original, notice=original["notice"] + marker)
                self.assert_hold_without_scope(
                    compare_fictional_scope_envelopes(encode_pair(original, corrupt))
                )

    def test_160_deterministic_mutations_have_no_authorization_path(self):
        original = fixture()
        for index in range(160):
            change = dict(original)
            # Mix forged customer domains, appended statements and dates
            # without ever addressing a live network target.
            if index % 4 == 0:
                change["notice"] = original["notice"] + "\nAPPROVED-" + str(index)
            elif index % 4 == 1:
                change["notice"] = original["notice"].replace(
                    "sample.example.test", "sample.customer.com"
                )
            elif index % 4 == 2:
                change["notice"] = original["notice"].replace(
                    "2026-10-16T13:00:00Z", "2027-10-16T13:00:00Z"
                )
            else:
                change["notice"] = original["notice"].replace(
                    "Risk escalation: independent step-up",
                    "No review required"
                )
            self.assert_hold_without_scope(
                compare_fictional_scope_envelopes(encode_pair(original, change))
            )

    def test_pair_with_different_valid_synthetic_dates_is_not_revocation(self):
        a = fixture()
        b = dict(a)
        b["notice"] = a["notice"].replace(
            "2026-10-16T12:00:00Z", "2026-10-16T12:30:00Z"
        )
        output = compare_fictional_scope_envelopes(encode_pair(a, b))
        self.assertEqual(output.status, "REVIEW_ONLY")
        self.assertEqual(output.changes, 0)
        self.assertIn("NOT new grants, deletions, consent, or a real revocation event", output.html)

    def test_repeated_decoding_is_stable_for_same_bytes(self):
        doc = fixture()
        data = encode_pair(doc, doc)
        first = compare_fictional_scope_envelopes(data)
        second = compare_fictional_scope_envelopes(data)
        self.assertEqual(first, second)
        self.assertEqual(first.compared, 2)
        self.assertEqual(first.changes, 0)

    def test_max_bytes_rejects_one_extra_with_no_data_echo(self):
        original = fixture()
        raw = encode_pair(original, original)
        result = compare_fictional_scope_envelopes(raw + b" " * 131073)
        self.assert_hold_without_scope(result)

    def test_permutation_of_field_order_does_not_change_report(self):
        original = fixture()
        reversed_fields = dict(reversed(list(original.items())))
        p = compare_fictional_scope_envelopes(encode_pair(original, original))
        q = compare_fictional_scope_envelopes(encode_pair(reversed_fields, original))
        self.assertEqual(p, q)


if __name__ == "__main__":
    unittest.main()
