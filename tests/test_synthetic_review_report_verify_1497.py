"""Strict import tests for OWN inert V1 fictional scope-review JSON (#1497).

Actual invocation and data are entirely fictional; no production policy or
target/handler/permit is invoked. The importer checks *shape* not provenance.
"""
from __future__ import annotations

from dataclasses import asdict
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

from lightup.synthetic_review_disclosure_1497 import review_fictional_handoff_notes, _hold
from lightup.synthetic_review_report_verify_1497 import review_fictional_report_bytes as verify

VALID = "Asset alpha.example.test; capability header_read; proposed risk 2."
VALID2 = "Asset beta.example.test; capability tls_review; proposed risk 4."


def canonical(verdict) -> bytes:
    return json.dumps(
        asdict(verdict), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


class FictionalReviewImportTests(unittest.TestCase):
    def test_exact_one_note_canonical_wire_review_only(self):
        result = review_fictional_handoff_notes((VALID,))
        imported = verify(canonical(result))
        self.assertEqual(imported, result)
        self.assertEqual(imported.reviewed_notes, 1)

    def test_canonical_two_note_wire_roundtrip_and_count(self):
        result = review_fictional_handoff_notes((VALID, VALID2))
        imported = verify(canonical(result))
        self.assertEqual(imported, result)
        self.assertEqual(imported.reviewed_notes, 2)

    def test_all_valid_exact_counts_up_to_16(self):
        for count in range(1, 17):
            notes = tuple(
                f"Asset fixture{i}.example.test; capability header_read; proposed risk 1."
                for i in range(count)
            )
            with self.subTest(count=count):
                verdict = review_fictional_handoff_notes(notes)
                self.assertEqual(verify(canonical(verdict)), verdict)

    def test_exact_canonical_hold_wire_remains_hold(self):
        result = verify(canonical(_hold()))
        self.assertEqual(result, _hold())
        self.assertEqual(result.reviewed_notes, 0)

    def test_one_cli_trailing_newline_accepted(self):
        original = canonical(review_fictional_handoff_notes((VALID,)))
        self.assertEqual(verify(original + b"\n").status, "REVIEW_ONLY")
        self.assertEqual(verify(canonical(_hold()) + b"\n").status, "HOLD")

    def test_more_than_one_newline_denied(self):
        self.assertEqual(verify(canonical(review_fictional_handoff_notes((VALID,))) + b"\n\n").status, "HOLD")

    def test_input_is_never_mutated_or_echoed(self):
        payload = canonical(review_fictional_handoff_notes((VALID,)))
        before = payload[:]
        result = verify(payload)
        self.assertEqual(payload, before)
        self.assertNotIn("alpha.example.test", repr(result))
        self.assertFalse(result.dispatch_allowed)
        self.assertFalse(result.release_allowed)

    def test_nonbytes_and_subclass_rejected_without_coercion(self):
        class Spoof(bytes):
            def __bytes__(self):
                raise AssertionError("do not coerce")
        valid = canonical(review_fictional_handoff_notes((VALID,)))
        for value in (None, 5, False, "str", Spoof(valid), memoryview(valid), bytearray(valid)):
            with self.subTest(t=type(value)):
                self.assertEqual(verify(value).status, "HOLD")

    def test_length_bound_before_json(self):
        for value in (b"", b" " * 4097, b"x" * 4_000_000, b"\xff" * 8_000):
            with self.subTest(length=len(value)):
                self.assertEqual(verify(value).status, "HOLD")

    def test_non_ascii_raw_bytes_denied(self):
        for raw in (b"\xef\xbb\xbf", b'\x00{}', b'\xff{}', b'\xc2\xa0{}'):
            with self.subTest(raw=raw[:4]):
                self.assertEqual(verify(raw).status, "HOLD")

    def test_json_duplicate_keys_rejected_before_reconstruction(self):
        x = canonical(review_fictional_handoff_notes((VALID,)))
        dup = x.replace(b'"authorized":false', b'"authorized":false,"authorized":false')
        self.assertEqual(verify(dup).status, "HOLD")
        dup = x.replace(b'"status":"REVIEW_ONLY"', b'"status":"REVIEW_ONLY","status":"REVIEW_ONLY"')
        self.assertEqual(verify(dup).status, "HOLD")

    def test_all_authority_fields_exact_false_or_hold(self):
        sample = json.loads(canonical(review_fictional_handoff_notes((VALID,))))
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            for bad in (True, 0, 1, "false", "True", None, {}, []):
                with self.subTest(field=key, type=type(bad).__name__):
                    forged = {**sample, key: bad}
                    raw = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
                    self.assertEqual(verify(raw).status, "HOLD")

    def test_rejects_extra_and_missing_fields(self):
        sample = json.loads(canonical(review_fictional_handoff_notes((VALID,))))
        for key in tuple(sample):
            modified = dict(sample)
            del modified[key]
            with self.subTest(missing=key):
                self.assertEqual(verify(json.dumps(modified, sort_keys=True, separators=(",", ":")).encode()).status, "HOLD")
        modified = {**sample, "grant_id": "fake-example"}
        self.assertEqual(verify(json.dumps(modified, sort_keys=True, separators=(",", ":")).encode()).status, "HOLD")

    def test_rejects_contract_version_or_provenance_spoof(self):
        sample = json.loads(canonical(review_fictional_handoff_notes((VALID,))))
        for contract in ("FICTIONAL-SCOPE-HANDOFF-1497-V2", "LIVE-GRANT",
                         "FICTIONAL-SCOPE-HANDOFF-1497-V1 ", "", None):
            with self.subTest(contract=contract):
                modified = {**sample, "contract": contract}
                self.assertEqual(verify(json.dumps(modified, sort_keys=True, separators=(",", ":")).encode()).status, "HOLD")

    def test_rejects_forged_status_notice_or_count(self):
        sample = json.loads(canonical(review_fictional_handoff_notes((VALID,))))
        for overrides in (
            {"status": "APPROVED"}, {"status": "AUTHORIZED"}, {"status": "HOLD"},
            {"notice": "APPROVED — grant permit"}, {"notice": sample["notice"] + " extra"},
            {"reviewed_notes": 0}, {"reviewed_notes": 17},
            {"reviewed_notes": False}, {"reviewed_notes": "1"},
            {"reviewed_notes": 1.0}, {"reviewed_notes": -1},
        ):
            with self.subTest(keys=list(overrides)):
                changed = {**sample, **overrides}
                self.assertEqual(verify(json.dumps(changed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).status, "HOLD")

    def test_noncanonical_whitespace_and_field_order_denied(self):
        x = canonical(review_fictional_handoff_notes((VALID,)))
        self.assertEqual(verify(b" " + x).status, "HOLD")
        self.assertEqual(verify(x + b" ").status, "HOLD")
        self.assertEqual(verify(x.replace(b":", b": ", 1)).status, "HOLD")
        self.assertEqual(verify(x.replace(b",", b", ", 1)).status, "HOLD")
        sample = json.loads(x)
        reversed_order = json.dumps(dict(reversed(list(sample.items()))), separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(verify(reversed_order).status, "HOLD")

    def test_unicode_escaping_is_canonical_only(self):
        sample = asdict(review_fictional_handoff_notes((VALID,)))
        raw_utf8 = json.dumps(sample, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(verify(raw_utf8).status, "HOLD")
        self.assertEqual(verify(canonical(review_fictional_handoff_notes((VALID,)))).status, "REVIEW_ONLY")

    def test_nonfinite_and_deep_json_denied(self):
        sample = canonical(review_fictional_handoff_notes((VALID,)))
        self.assertEqual(verify(sample.replace(b"false", b"NaN", 1)).status, "HOLD")
        self.assertEqual(verify(b"[" * 1300 + b"0" + b"]" * 1300).status, "HOLD")

    def test_deterministic_single_byte_mutation_fails_closed(self):
        raw = canonical(review_fictional_handoff_notes((VALID,)))
        count = 0
        for index in range(len(raw)):
            for replacement in (0, 10, 34, 35, 65, 127, 255):
                if raw[index] == replacement:
                    continue
                attack = raw[:index] + bytes((replacement,)) + raw[index + 1:]
                self.assertEqual(verify(attack).status, "HOLD", (index, replacement))
                count += 1
        self.assertGreater(count, 1000)

    def test_no_os_file_db_network_or_process_side_effects(self):
        x = canonical(review_fictional_handoff_notes((VALID,)))
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("os.open", side_effect=AssertionError("os")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("db")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assertEqual(verify(x).status, "REVIEW_ONLY")
            self.assertEqual(verify(b"not json").status, "HOLD")


class FictionalReviewImportCliTests(unittest.TestCase):
    def invoke(self, content: bytes, *args: str):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "lightup.synthetic_review_disclosure_cli_1497", *args],
            input=content, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=8, check=False,
        )

    def test_actual_two_process_roundtrip_never_exit_zero(self):
        payload = json.dumps([VALID, VALID2]).encode()
        first = self.invoke(payload, "--synthetic-only")
        self.assertEqual(first.returncode, 2, first.stderr)
        second = self.invoke(first.stdout, "--verify-report-only")
        self.assertEqual(second.returncode, 2, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        result = json.loads(second.stdout)
        self.assertEqual(result["reviewed_notes"], 2)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertIs(result["authorized"], False)

    def test_actual_hold_pipe_remains_generic_hold(self):
        first = self.invoke(json.dumps([VALID + " approved"]).encode(), "--synthetic-only")
        self.assertEqual(first.returncode, 3)
        second = self.invoke(first.stdout, "--verify-report-only")
        self.assertEqual(second.returncode, 3)
        self.assertEqual(first.stdout, second.stdout)
        self.assertNotIn(b"alpha.example.test", second.stdout)

    def test_actual_forged_authority_report_gets_hold(self):
        x = asdict(review_fictional_handoff_notes((VALID,)))
        x["authorized"] = True
        value = self.invoke(json.dumps(x).encode(), "--verify-report-only")
        self.assertEqual(value.returncode, 3)
        result = json.loads(value.stdout)
        self.assertEqual(result["status"], "HOLD")
        self.assertIs(result["authorized"], False)
        self.assertNotIn(b"alpha.example.test", value.stdout)

    def test_actual_unknown_flag_and_oversized_envelopes_hold(self):
        for raw in (b'{}', b'["hello"]', b"not json", b"\x00" * 20, b"X" * 4097):
            with self.subTest(raw=raw[:20]):
                p = self.invoke(raw, "--verify-report-only")
                self.assertEqual(p.returncode, 3)
                self.assertEqual(json.loads(p.stdout)["reviewed_notes"], 0)

    def test_actual_cli_invalid_switch_denied(self):
        data = canonical(review_fictional_handoff_notes((VALID,)))
        for args in ((), ("--verify-report-only", "--synthetic-only"), ("--verify-report-only", "now")):
            with self.subTest(args=args):
                p = self.invoke(data, *args)
                self.assertEqual(p.returncode, 3)
                self.assertEqual(json.loads(p.stdout)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
