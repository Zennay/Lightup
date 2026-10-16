"""Strict offline CLI behavioral and adversarial regressions for #1493."""
import copy
import itertools
import json
import os
import random
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cross_grant_lineage_cli_1493 import (
    MAX_INPUT_BYTES, SCHEMA, evaluate_bytes,
)


def valid_record(asset="app.example.test", grant="G-1"):
    return {
        "legacy": {
            "owner": "reviewer@example.test", "reference": "SYNTH-REF-1",
            "valid_from": "2020-01-01T11:00:00Z",
            "valid_until": "2020-01-01T13:00:00Z",
        },
        "durable": {
            "grant_id": grant, "client_id": "CLIENT-1", "engagement_id": "ENG-1",
            "approved_by": "reviewer@example.test", "reference": "SYNTH-REF-1",
            "scope": {
                "assets": [asset], "max_risk": "STANDARD",
                "allowed_capabilities": ["web-baseline"], "excluded_assets": [],
            },
            "valid_from": "2020-01-01T10:00:00Z",
            "valid_until": "2020-01-01T14:00:00Z",
            "recurring_retest_allowed": False,
        },
        "asset": asset, "capability_id": "web-baseline",
        "client_id": "CLIENT-1", "engagement_id": "ENG-1",
        "requested_risk": "LOW_IMPACT",
    }


def valid_document():
    return {
        "schema": SCHEMA,
        "evaluated_at": "2020-01-01T12:00:00Z",
        "candidates": [valid_record()],
    }


def encoded(document):
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


class FictionalCliTests(unittest.TestCase):
    def check(self, change=None):
        document = valid_document()
        if change:
            change(document)
        return evaluate_bytes(encoded(document))

    def assert_invalid(self, change):
        result, code = self.check(change)
        self.assertEqual(code, 3)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "INVALID_INPUT")
        self.assertEqual(result["reviewed"], 0)
        self.assertEqual((
            result["authorized"], result["consent_verified"],
            result["dispatch_allowed"], result["release_allowed"]),
            (False, False, False, False))

    def test_fictional_coherent_preview_never_succeeds_as_permission(self):
        result, code = self.check()
        self.assertEqual(code, 2)
        self.assertEqual((result["status"], result["reason"], result["reviewed"]),
                         ("REVIEW_ONLY", "UNTRUSTED_COHERENCE", 1))
        self.assertEqual((
            result["authorized"], result["consent_verified"],
            result["dispatch_allowed"], result["release_allowed"]),
            (False, False, False, False))

    def test_notional_valid_two_distinct_grants_review_only(self):
        def two(d):
            d["candidates"].append(valid_record("other.example.test", "G-2"))
        result, code = self.check(two)
        self.assertEqual((result["status"], result["reviewed"], code),
                         ("REVIEW_ONLY", 2, 2))

    def test_fictional_mismatched_reference_atomic_hold_not_parse_error(self):
        def mismatch(d):
            d["candidates"][0]["legacy"]["reference"] = "SYNTH-OTHER"
        r, code = self.check(mismatch)
        self.assertEqual((r["status"], r["reason"], r["reviewed"], code),
                         ("HOLD", "COHERENCE_DENIED", 0, 2))

    def test_atomic_duplicate_record_hold(self):
        def dup(d):
            d["candidates"].append(copy.deepcopy(d["candidates"][0]))
        r, code = self.check(dup)
        self.assertEqual((r["status"], r["reviewed"], code), ("HOLD", 0, 2))

    def test_atomic_mixed_tenant_hold(self):
        def mixed(d):
            item = valid_record("other.example.test", "G-2")
            item["client_id"] = "CLIENT-2"
            item["durable"]["client_id"] = "CLIENT-2"
            d["candidates"].append(item)
        r, code = self.check(mixed)
        self.assertEqual((r["status"], r["reviewed"], code), ("HOLD", 0, 2))

    def test_atomic_conflicting_durable_grant_snapshots_hold(self):
        def conflict(d):
            d["candidates"].append(valid_record("other.example.test", "G-1"))
        r, code = self.check(conflict)
        self.assertEqual((r["status"], r["reviewed"], code), ("HOLD", 0, 2))

    def test_distinct_grants_same_asset_capability_are_coherence_hold(self):
        def collide(d):
            d["candidates"].append(valid_record("app.example.test", "G-2"))
        result, code = self.check(collide)
        self.assertEqual((result["status"], result["reason"], result["reviewed"], code),
                         ("HOLD", "COHERENCE_DENIED", 0, 2))
        for key in ("authorized", "consent_verified",
                    "dispatch_allowed", "release_allowed"):
            self.assertIs(result[key], False)

    def test_distinct_grants_same_asset_different_capability_stay_review_only(self):
        def noncollision(d):
            other = valid_record("app.example.test", "G-2")
            other["capability_id"] = "tls-baseline"
            other["durable"]["scope"]["allowed_capabilities"] = ["tls-baseline"]
            d["candidates"].append(other)
        result, code = self.check(noncollision)
        self.assertEqual((result["status"], result["reviewed"], code),
                         ("REVIEW_ONLY", 2, 2))

    def test_distinct_grants_same_capability_different_assets_stay_review_only(self):
        def noncollision(d):
            d["candidates"].append(valid_record("other.example.test", "G-2"))
        result, code = self.check(noncollision)
        self.assertEqual((result["status"], result["reviewed"], code),
                         ("REVIEW_ONLY", 2, 2))

    def test_max_size_distinct_grant_replay_is_atomic_hold(self):
        def inflated(d):
            d["candidates"] = [
                valid_record("app.example.test", f"G-{i}") for i in range(32)]
        result, code = self.check(inflated)
        self.assertEqual((result["status"], result["reviewed"], code), ("HOLD", 0, 2))
        self.assertFalse(result["release_allowed"])

    def test_cli_ambiguous_provenance_denied_under_all_input_orders(self):
        source = valid_document()
        claims = (
            valid_record("app.example.test", "G-1"),
            valid_record("app.example.test", "G-2"),
            valid_record("other.example.test", "G-3"),
        )
        outputs = set()
        for ordered in itertools.permutations(claims):
            source["candidates"] = list(ordered)
            r, code = evaluate_bytes(encoded(source))
            outputs.add((r["status"], r["reason"], r["reviewed"], code))
            self.assertFalse(r["authorized"])
            self.assertFalse(r["dispatch_allowed"])
        self.assertEqual(outputs, {("HOLD", "COHERENCE_DENIED", 0, 2)})

    def test_cli_disjoint_provenance_remains_review_only_in_any_order(self):
        source = valid_document()
        claims = (
            valid_record("app.example.test", "G-1"),
            valid_record("other.example.test", "G-2"),
            valid_record("third.example.test", "G-3"),
        )
        outputs = set()
        for ordered in itertools.permutations(claims):
            source["candidates"] = list(ordered)
            r, code = evaluate_bytes(encoded(source))
            outputs.add((r["status"], r["reason"], r["reviewed"], code))
            self.assertFalse(r["release_allowed"])
        self.assertEqual(outputs, {("REVIEW_ONLY", "UNTRUSTED_COHERENCE", 3, 2)})

    def test_same_grant_id_identical_two_asset_legacy_stays_review_only(self):
        def coherent(document):
            first = document["candidates"][0]
            first["durable"]["scope"]["assets"] = [
                "app.example.test", "other.example.test"]
            first["durable"]["scope"]["allowed_capabilities"] = [
                "web-baseline", "tls-baseline"]
            second = copy.deepcopy(first)
            second["asset"] = "other.example.test"
            second["capability_id"] = "tls-baseline"
            document["candidates"].append(second)
        r, code = self.check(coherent)
        self.assertEqual((r["status"], r["reviewed"], code),
                         ("REVIEW_ONLY", 2, 2))
        self.assertFalse(r["authorized"])
        self.assertFalse(r["release_allowed"])

    def test_same_grant_id_changed_legacy_window_is_atomic_hold(self):
        def rebinding(document):
            first = document["candidates"][0]
            first["durable"]["scope"]["assets"] = [
                "app.example.test", "other.example.test"]
            first["durable"]["scope"]["allowed_capabilities"] = [
                "web-baseline", "tls-baseline"]
            second = copy.deepcopy(first)
            second["asset"] = "other.example.test"
            second["capability_id"] = "tls-baseline"
            second["legacy"]["valid_from"] = "2020-01-01T11:01:00Z"
            document["candidates"].append(second)
        r, code = self.check(rebinding)
        self.assertEqual((r["status"], r["reason"], r["reviewed"], code),
                         ("HOLD", "COHERENCE_DENIED", 0, 2))
        self.assertFalse(r["authorized"])
        self.assertFalse(r["dispatch_allowed"])

    def test_privacy_receipt_does_not_echo_identity(self):
        r, _ = self.check()
        printed = json.dumps(r)
        for forbidden in ("example.test", "G-1", "SYNTH-REF-1", "CLIENT-1", "ENG-1", "web-baseline"):
            self.assertNotIn(forbidden, printed)

    def test_idempotent_input_bytes_and_deterministic_output(self):
        data = encoded(valid_document())
        preserved = data[:]
        self.assertEqual(evaluate_bytes(data), evaluate_bytes(data))
        self.assertEqual(data, preserved)

    def test_missing_input(self):
        self.assertEqual(evaluate_bytes(b"")[1], 3)

    def test_null_input(self):
        self.assertEqual(evaluate_bytes(b"null")[1], 3)

    def test_nonbytes_input(self):
        self.assertEqual(evaluate_bytes("oops")[1], 3)

    def test_oversized_input_predecode(self):
        self.assertEqual(evaluate_bytes(b" " * (MAX_INPUT_BYTES + 1))[1], 3)

    def test_exact_limit_inert_filler_still_denied_safely(self):
        self.assertEqual(evaluate_bytes(b" " * MAX_INPUT_BYTES)[1], 3)

    def test_invalid_utf8(self):
        self.assertEqual(evaluate_bytes(b"\xff\xfe")[1], 3)

    def test_utf8_bom_rejected(self):
        self.assertEqual(evaluate_bytes(b"\xef\xbb\xbf" + encoded(valid_document()))[1], 3)

    def test_duplicate_root_key(self):
        data = encoded(valid_document())
        self.assertEqual(evaluate_bytes(data[:-1] + b',"schema":"FICTIONAL-CROSS-GRANT-V1"}')[1], 3)

    def test_duplicate_nested_grant_key(self):
        data = encoded(valid_document())
        data = data.replace(b'"grant_id":"G-1"', b'"grant_id":"G-1","grant_id":"G-2"')
        self.assertEqual(evaluate_bytes(data)[1], 3)

    def test_nan_rejected(self):
        self.assertEqual(evaluate_bytes(encoded(valid_document())[:-1] + b',"extra":NaN}')[1], 3)

    def test_float_rejected(self):
        self.assertEqual(evaluate_bytes(encoded(valid_document())[:-1] + b',"extra":1.0}')[1], 3)

    def test_number_rejected(self):
        self.assertEqual(evaluate_bytes(encoded(valid_document())[:-1] + b',"extra":1}')[1], 3)

    def test_trailing_extra_document_rejected(self):
        self.assertEqual(evaluate_bytes(encoded(valid_document()) + b"{}")[1], 3)

    def test_unknown_schema(self):
        self.assert_invalid(lambda d: d.update(schema="FICTIONAL-GRANT-V2"))

    def test_missing_schema(self):
        self.assert_invalid(lambda d: d.pop("schema"))

    def test_extra_root_field(self):
        self.assert_invalid(lambda d: d.update(authorized=True))

    def test_extra_candidate_authority_marker(self):
        self.assert_invalid(lambda d: d["candidates"][0].update(consent_verified=True))

    def test_extra_durable_marker(self):
        self.assert_invalid(lambda d: d["candidates"][0]["durable"].update(signature="forged"))

    def test_empty_batch(self):
        self.assert_invalid(lambda d: d.update(candidates=[]))

    def test_oversized_batch(self):
        def over(d):
            d["candidates"] = [valid_record(grant=f"G-{i}") for i in range(33)]
        self.assert_invalid(over)

    def test_boolean_string_marker(self):
        self.assert_invalid(lambda d: d["candidates"][0]["durable"].update(recurring_retest_allowed="false"))

    def test_unrecognized_risk_name(self):
        self.assert_invalid(lambda d: d["candidates"][0].update(requested_risk="ADMIN"))

    def test_integer_risk_rejected(self):
        self.assert_invalid(lambda d: d["candidates"][0].update(requested_risk=2))

    def test_naive_timestamp_rejected(self):
        self.assert_invalid(lambda d: d.update(evaluated_at="2020-01-01T12:00:00"))

    def test_offset_timestamp_rejected(self):
        self.assert_invalid(lambda d: d.update(evaluated_at="2020-01-01T12:00:00+00:00"))

    def test_invalid_timestamp_date_rejected(self):
        self.assert_invalid(lambda d: d.update(evaluated_at="2020-02-30T12:00:00Z"))

    def test_nonfictional_target_denied(self):
        self.assert_invalid(lambda d: d["candidates"][0].update(asset="some-company.com"))

    def test_nonfictional_scope_asset_denied(self):
        self.assert_invalid(lambda d: d["candidates"][0]["durable"]["scope"].update(assets=["some-company.com"]))

    def test_nonfictional_excluded_scope_asset_denied(self):
        self.assert_invalid(lambda d: d["candidates"][0]["durable"]["scope"].update(excluded_assets=["real.example.com"]))

    def test_nonfictional_approver_denied(self):
        self.assert_invalid(lambda d: d["candidates"][0]["durable"].update(approved_by="real-operator@company.com"))

    def test_nonfictional_reference_denied(self):
        self.assert_invalid(lambda d: d["candidates"][0]["legacy"].update(reference="LIVE-AUTH"))

    def test_duplicate_scope_asset_is_coherence_hold_not_error(self):
        def dup(d):
            d["candidates"][0]["durable"]["scope"]["assets"].append("app.example.test")
        r, code = self.check(dup)
        self.assertEqual((r["status"], r["reason"], code), ("HOLD", "COHERENCE_DENIED", 2))

    def test_ascii_control_in_client_identity_rejected_at_json_admission(self):
        self.assert_invalid(lambda d: d["candidates"][0].update(client_id="CLIENT-1\\nGO"))

    def test_unicode_escaped_tab_in_operator_rejected_at_admission(self):
        self.assert_invalid(
            lambda d: d["candidates"][0]["legacy"].update(
                owner="reviewer\\t@example.test"))

    def test_fictional_host_rejects_double_dot_alias_at_admission(self):
        self.assert_invalid(
            lambda d: d["candidates"][0].update(asset="x..example.test"))

    def test_fictional_host_rejects_label_leading_hyphen_at_admission(self):
        self.assert_invalid(
            lambda d: d["candidates"][0].update(asset="x.-y.example.test"))

    def test_fictional_host_rejects_label_trailing_hyphen_at_admission(self):
        self.assert_invalid(
            lambda d: d["candidates"][0].update(asset="x-.example.test"))

    def test_fictional_host_rejects_uppercase_case_alias_at_admission(self):
        self.assert_invalid(
            lambda d: d["candidates"][0].update(asset="App.example.test"))

    def test_fictional_host_rejects_overlong_label_at_admission(self):
        self.assert_invalid(
            lambda d: d["candidates"][0].update(asset=("a" * 64) + ".example.test"))

    def test_fictional_reference_never_accepts_newline_escape(self):
        self.assert_invalid(
            lambda d: d["candidates"][0]["legacy"].update(reference="SYNTH-REF\\nGO"))

    def test_overly_long_text_denied(self):
        self.assert_invalid(lambda d: d["candidates"][0].update(client_id="A" * 129))

    def test_deterministic_1024_byte_mutants_never_grant_authority(self):
        baseline = encoded(valid_document())
        rng = random.Random(1493)
        mutation_values = (0, 9, 10, 13, 34, 39, 44, 58, 91, 93, 123, 125, 127, 128, 255)
        for index in range(1024):
            position = rng.randrange(len(baseline) + 1)
            byte = rng.choice(mutation_values)
            if index % 3 == 0:
                mutant = baseline[:position] + bytes((byte,)) + baseline[position:]
            elif index % 3 == 1:
                mutant = baseline[:position] + bytes((byte,)) + baseline[position + 1:]
            else:
                mutant = baseline[:position] + baseline[position + 1:]
            receipt, exit_code = evaluate_bytes(mutant)
            self.assertIn(exit_code, (2, 3))
            self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
            self.assertEqual(receipt["reviewed"], 0 if receipt["status"] == "HOLD" else 1)
            for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
                self.assertIs(receipt[field], False)

    def test_deeply_nested_json_stays_denied_and_sanitized(self):
        payload = b"[" * 900 + b"0" + b"]" * 900
        receipt, exit_code = evaluate_bytes(payload)
        self.assertEqual(exit_code, 3)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "INVALID_INPUT")
        self.assertFalse(receipt["release_allowed"])

    def test_excessive_stdin_subprocess_returns_no_authority_and_exit_3(self):
        process = subprocess.run(
            [sys.executable, "-B", "-m", "lightup.cross_grant_lineage_cli_1493",
             "--synthetic-only"],
            input=(b" " * (MAX_INPUT_BYTES + 1)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False,
        )
        self.assertEqual(process.returncode, 3)
        self.assertEqual(process.stderr, b"")
        receipt = json.loads(process.stdout)
        self.assertEqual((receipt["status"], receipt["reviewed"]), ("HOLD", 0))
        self.assertEqual((receipt["authorized"], receipt["consent_verified"],
                          receipt["dispatch_allowed"], receipt["release_allowed"]),
                         (False, False, False, False))

    def test_cli_requires_explicit_synthetic_only_flag(self):
        process = subprocess.run(
            [sys.executable, "-m", "lightup.cross_grant_lineage_cli_1493"],
            input=encoded(valid_document()), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False,
        )
        r = json.loads(process.stdout)
        self.assertEqual((process.returncode, r["status"], r["reviewed"]), (3, "HOLD", 0))
        self.assertEqual(process.stderr, b"")

    def test_cli_subprocess_fictional_holds_nonzero_and_no_identity_echo(self):
        process = subprocess.run(
            [sys.executable, "-m", "lightup.cross_grant_lineage_cli_1493", "--synthetic-only"],
            input=encoded(valid_document()), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False,
        )
        r = json.loads(process.stdout)
        self.assertEqual((process.returncode, r["status"], r["reviewed"]), (2, "REVIEW_ONLY", 1))
        self.assertFalse(r["authorized"])
        self.assertNotIn(b"example.test", process.stdout)
        self.assertNotIn(b"SYNTH-REF-1", process.stdout)
        self.assertEqual(process.stderr, b"")

    def test_cold_process_utc_parser_does_not_import_strptime_or_locale(self):
        # Fresh interpreter, guard import AFTER loading only this local module.
        # No bytecode writes; all assertions remain fake data and no authority.
        snippet = """
import builtins, json, sys
from lightup.cross_grant_lineage_cli_1493 import evaluate_bytes
original_import = builtins.__import__
def deny_lazy_parser(name, *args, **kwargs):
    if name in ('_strptime', 'locale'):
        raise AssertionError('unexpected late calendar import')
    return original_import(name, *args, **kwargs)
builtins.__import__ = deny_lazy_parser
receipt, code = evaluate_bytes(sys.stdin.buffer.read())
assert code == 2, (receipt, code)
assert receipt['status'] == 'REVIEW_ONLY' and receipt['authorized'] is False
"""
        process = subprocess.run(
            [sys.executable, "-B", "-c", snippet],
            input=encoded(valid_document()), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
        self.assertEqual(process.stdout, b"")

    def test_offline_evaluator_no_socket_db_file_or_process(self):
        # Prime standard-library fixed-time parsing before enforcing I/O spies.
        self.check()
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file")):
            r, code = self.check()
            self.assertEqual((r["status"], code), ("REVIEW_ONLY", 2))


if __name__ == "__main__":
    unittest.main()
