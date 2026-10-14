"""Synthetic/offline contracts for non-authorizing grant amendment comparison."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_grant_amendment_20261014_offline.py"
spec = importlib.util.spec_from_file_location("grant_amendment_review", SCRIPT)
reviewer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(reviewer)


def fixture():
    grant = {
        "grant_id": "grant-demo-01",
        "client_id": "client-demo",
        "engagement_id": "eng-demo",
        "reference": "reference-demo",
        "assets": ["lab-a.example", "lab-b.example"],
        "excluded_assets": ["lab-b.example"],
        "capabilities": ["http_headers", "tls_baseline"],
        "max_risk": 3,
        "valid_from": "2026-10-14T00:00:00Z",
        "valid_until": "2026-10-15T00:00:00Z",
        "recurring_retest_allowed": False,
    }
    return {"schema": "lightup.grant-amendment-review.v1", "before": copy.deepcopy(grant), "after": copy.deepcopy(grant)}


def encode(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class GrantAmendmentOfflineTests(unittest.TestCase):
    def assert_denied_authority(self, receipt, code):
        self.assertIn(code, (2, 3))
        self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
        for flag in (
            "authorized", "permit_issued", "dispatch_enabled",
            "merge_approved", "deploy_approved", "release_approved",
        ):
            self.assertIs(receipt[flag], False)

    def test_unchanged_review_only_no_permission(self):
        out, code = reviewer.review(encode(fixture()))
        self.assertEqual((out["status"], code), ("REVIEW_ONLY", 3))
        self.assertEqual(out["widening_dimensions"], [])
        self.assert_denied_authority(out, code)

    def test_genuine_multidimensional_narrowing(self):
        value = fixture()
        value["after"].update({
            "assets": ["lab-a.example"],
            "excluded_assets": ["lab-b.example", "lab-c.example"],
            "capabilities": ["tls_baseline"],
            "max_risk": 1,
            "valid_from": "2026-10-14T06:00:00Z",
            "valid_until": "2026-10-14T09:00:00Z",
        })
        out, code = reviewer.review(encode(value))
        self.assertEqual((out["status"], code), ("REVIEW_ONLY", 3))
        self.assert_denied_authority(out, code)

    def test_each_widening_dimension_refused(self):
        changes = [
            ("grant_id", "grant-other", "identity"),
            ("client_id", "client-other", "identity"),
            ("engagement_id", "eng-other", "identity"),
            ("reference", "reference-other", "identity"),
            ("assets", ["lab-a.example", "lab-b.example", "lab-c.example"], "assets"),
            ("excluded_assets", [], "exclusions"),
            ("capabilities", ["http_headers", "tls_baseline", "new_tool"], "capabilities"),
            ("max_risk", 4, "risk"),
            ("valid_from", "2026-10-13T00:00:00Z", "window"),
            ("valid_until", "2026-10-16T00:00:00Z", "window"),
            ("recurring_retest_allowed", True, "recurring_retest"),
        ]
        for name, value, dimension in changes:
            with self.subTest(name=name):
                case = fixture()
                case["after"][name] = value
                out, code = reviewer.review(encode(case))
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assertIn(dimension, out["widening_dimensions"])
                self.assert_denied_authority(out, code)

    def test_atomic_multi_widening(self):
        value = fixture()
        value["after"]["max_risk"] = 4
        value["after"]["assets"].append("new.example")
        value["after"]["recurring_retest_allowed"] = True
        out, code = reviewer.review(encode(value))
        self.assertEqual(out["widening_dimensions"], ["assets", "recurring_retest", "risk"])
        self.assertEqual(code, 2)

    def test_malformed_primitive_type_and_shape_hold(self):
        bad_values = [
            (("after", "max_risk"), True),
            (("after", "max_risk"), 1.0),
            (("after", "max_risk"), -1),
            (("after", "max_risk"), 5),
            (("after", "recurring_retest_allowed"), 1),
            (("after", "assets"), "lab.example"),
            (("after", "capabilities"), []),
            (("after", "assets"), []),
            (("after", "assets"), ["lab-a.example", "lab-a.example"]),
            (("after", "assets"), ["UPPERCASE.example"]),
            (("after", "grant_id"), ""),
            (("after", "grant_id"), ["x"]),
            (("after", "valid_from"), "2026-10-14"),
            (("after", "valid_from"), "2026-10-14T00:00:00+00:00"),
            (("after", "valid_from"), "2026-02-30T00:00:00Z"),
            (("after", "valid_until"), "2026-10-14T00:00:00Z"),
        ]
        for path, replacement in bad_values:
            with self.subTest(path=path, value=replacement):
                case = fixture()
                case[path[0]][path[1]] = replacement
                out, code = reviewer.review(encode(case))
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assert_denied_authority(out, code)

    def test_extra_or_missing_fields_fail(self):
        cases = []
        x = fixture()
        x["after"]["authorized"] = True
        cases.append(x)
        y = fixture()
        del y["before"]["client_id"]
        cases.append(y)
        z = fixture()
        z["trusted"] = True
        cases.append(z)
        for case in cases:
            out, code = reviewer.review(encode(case))
            self.assertEqual((out["status"], code), ("HOLD", 2))

    def test_duplicate_json_keys_including_decoded_alias(self):
        for raw in (
            b'{"schema":"x","schema":"x","before":{},"after":{}}',
            b'{"schema":"lightup.grant-amendment-review.v1","before":{"assets":[],"\\u0061ssets":[]},"after":{}}',
        ):
            out, code = reviewer.review(raw)
            self.assertEqual((out["status"], code), ("HOLD", 2))

    def test_untrusted_bytes_never_raise_or_echo(self):
        inputs = [
            b"", b"\xff", b"\xef\xbb\xbf{}", b"null", b"{}{}",
            b"NaN", b"1e999", b"[]", b" " * (reviewer.MAX_INPUT + 1),
            b"{", b"\x00", b'{"secret":"do-not-print-this"}',
        ]
        for data in inputs:
            with self.subTest(data=data[:15]):
                out, code = reviewer.review(data)
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assertNotIn("do-not-print-this", json.dumps(out))
                self.assert_denied_authority(out, code)

    def test_wrong_input_python_types_fail_closed(self):
        for data in ("{}", bytearray(b"{}"), None, 5, True):
            out, code = reviewer.review(data)
            self.assertEqual((out["status"], code), ("HOLD", 2))

    def test_repeated_deterministic_and_caller_unchanged(self):
        value = fixture()
        original = copy.deepcopy(value)
        a = reviewer.review(encode(value))
        b = reviewer.review(encode(value))
        self.assertEqual(a, b)
        self.assertEqual(value, original)

    def test_script_has_no_runtime_authorization_import(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("from lightup", source)
        self.assertNotIn("import socket", source)
        self.assertNotIn("urllib.request", source)

    def test_real_subprocess_narrowing_is_nonzero_and_opaque(self):
        raw = encode(fixture())
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            input=raw, capture_output=True, check=False, timeout=8,
        )
        self.assertEqual(result.returncode, 3)
        receipt = json.loads(result.stdout)
        self.assert_denied_authority(receipt, result.returncode)
        self.assertNotIn(b"grant-demo-01", result.stdout)
        self.assertNotIn(b"client-demo", result.stdout)
        self.assertNotIn(b"lab-a.example", result.stdout)
        self.assertFalse(result.stderr)

    def test_real_subprocess_widening_is_nonzero_and_opaque(self):
        value = fixture()
        value["after"]["assets"] = ["lab-a.example", "new.example"]
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            input=encode(value), capture_output=True, check=False, timeout=8,
        )
        self.assertEqual(result.returncode, 2)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["widening_dimensions"], ["assets"])
        self.assert_denied_authority(receipt, result.returncode)

    def test_subprocess_complete_but_unclosed_fifo_fails_finitely(self):
        process = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            process.stdin.write(encode(fixture()))
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=7), 2)
            out = process.stdout.read()
            receipt = json.loads(out)
            self.assertEqual(receipt["status"], "HOLD")
            self.assert_denied_authority(receipt, process.returncode)
            self.assertNotIn(b"grant-demo", out)
            self.assertFalse(process.stderr.read())
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_subprocess_partial_unclosed_fifo_fails_finitely(self):
        process = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            process.stdin.write(b'{"schema":"do-not-echo')
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=7), 2)
            out = process.stdout.read()
            self.assertEqual(json.loads(out)["status"], "HOLD")
            self.assertNotIn(b"do-not-echo", out)
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_subprocess_redirected_bounded_regular_file_is_reviewable(self):
        with tempfile.TemporaryFile() as source:
            source.write(encode(fixture()))
            source.seek(0)
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                stdin=source, capture_output=True, check=False, timeout=8,
            )
        self.assertEqual(result.returncode, 3)
        self.assert_denied_authority(json.loads(result.stdout), result.returncode)

    @unittest.skipUnless(hasattr(socket, "socketpair") and os.name == "posix", "POSIX local socket")
    def test_subprocess_socket_stdin_refused_without_read(self):
        source, sink = socket.socketpair()
        try:
            with source, sink:
                result = subprocess.run(
                    [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                    stdin=sink, capture_output=True, check=False, timeout=8,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
        finally:
            source.close()
            sink.close()

    def test_cli_rejects_no_flag(self):
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT)],
            input=b"", capture_output=True, check=False, timeout=8,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
