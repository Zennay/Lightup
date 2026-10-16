"""Hermetic tests for the independent non-authorizing #299 diagnostic.

Only subprocesses running local synthetic input; no imported app, target or socket.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "scope_299_legacy_provenance_review.py"
_FALSE_FLAGS = (
    "can_authorize",
    "can_dispatch",
    "can_deploy",
    "can_merge",
    "can_release",
    "can_scan",
)


def _run_packet(packet: bytes, *args: str) -> tuple[int, dict[str, object], str]:
    result = subprocess.run(
        [sys.executable, "-B", str(_SCRIPT), *args],
        input=packet,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
        cwd=_ROOT,
    )
    output = result.stdout.decode("utf-8")
    if len(output.splitlines()) != 1:
        raise AssertionError("diagnostic must emit exactly one JSON line")
    parsed = json.loads(output)
    if type(parsed) is not dict:
        raise AssertionError("diagnostic must emit one JSON object")
    return result.returncode, parsed, result.stderr.decode("utf-8")


class Scope299OfflineReviewerTests(unittest.TestCase):
    def assert_hold(self, result: tuple[int, dict[str, object], str], *, code: int, reason: str):
        actual_code, receipt, stderr = result
        self.assertEqual(actual_code, code)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt.get("status"), "HOLD")
        self.assertEqual(receipt.get("reason"), reason)
        self.assertEqual(set(receipt), {"status", "reason", *_FALSE_FLAGS})
        for field in _FALSE_FLAGS:
            self.assertIs(receipt[field], False)
        self.assertLess(len(json.dumps(receipt)), 220)

    def test_canonical_synthetic_shape_still_returns_hold_exit_two(self):
        packet = b'{"owner":"fictional","reference":"NOT-CUSTOMER-CONSENT"}'
        self.assert_hold(
            _run_packet(packet, "--offline-synthetic-only"),
            code=2,
            reason="canonical_shape_only",
        )

    def test_missing_or_blank_provenance_never_promotes_authority(self):
        packets = (
            b'{"owner":"","reference":"synthetic"}',
            b'{"owner":"fictional","reference":""}',
            b'{"owner":" \t ","reference":"synthetic"}',
            b'{"owner":"fictional","reference":"\n"}',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(
                    _run_packet(packet, "--offline-synthetic-only"),
                    code=2,
                    reason="noncanonical_shape",
                )

    def test_padded_and_embedded_control_text_is_rejected(self):
        packets = (
            b'{"owner":" fictional","reference":"synthetic"}',
            b'{"owner":"fictional","reference":"synthetic "}',
            b'{"owner":"fictional\\nname","reference":"synthetic"}',
            b'{"owner":"fictional","reference":"synthetic\\u0000control"}',
            b'{"owner":"fictional","reference":"synthetic\\u200binvisible"}',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(
                    _run_packet(packet, "--offline-synthetic-only"),
                    code=2,
                    reason="noncanonical_shape",
                )

    def test_polymorphic_types_never_become_strings(self):
        values = (None, True, False, 0, -1, 1.2, [], ["fictional"], {}, {"value": "fictional"})
        for value in values:
            for field in ("owner", "reference"):
                with self.subTest(value=repr(value), field=field):
                    sample = {"owner": "fictional", "reference": "NOT-CONSENT"}
                    sample[field] = value
                    packet = json.dumps(sample).encode("utf-8")
                    self.assert_hold(
                        _run_packet(packet, "--offline-synthetic-only"),
                        code=2,
                        reason="noncanonical_shape",
                    )

    def test_duplicate_key_packets_fail_entire_packet(self):
        packets = (
            b'{"owner":"fictional","owner":"attacker","reference":"synthetic"}',
            b'{"owner":"fictional","reference":"synthetic","reference":""}',
            b'{"owner":"fictional","reference":"synthetic","extra":{"x":1,"x":2}}',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(
                    _run_packet(packet, "--offline-synthetic-only"),
                    code=3,
                    reason="invalid_packet",
                )

    def test_missing_extra_nested_or_wrong_case_keys_fail(self):
        packets = (
            b'{}',
            b'{"owner":"fictional"}',
            b'{"Owner":"fictional","reference":"synthetic"}',
            b'{"owner":"fictional","reference":"synthetic","can_authorize":true}',
            b'{"owner":"fictional","reference":"synthetic","scope":["public"]}',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(
                    _run_packet(packet, "--offline-synthetic-only"),
                    code=3,
                    reason="invalid_packet",
                )

    def test_non_object_and_trailing_json_fail(self):
        packets = (b"[]", b"null", b"true", b'""', b"42", b'{}{}', b"")
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(
                    _run_packet(packet, "--offline-synthetic-only"),
                    code=3,
                    reason="invalid_packet",
                )

    def test_non_json_constants_and_invalid_encodings_fail(self):
        packets = (
            b'{"owner":NaN,"reference":"synthetic"}',
            b'{"owner":Infinity,"reference":"synthetic"}',
            b'{"owner":-Infinity,"reference":"synthetic"}',
            b"\xff\xfe",
            b'\xef\xbb\xbf{"owner":"fictional","reference":"synthetic"}',
            b'{"owner":"fictional","reference":"synthetic"',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(
                    _run_packet(packet, "--offline-synthetic-only"),
                    code=3,
                    reason="invalid_packet",
                )

    def test_oversized_packet_does_not_echo_or_parse(self):
        packet = (b"A" * 5000) + b"SECRET-NEVER-ECHO-XYZ"
        result = _run_packet(packet, "--offline-synthetic-only")
        self.assert_hold(result, code=3, reason="invalid_packet")
        self.assertNotIn("SECRET-NEVER-ECHO-XYZ", json.dumps(result[1]))

    def test_absent_or_invalid_optin_arguments_always_hold(self):
        packet = b'{"owner":"fictional","reference":"synthetic"}'
        for flags in ((), ("--unknown",), ("--offline-synthetic-only", "--extra")):
            with self.subTest(args=flags):
                self.assert_hold(_run_packet(packet, *flags), code=3, reason="invalid_packet")

    def test_sensitive_synthetic_provenance_never_reaches_stdout(self):
        secret = "FICTIONAL-SECRET-NEVER-ECHO-XYZ"
        packet = json.dumps({"owner": secret, "reference": secret}).encode("utf-8")
        code, receipt, stderr = _run_packet(packet, "--offline-synthetic-only")
        self.assertEqual(code, 2)
        self.assertEqual(stderr, "")
        self.assertNotIn(secret, json.dumps(receipt))
        self.assertEqual(receipt["reason"], "canonical_shape_only")

    def test_no_recursion_crash_or_real_payload_echo(self):
        packet = (b'{"owner":' + b"[" * 1500 + b"0" + b"]" * 1500 +
                  b',"reference":"synthetic"}')
        self.assert_hold(
            _run_packet(packet, "--offline-synthetic-only"),
            code=3,
            reason="invalid_packet",
        )

    def test_text_subclass_with_hostile_methods_is_not_canonical(self):
        sys.path.insert(0, str(_ROOT))
        try:
            from scripts.scope_299_legacy_provenance_review import canonical_text

            class HostileString(str):
                def strip(self):
                    raise AssertionError("must not call subclass code")

                def isprintable(self):
                    raise AssertionError("must not call subclass code")

            self.assertFalse(canonical_text(HostileString("fictional")))
            self.assertTrue(canonical_text("fictional"))
            self.assertFalse(canonical_text(" fictional"))
            self.assertFalse(canonical_text("fictional\u200b"))
            self.assertFalse(canonical_text(1))
        finally:
            sys.path.remove(str(_ROOT))

    def test_import_boundary_excludes_network_subprocess_and_application(self):
        tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
        imported = set()
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                imported.update(name.name.split(".")[0] for name in item.names)
            elif isinstance(item, ast.ImportFrom):
                imported.add((item.module or "").split(".")[0])
        self.assertEqual(imported, {"__future__", "json", "sys"})

    def test_entrypoint_does_not_accept_target_or_path_options(self):
        sample = b'{"owner":"fictional","reference":"synthetic"}'
        for flag in ("--target", "--input-file", "--authorize", "--scan", "--permit"):
            with self.subTest(flag=flag):
                self.assert_hold(
                    _run_packet(sample, "--offline-synthetic-only", flag, "anything"),
                    code=3,
                    reason="invalid_packet",
                )


if __name__ == "__main__":
    unittest.main()
