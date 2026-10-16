"""Hermetic unit/subprocess tests for synthetic #920 review-only sidecar."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scope_920_offline_transport_guard import review_json, review_metadata, main

_SCRIPT = Path(__file__).with_name("scope_920_offline_transport_guard.py")
_SAMPLE = {"trusted_proxy_ip": "127.0.0.1", "public_origin": "https://lightup.example"}
_FLAGS = (
    "grants_authority", "permits_execution", "dispatch_allowed",
    "scans_allowed", "deploy_allowed", "release_allowed",
)


class _StrSubclass(str):
    def __eq__(self, _other: object) -> bool:
        return True


class _ClassSpoof:
    @property
    def __class__(self):
        return str


class TransportReviewTests(unittest.TestCase):
    def assertNoAuthority(self, receipt: dict[str, object]) -> None:
        self.assertIn(receipt["decision"], ("HOLD", "REVIEW_ONLY"))
        self.assertEqual(set(receipt), {"decision", *_FLAGS})
        for flag in _FLAGS:
            self.assertIs(receipt[flag], False)

    def test_only_fictional_exact_loopback_https_preview(self) -> None:
        for proxy in ("127.0.0.1", "::1"):
            with self.subTest(proxy=proxy):
                receipt = review_metadata({**_SAMPLE, "trusted_proxy_ip": proxy})
                self.assertEqual(receipt["decision"], "REVIEW_ONLY")
                self.assertNoAuthority(receipt)

    def test_caller_dictionary_is_not_modified(self) -> None:
        payload = _SAMPLE.copy()
        review_metadata(payload)
        self.assertEqual(payload, _SAMPLE)

    def test_rejects_polymorphic_outer_and_inner_inputs(self) -> None:
        cases = (
            _ClassSpoof(), [], None,
            {**_SAMPLE, "trusted_proxy_ip": _StrSubclass("127.0.0.1")},
            {**_SAMPLE, "public_origin": _StrSubclass("https://lightup.example")},
            {**_SAMPLE, "public_origin": _ClassSpoof()},
            {**_SAMPLE, "trusted_proxy_ip": 1},
            {**_SAMPLE, "trusted_proxy_ip": True},
        )
        for case in cases:
            with self.subTest(case=type(case).__name__):
                receipt = review_metadata(case)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_rejects_ambiguous_scope_and_origin_shapes(self) -> None:
        cases = (
            {**_SAMPLE, "trusted_proxy_ip": "203.0.113.5"},
            {**_SAMPLE, "trusted_proxy_ip": "127.1"},
            {**_SAMPLE, "trusted_proxy_ip": "::ffff:127.0.0.1"},
            {**_SAMPLE, "trusted_proxy_ip": "127.0.0.1%lo"},
            {**_SAMPLE, "public_origin": "http://lightup.example"},
            {**_SAMPLE, "public_origin": "https://lightup.example:443"},
            {**_SAMPLE, "public_origin": "https://user@lightup.example"},
            {**_SAMPLE, "public_origin": "https://lightup.example/path"},
            {**_SAMPLE, "public_origin": "https://lightup.example?x=y"},
            {**_SAMPLE, "public_origin": "https://lightup.example#part"},
            {**_SAMPLE, "public_origin": "https://lightup.example."},
            {**_SAMPLE, "public_origin": "HTTPS://lightup.example"},
            {**_SAMPLE, "public_origin": "https://lightup.ｅxample"},
            {**_SAMPLE, "public_origin": "https://lightup.example\x00"},
            {**_SAMPLE, "public_origin": "https://lightup.example\n"},
            {**_SAMPLE, "public_origin": "https://evil.example@lightup.example"},
            {**_SAMPLE, "public_origin": "https://lightup.example.evil.test"},
            {**_SAMPLE, "unexpected_key": "token"},
            {"trusted_proxy_ip": "127.0.0.1"},
        )
        for case in cases:
            with self.subTest(case=case):
                receipt = review_metadata(case)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_rejects_ambiguous_json_input(self) -> None:
        inputs = (
            b'{"trusted_proxy_ip":"127.0.0.1","trusted_proxy_ip":"::1","public_origin":"https://lightup.example"}',
            b'{"trusted_proxy_ip":"127.0.0.1","public_origin":"https://lightup.example","extra":1}',
            b'NaN', b'[]', b'null', b'{', b'\xff', b' ' * 4097,
            b'{"trusted_proxy_ip":true,"public_origin":"https://lightup.example"}',
        )
        for raw in inputs:
            with self.subTest(raw=raw[:50]):
                result = review_json(raw)
                self.assertEqual(result["decision"], "HOLD")
                self.assertNoAuthority(result)

    def test_exact_json_round_trip_review_only_is_non_authorizing(self) -> None:
        receipt = review_json(json.dumps(_SAMPLE).encode())
        self.assertEqual(receipt["decision"], "REVIEW_ONLY")
        self.assertNoAuthority(receipt)

    def test_cli_requires_explicit_offline_opt_in(self) -> None:
        proc = subprocess.run([sys.executable, str(_SCRIPT)], input=json.dumps(_SAMPLE).encode(), capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["decision"], "HOLD")
        self.assertFalse(proc.stderr)

    def test_cli_returns_nonzero_and_six_false_flags_for_valid_synthetic_only(self) -> None:
        proc = subprocess.run([sys.executable, str(_SCRIPT), "--offline-synthetic-only"], input=json.dumps(_SAMPLE).encode(), capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 3)
        self.assertFalse(proc.stderr)
        self.assertNoAuthority(json.loads(proc.stdout))
        self.assertEqual(json.loads(proc.stdout)["decision"], "REVIEW_ONLY")

    def test_cli_fails_closed_without_echoing_sensitive_input(self) -> None:
        secret = "PRIVATE-DATA-NOT-FOR-OUTPUT"
        payload = json.dumps({**_SAMPLE, "extra": secret}).encode()
        proc = subprocess.run([sys.executable, str(_SCRIPT), "--offline-synthetic-only"], input=payload, capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertNoAuthority(json.loads(proc.stdout))
        self.assertNotIn(secret.encode(), proc.stdout + proc.stderr)
        self.assertNotIn(b"lightup.example", proc.stdout + proc.stderr)
        self.assertFalse(proc.stderr)


    def test_exact_byte_boundary_never_widens_authority(self) -> None:
        canonical = json.dumps(_SAMPLE).encode()
        padded = canonical + b" " * (4096 - len(canonical))
        self.assertEqual(len(padded), 4096)
        self.assertEqual(review_json(padded)["decision"], "REVIEW_ONLY")
        receipt = review_json(padded + b" ")
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_escaped_unicode_controls_and_duplicate_nested_keys_hold(self) -> None:
        payloads = (
            b'{"trusted_proxy_ip":"127.0.0.1","public_origin":"https://lightup.\\u0065xample"}',
            b'{"trusted_proxy_ip":"127.0.0.1","public_origin":"https://lightup.example\\u202e"}',
            b'{"trusted_proxy_ip":"127.0.0.1","public_origin":"https://lightup.example","nested":{"x":1,"x":2}}',
        )
        for raw in payloads:
            with self.subTest(raw=raw[:60]):
                receipt = review_json(raw)
                self.assertNoAuthority(receipt)
                if b"nested" in raw or b"202e" in raw:
                    self.assertEqual(receipt["decision"], "HOLD")

    def test_mapping_subclass_and_nested_spoofers_cannot_gain_authority(self) -> None:
        class UntrustedMapping(dict):
            def __eq__(self, other):
                return True
        for obj in (UntrustedMapping(_SAMPLE), {**_SAMPLE, "trusted_proxy_ip": _ClassSpoof()}):
            receipt = review_metadata(obj)
            self.assertEqual(receipt["decision"], "HOLD")
            self.assertNoAuthority(receipt)

    def test_cli_rejects_unknown_arguments_without_reading_grant_like_data(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--offline-synthetic-only", "--grant"],
            input=json.dumps(_SAMPLE).encode(), capture_output=True, timeout=5,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(proc.stderr)
        receipt = json.loads(proc.stdout)
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)



    def test_polymorphic_dictionary_keys_are_rejected_before_caller_methods(self) -> None:
        class _TrackedKey(str):
            def __new__(cls, value):
                obj = str.__new__(cls, value)
                obj.calls = 0
                return obj

            def __hash__(self):
                self.calls += 1
                return str.__hash__(self)

            def __eq__(self, other):
                self.calls += 1
                return str.__eq__(self, other)

        trap = _TrackedKey("public_origin")
        payload = dict(_SAMPLE)
        original_value = payload.pop("public_origin")
        payload[trap] = original_value
        trap.calls = 0
        receipt = review_metadata(payload)
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertEqual(trap.calls, 0, "untrusted key methods must not run")
        self.assertNoAuthority(receipt)
        self.assertEqual(len(payload), len(_SAMPLE))

    def test_nonstring_dictionary_keys_fail_before_equality_or_hashing(self) -> None:
        class _SpoofKey:
            def __init__(self):
                self.calls = 0

            def __hash__(self):
                self.calls += 1
                return hash("public_origin")

            def __eq__(self, other):
                self.calls += 1
                return other == "public_origin"

        trap = _SpoofKey()
        payload = dict(_SAMPLE)
        value = payload.pop("public_origin")
        payload[trap] = value
        trap.calls = 0
        receipt = review_metadata(payload)
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertEqual(trap.calls, 0, "untrusted key methods must not run")
        self.assertNoAuthority(receipt)


    def test_programmatic_cli_rejects_equality_spoofed_argv_without_stdin_read(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        class _NoStdin:
            @property
            def buffer(self):
                raise AssertionError("untrusted argv must never trigger a stdin read")

        class _ForgedArgs:
            def __init__(self):
                self.calls = 0

            def __eq__(self, other):
                self.calls += 1
                return True

            @property
            def __class__(self):
                return list

        forged = _ForgedArgs()
        output = io.StringIO()
        with patch.object(sys, "stdin", _NoStdin()), redirect_stdout(output):
            rc = main(forged)  # type: ignore[arg-type]
        self.assertEqual(rc, 2)
        self.assertEqual(forged.calls, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_programmatic_cli_rejects_str_subclass_optin_without_comparison(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        class _NoStdin:
            @property
            def buffer(self):
                raise AssertionError("subclass argv must never trigger stdin")

        class _SpoofArg(str):
            def __new__(cls, value):
                obj = str.__new__(cls, value)
                obj.calls = 0
                return obj

            def __eq__(self, other):
                self.calls += 1
                return True

        forged = _SpoofArg("--offline-synthetic-only")
        output = io.StringIO()
        with patch.object(sys, "stdin", _NoStdin()), redirect_stdout(output):
            rc = main([forged])
        self.assertEqual(rc, 2)
        self.assertEqual(forged.calls, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_host_parser_fail_closed_on_invalid_brackets_and_canonical_form(self) -> None:
        # The reviewer never resolves a hostname and never accepts raw URL
        # syntax that urlsplit might normalize into a different identity.
        bad_origins = (
            "https://[not-an-ip].example",
            "https://broken-.example",
            "https://-broken.example",
            "https://LIGHTUP.example",
            "https://lightup..example",
            "https://lightup.example:bad",
        )
        for origin in bad_origins:
            with self.subTest(origin=origin):
                receipt = review_metadata({**_SAMPLE, "public_origin": origin})
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)


if __name__ == "__main__":
    unittest.main()
