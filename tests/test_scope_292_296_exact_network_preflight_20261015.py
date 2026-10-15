"""Pure offline and actual local-CLI acceptance for #292/#296 config preflight.

Not a grant source, permission evaluator, or target scanner.
"""
from __future__ import annotations

from ipaddress import IPv4Interface, IPv6Interface, ip_network
import json
from io import BytesIO, StringIO
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scope_292_296_exact_network_preflight as guard


class _TrickStr(str):
    def __str__(self):
        return "8.8.8.0/24"


class OfflineExactNetworks292296(unittest.TestCase):
    def _payload(self, networks):
        return json.dumps({"explicit_networks": networks}).encode("utf-8")

    def _cli(self, raw: bytes):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "scope_292_296_exact_network_preflight.py")],
            input=raw,
            capture_output=True,
            timeout=8,
            check=False,
        )

    def test_empty_collection_review_only_but_never_permits(self):
        self.assertEqual(guard.review(self._payload([])), "REVIEW_ONLY")
        response = json.loads(guard.receipt("REVIEW_ONLY"))
        self.assertEqual(response["disposition"], "REVIEW_ONLY")
        for key in ("is_grant", "authorizes_scan", "authorizes_target_io", "authorizes_execution", "authorizes_release"):
            self.assertIs(response[key], False)

    def test_canonical_v4_v6_and_syntactic_zero_prefix_review_only(self):
        self.assertEqual(
            guard.review(self._payload([
                "8.8.8.0/24", "8.8.8.8/32",
                "2001:4860:4860::/64", "2001:4860:4860::8888/128",
                "0.0.0.0/0", "::/0",
            ])),
            "REVIEW_ONLY",
        )
        self.assertNotEqual(guard.receipt("REVIEW_ONLY").find('"is_grant":false'), -1)

    def test_noncanonical_host_bits_fail_closed_ipv4_ipv6(self):
        for text in (
            "8.8.8.8/24", "8.8.8.8/0",
            "2001:4860:4860::8888/64", "2001:4860:4860::8888/0",
        ):
            with self.subTest(text=text):
                self.assertEqual(guard.review(self._payload([text])), "HOLD")

    def test_aliases_and_missing_prefix_fail_closed(self):
        for value in (
            "8.8.8.8", "2001:4860:4860::8888",
            "8.8.8.0/255.255.255.0",
            "2001:4860:4860:0000::/64",
            "8.8.8.0/24 ", " 8.8.8.0/24",
            "8.8.8.0/33", "8.8.8.0//24",
        ):
            with self.subTest(value=value):
                self.assertEqual(guard.review(self._payload([value])), "HOLD")

    def test_public_interface_objects_and_hostbits_are_never_policy_syntax(self):
        # ip_network(obj, strict=False) normalizes these, but the standalone
        # review must reject the Python object type before parsing.
        samples = (
            IPv4Interface("8.8.8.8/24"),
            IPv4Interface("8.8.8.8/0"),
            IPv6Interface("2001:4860:4860::8888/64"),
            IPv6Interface("2001:4860:4860::8888/0"),
        )
        for obj in samples:
            with self.subTest(kind=type(obj).__name__, value=str(obj)):
                self.assertIs(guard._canonical(obj), False)
                self.assertNotEqual(str(ip_network(obj, strict=False)), str(obj))

    def test_nonstring_coercions_fail_closed(self):
        for value in (134744072, True, False, None, 8.8, {}, ["8.8.8.0/24"]):
            with self.subTest(value=value):
                self.assertEqual(guard.review(self._payload([value])), "HOLD")

    def test_direct_review_rejects_string_subclasses(self):
        self.assertIs(guard._canonical(_TrickStr("not-cidr")), False)

    def test_cardinality_128_accepted_129_hold(self):
        networks = [f"198.51.100.{i}/32" for i in range(128)]
        self.assertEqual(guard.review(self._payload(networks)), "REVIEW_ONLY")
        networks.append("198.51.100.128/32")
        self.assertEqual(guard.review(self._payload(networks)), "HOLD")

    def test_oversized_utf8_payload_rejected_at_boundary(self):
        self.assertEqual(guard.review(b" " * (guard.MAX_JSON_BYTES + 1)), "HOLD")
        raw = self._payload(["8.8.8.0/24"])
        self.assertEqual(guard.review(raw), "REVIEW_ONLY")

    def test_overlong_single_network_rejected(self):
        self.assertEqual(guard.review(self._payload(["8.8.8.0/" + "1" * 260])), "HOLD")

    def test_malformed_utf8_and_json_are_hold(self):
        for raw in (b"\xff", b"{", b"", b"null", b"[]", b'"text"', b"\xef\xbb\xbf{}"):
            with self.subTest(raw=repr(raw)):
                self.assertEqual(guard.review(raw), "HOLD")

    def test_duplicate_object_keys_fail_closed(self):
        raw = b'{"explicit_networks":["8.8.8.0/24"],"explicit_networks":[]}'
        self.assertEqual(guard.review(raw), "HOLD")

    def test_unknown_or_missing_envelope_fields_fail_closed(self):
        for raw in (
            b'{}',
            b'{"explicit_networks":[],"grant":true}',
            b'{"explicit_networks":"8.8.8.0/24"}',
            b'{"explicit_networks":null}',
        ):
            self.assertEqual(guard.review(raw), "HOLD")

    def test_nonfinite_json_constants_rejected(self):
        for text in ('NaN', 'Infinity', '-Infinity'):
            raw = ('{"explicit_networks":[' + text + ']}').encode()
            self.assertEqual(guard.review(raw), "HOLD")

    def test_output_receipt_is_privacy_constant_and_false_authority(self):
        self.assertEqual(guard.receipt("SECRET.example.net"), guard.receipt("HOLD"))
        self.assertNotIn("SECRET", guard.receipt("SECRET.example.net"))
        for disposition in ("HOLD", "REVIEW_ONLY"):
            value = json.loads(guard.receipt(disposition))
            self.assertEqual(set(value), {
                "disposition", "is_grant", "authorizes_scan",
                "authorizes_target_io", "authorizes_execution", "authorizes_release",
            })
            self.assertFalse(any(x for k, x in value.items() if k != "disposition"))

    def test_pure_review_makes_no_dns_socket_or_process_calls(self):
        with (
            patch("socket.socket", side_effect=AssertionError("socket forbidden")),
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")),
            patch("subprocess.Popen", side_effect=AssertionError("process forbidden")),
            patch("os.system", side_effect=AssertionError("shell forbidden")),
        ):
            self.test_canonical_v4_v6_and_syntactic_zero_prefix_review_only()
            self.test_noncanonical_host_bits_fail_closed_ipv4_ipv6()

    def test_deeply_nested_json_is_generic_hold_not_traceback(self):
        # Trigger parser recursion before envelope checking, within byte limit.
        nested = b"[" * 1100 + b"0" + b"]" * 1100
        self.assertLess(len(nested), guard.MAX_JSON_BYTES)
        self.assertEqual(guard.review(nested), "HOLD")
        done = self._cli(nested)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stderr, b"")
        self.assertEqual(json.loads(done.stdout)["disposition"], "HOLD")

    def test_mixed_valid_invalid_networks_fail_whole_snapshot(self):
        good = "8.8.8.0/24"
        bad = "8.8.8.8/0"
        for values in ([good, bad], [bad, good], [good, None]):
            with self.subTest(values=repr(values)):
                self.assertEqual(guard.review(self._payload(values)), "HOLD")

    def test_review_output_cannot_expose_sensitive_input(self):
        marker = "SYNTHETIC-SECRET-NETWORK-INPUT"
        malicious = self._payload([marker, "8.8.8.0/24"])
        result = guard.receipt(guard.review(malicious))
        self.assertNotIn(marker, result)
        self.assertNotIn("8.8.8.0", result)
        self.assertEqual(json.loads(result)["is_grant"], False)

    def test_max_exact_bytes_does_not_bypass_parser_rejection(self):
        raw = b" " * guard.MAX_JSON_BYTES
        self.assertEqual(guard.review(raw), "HOLD")

    def test_receipt_subclass_identity_spoofing_always_hold(self):
        # Caller-originated subclass is never a trusted REVIEW_ONLY disposition.
        self.assertEqual(guard.receipt(_TrickStr("REVIEW_ONLY")), guard.receipt("HOLD"))
        self.assertEqual(guard.receipt(None), guard.receipt("HOLD"))
        self.assertEqual(guard.receipt(["REVIEW_ONLY"]), guard.receipt("HOLD"))

    def test_receipt_is_constant_across_distinct_network_inputs(self):
        examples = (
            ["198.51.100.0/24"],
            ["203.0.113.0/24"],
            ["2001:db8::/64"],
            ["::/0"],
            [],
        )
        receipts = {
            guard.receipt(guard.review(self._payload(sample))) for sample in examples
        }
        self.assertEqual(receipts, {guard.receipt("REVIEW_ONLY")})
        self.assertFalse(json.loads(next(iter(receipts)))["authorizes_target_io"])

    def test_exhaustive_documentation_range_host_bit_widening_is_hold(self):
        # 4 x 127 deterministic, synthetic host-bit samples, no network I/O.
        for offset in range(1, 128):
            for text in (
                f"198.51.100.{offset}/24",
                f"198.51.100.{offset}/0",
                f"2001:db8::{offset:x}/64",
                f"2001:db8::{offset:x}/0",
            ):
                with self.subTest(text=text):
                    widened = ip_network(text, strict=False)
                    self.assertNotEqual(text, str(widened))
                    self.assertEqual(guard.review(self._payload([text])), "HOLD")

    def test_all_canonical_ipv4_ipv6_prefix_lengths_remain_review_only(self):
        for prefix in range(33):
            canonical = str(ip_network(f"198.51.100.42/{prefix}", strict=False))
            with self.subTest(family=4, prefix=prefix):
                self.assertEqual(guard.review(self._payload([canonical])), "REVIEW_ONLY")
        for prefix in range(129):
            canonical = str(ip_network(f"2001:db8::1234/{prefix}", strict=False))
            with self.subTest(family=6, prefix=prefix):
                self.assertEqual(guard.review(self._payload([canonical])), "REVIEW_ONLY")

    def test_cli_never_conveys_grant_or_target_io_for_valid_and_invalid(self):
        for networks, expected_status in (
            (["198.51.100.0/24"], 3),
            (["2001:db8::/64"], 3),
            (["198.51.100.42/24"], 2),
            ([134744072], 2),
        ):
            with self.subTest(networks=networks):
                done = self._cli(self._payload(networks))
                self.assertEqual(done.returncode, expected_status)
                self.assertEqual(done.stderr, b"")
                packet = json.loads(done.stdout)
                self.assertEqual(set(packet), {
                    "disposition", "is_grant", "authorizes_scan",
                    "authorizes_target_io", "authorizes_execution",
                    "authorizes_release",
                })
                self.assertFalse(any(v for k, v in packet.items() if k != "disposition"))

    def test_exact_byte_boundary_complete_json_and_plus_one_fail_closed(self):
        base = self._payload(["198.51.100.0/24"])
        exact = b" " * (guard.MAX_JSON_BYTES - len(base)) + base
        self.assertEqual(len(exact), guard.MAX_JSON_BYTES)
        self.assertEqual(guard.review(exact), "REVIEW_ONLY")
        self.assertEqual(guard.review(exact + b" "), "HOLD")
        for raw, status, disposition in (
            (exact, 3, "REVIEW_ONLY"),
            (exact + b" ", 2, "HOLD"),
        ):
            done = self._cli(raw)
            self.assertEqual(done.returncode, status)
            self.assertEqual(done.stderr, b"")
            self.assertEqual(json.loads(done.stdout)["disposition"], disposition)
            self.assertFalse(json.loads(done.stdout)["authorizes_target_io"])

    def test_main_stdin_io_error_produces_only_private_hold_receipt(self):
        class BrokenReader:
            def read(self, _):
                raise OSError("private synthetic input failure")

        output = StringIO()
        with (
            patch.object(guard.sys, "stdin", SimpleNamespace(buffer=BrokenReader())),
            patch.object(guard.sys, "stdout", output),
        ):
            status = guard.main()
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), guard.receipt("HOLD") + "\n")
        self.assertNotIn("private", output.getvalue())

    def test_main_broken_pipe_never_exits_review_only(self):
        class BrokenOutput:
            def write(self, _):
                raise BrokenPipeError("private synthetic broken pipe")
            def flush(self):
                raise AssertionError("flush should not run after broken write")

        reader = SimpleNamespace(buffer=BytesIO(self._payload(["198.51.100.0/24"])))
        with (
            patch.object(guard.sys, "stdin", reader),
            patch.object(guard.sys, "stdout", BrokenOutput()),
        ):
            self.assertEqual(guard.main(), 2)

    def test_main_short_output_write_returns_fail_closed(self):
        class ShortOutput:
            def write(self, text):
                return len(text) - 1
            def flush(self):
                raise AssertionError("incomplete receipt must not be flushed")

        reader = SimpleNamespace(buffer=BytesIO(self._payload(["198.51.100.0/24"])))
        with (
            patch.object(guard.sys, "stdin", reader),
            patch.object(guard.sys, "stdout", ShortOutput()),
        ):
            self.assertEqual(guard.main(), 2)

    def test_main_stdout_flush_error_never_exits_review_only(self):
        class FailingFlush:
            def write(self, text):
                return len(text)
            def flush(self):
                raise OSError("synthetic output unavailable")

        reader = SimpleNamespace(buffer=BytesIO(self._payload(["198.51.100.0/24"])))
        with (
            patch.object(guard.sys, "stdin", reader),
            patch.object(guard.sys, "stdout", FailingFlush()),
        ):
            self.assertEqual(guard.main(), 2)

    def test_fragmented_valid_stream_requires_eof_then_review_only(self):
        class Fragmented:
            def __init__(self, data):
                self.parts = [data[:4], data[4:17], data[17:], b""]
            def read(self, size):
                value = self.parts.pop(0)
                self_limit = len(value) <= size
                if not self_limit:
                    raise AssertionError("unbounded read request")
                return value

        raw = self._payload(["198.51.100.0/24"])
        reader = Fragmented(raw)
        self.assertEqual(guard._read_bounded_stream(reader), raw)
        self.assertEqual(reader.parts, [])
        stdout = StringIO()
        with (
            patch.object(guard.sys, "stdin", SimpleNamespace(buffer=Fragmented(raw))),
            patch.object(guard.sys, "stdout", stdout),
        ):
            self.assertEqual(guard.main(), 3)
        self.assertEqual(stdout.getvalue(), guard.receipt("REVIEW_ONLY") + "\n")

    def test_fragmented_valid_prefix_followed_by_untrusted_suffix_is_hold(self):
        valid = self._payload(["198.51.100.0/24"])
        marker = b'{"authorizes_scan":true,"secret":"SYNTHETIC-PRIVATE"}'

        class Fragmented:
            def __init__(self):
                self.parts = [valid, marker, b""]
            def read(self, size):
                value = self.parts.pop(0)
                self_size = len(value) <= size
                if not self_size:
                    raise AssertionError("stream requested too few bytes")
                return value

        stdout = StringIO()
        with (
            patch.object(guard.sys, "stdin", SimpleNamespace(buffer=Fragmented())),
            patch.object(guard.sys, "stdout", stdout),
        ):
            self.assertEqual(guard.main(), 2)
        self.assertEqual(stdout.getvalue(), guard.receipt("HOLD") + "\n")
        self.assertNotIn("SYNTHETIC-PRIVATE", stdout.getvalue())

    def test_fragmented_16384_plus_one_byte_is_hold(self):
        valid = self._payload(["198.51.100.0/24"])
        exact = b" " * (guard.MAX_JSON_BYTES - len(valid)) + valid

        class Fragmented:
            def __init__(self):
                self.parts = [exact[:8000], exact[8000:], b"x"]
                self.calls = 0
            def read(self, size):
                self.calls += 1
                self.assert_size = size
                return self.parts.pop(0)

        reader = Fragmented()
        with self.assertRaises(ValueError):
            guard._read_bounded_stream(reader)
        self.assertEqual(reader.calls, 3)

    def test_stream_wrong_type_or_none_is_hold_not_eof(self):
        for wrong in (None, "text", bytearray(b"x"), True):
            class Malformed:
                def read(self, _size):
                    return wrong

            stdout = StringIO()
            with (
                patch.object(guard.sys, "stdin", SimpleNamespace(buffer=Malformed())),
                patch.object(guard.sys, "stdout", stdout),
            ):
                self.assertEqual(guard.main(), 2)
            self.assertEqual(stdout.getvalue(), guard.receipt("HOLD") + "\n")

    def test_stream_overreturning_size_is_hold(self):
        class Overreturn:
            def read(self, size):
                return b"x" * (size + 1)

        stdout = StringIO()
        with (
            patch.object(guard.sys, "stdin", SimpleNamespace(buffer=Overreturn())),
            patch.object(guard.sys, "stdout", stdout),
        ):
            self.assertEqual(guard.main(), 2)
        self.assertEqual(stdout.getvalue(), guard.receipt("HOLD") + "\n")

    def test_fragmentation_invariance_over_bounded_input_matrix(self):
        # Short reads must never change disposition or create grant authority.
        valid = self._payload(["198.51.100.0/24", "2001:db8::/64"])
        cases = (
            valid,
            self._payload([]),
            self._payload(["198.51.100.42/24"]),
            valid + b'{"forged_grant":true}',
            b'{"explicit_networks":["198.51.100.0/24"],"explicit_networks":[]}',
            b'{"explicit_networks":[true]}',
            b'not-json',
            b' ' * (guard.MAX_JSON_BYTES - len(valid)) + valid,
            b' ' * (guard.MAX_JSON_BYTES - len(valid)) + valid + b'X',
        )

        class SmallChunks:
            def __init__(self, payload, chunk_size):
                self.payload = payload
                self.pos = 0
                self.chunk_size = chunk_size
            def read(self, limit):
                requested = min(limit, self.chunk_size)
                chunk = self.payload[self.pos:self.pos + requested]
                self.pos += len(chunk)
                return chunk

        for index, raw in enumerate(cases):
            expected = guard.review(raw)
            for chunk_size in (1, 2, 3, 7, 17, 64, 257, 2048):
                with self.subTest(case=index, chunk_size=chunk_size):
                    stdout = StringIO()
                    reader = SmallChunks(raw, chunk_size)
                    with (
                        patch.object(guard.sys, "stdin", SimpleNamespace(buffer=reader)),
                        patch.object(guard.sys, "stdout", stdout),
                    ):
                        status = guard.main()
                    self.assertEqual(reader.pos, len(raw))
                    self.assertEqual(status, 3 if expected == "REVIEW_ONLY" else 2)
                    self.assertEqual(stdout.getvalue(), guard.receipt(expected) + "\n")
                    packet = json.loads(stdout.getvalue())
                    self.assertFalse(packet["authorizes_target_io"])
                    self.assertFalse(packet["is_grant"])

    def test_partial_valid_stream_then_io_failure_remains_private_hold(self):
        prefix = self._payload(["198.51.100.0/24"])

        class FailingAfterPrefix:
            def __init__(self):
                self.calls = 0
            def read(self, _size):
                self.calls += 1
                if self.calls == 1:
                    return prefix
                raise OSError("private synthetic stream corruption")

        stdout = StringIO()
        with (
            patch.object(guard.sys, "stdin", SimpleNamespace(buffer=FailingAfterPrefix())),
            patch.object(guard.sys, "stdout", stdout),
        ):
            self.assertEqual(guard.main(), 2)
        self.assertEqual(stdout.getvalue(), guard.receipt("HOLD") + "\n")
        self.assertNotIn("private", stdout.getvalue())

    def test_json_escape_aliases_cannot_mint_canonical_network_review(self):
        # JSON decoding normalizes these strings to a canonical CIDR.
        # Literal network declarations are required, even for syntax review.
        aliases = (
            b'{"explicit_networks":["\u0038.8.8.0/24"]}',
            b'{"explicit_networks":["8.8.8.0\/24"]}',
            b'{"explicit_networks":["2001:db8::\u002f64"]}',
            b'{"explicit_networks":["\u0032\u0030\u0030\u0031:db8::/64"]}',
            b'{"explicit_net\u0077orks":["198.51.100.0/24"]}',
            b'{"\u0065xplicit_networks":["198.51.100.0/24"]}',
        )
        for raw in aliases:
            with self.subTest(raw=repr(raw)):
                decoded = json.loads(raw)
                self.assertEqual(set(decoded), {"explicit_networks"})
                self.assertTrue(all(guard._canonical(x) for x in decoded["explicit_networks"]))
                self.assertEqual(guard.review(raw), "HOLD")
                self.assertFalse(json.loads(guard.receipt(guard.review(raw)))["is_grant"])

    def test_structural_json_whitespace_remains_reviewable(self):
        examples = (
            b'{"explicit_networks":["198.51.100.0/24"]}',
            b' \t\r\n {  "explicit_networks" : [ "198.51.100.0/24" ] } \r\n',
            b'{\n"explicit_networks":\t[ "198.51.100.0/24", "2001:db8::/64" ]\n}\t',
            b'\n {"explicit_networks": []} \r',
        )
        for raw in examples:
            with self.subTest(raw=repr(raw)):
                self.assertEqual(guard.review(raw), "REVIEW_ONLY")

    def test_real_cli_rejects_escaped_scope_with_private_nonzero_hold(self):
        marker = "NEVER-PRINT-PRIVATE-SYNTHETIC"
        raw = (
            b'{"explicit_networks":["198.51.100.0\/24"],'
            b'"untrusted":"NEVER-PRINT-PRIVATE-SYNTHETIC"}'
        )
        # Raw malformed envelopes and escaped CIDR aliases both deny.
        for example in (
            raw,
            b'{"explicit_networks":["198.51.100.0\/24"]}',
            b'{"explicit_net\u0077orks":["198.51.100.0/24"]}',
        ):
            with self.subTest(raw=repr(example)):
                done = self._cli(example)
                self.assertEqual(done.returncode, 2)
                self.assertEqual(done.stderr, b"")
                self.assertEqual(json.loads(done.stdout)["disposition"], "HOLD")
                self.assertNotIn(marker.encode(), done.stdout)

    def test_minifier_retains_whitespace_inside_json_string(self):
        raw = b' { "explicit_networks" : [ "198.51.100. 0/24" ] } '
        self.assertIn(b"100. 0", guard._strip_json_structural_whitespace(raw))
        self.assertEqual(guard.review(raw), "HOLD")

    def test_minifier_does_not_drop_escaped_quote_or_backslash(self):
        raw = b'{"explicit_networks":["198.51.100.0\\/24"]}'
        minified = guard._strip_json_structural_whitespace(raw)
        self.assertEqual(minified, raw)
        self.assertEqual(guard.review(raw), "HOLD")

    def test_real_cli_valid_returns_nonzero_and_no_grant(self):
        done = self._cli(self._payload(["8.8.8.0/24"]))
        self.assertEqual(done.returncode, 3, done.stderr.decode(errors="replace"))
        self.assertEqual(done.stderr, b"")
        self.assertEqual(json.loads(done.stdout)["disposition"], "REVIEW_ONLY")
        self.assertFalse(json.loads(done.stdout)["authorizes_execution"])

    def test_real_cli_invalid_is_private_and_nonzero(self):
        marker = "PRIVATE-SYNTHETIC-TARGET-NEVER-PRINT"
        done = self._cli(self._payload([marker]))
        self.assertEqual(done.returncode, 2, done.stderr.decode(errors="replace"))
        self.assertEqual(done.stderr, b"")
        self.assertEqual(json.loads(done.stdout)["disposition"], "HOLD")
        self.assertNotIn(marker.encode(), done.stdout + done.stderr)
        self.assertNotIn(b"PRIVATE", done.stdout + done.stderr)

    def test_real_cli_oversize_is_hold_and_never_leaks(self):
        done = self._cli(b"x" * (guard.MAX_JSON_BYTES + 100))
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stdout)["disposition"], "HOLD")
        self.assertEqual(done.stderr, b"")


if __name__ == "__main__":
    unittest.main()
