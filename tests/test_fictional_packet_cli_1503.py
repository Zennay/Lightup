"""Opt-in exact-byte offline subprocess tests for fictional-only #1503 CLI."""
from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

from lightup import fictional_packet_cli_1503 as cli
from lightup.fictional_packet_copy_1503 import CopyReview, build_fictional_copy_packet

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src"
GOOD = build_fictional_copy_packet(
    "alpha.example.test", "REVIEW_REQUIRED", ("metadata_read", "report_preview")
)
BAD_COPY = build_fictional_copy_packet(
    "beta.example.test", "REVIEW_REQUIRED", ("metadata_read", "report_preview")
)
assert type(GOOD) is bytes and type(BAD_COPY) is bytes


def request(original=GOOD, copies=(GOOD,)):
    return json.dumps(
        {"schema": "lightup-fictional-cli-v1",
         "original": original.decode("ascii"),
         "copies": [c.decode("ascii") for c in copies]},
        ensure_ascii=True, separators=(",", ":"), sort_keys=False,
    ).encode("ascii")



def request_pinned(original=GOOD, copies=(GOOD,), expected_sha256=None):
    if expected_sha256 is None:
        expected_sha256 = hashlib.sha256(GOOD).hexdigest()
    return json.dumps(
        {
            "schema": "lightup-fictional-cli-pinned-v1",
            "original": original.decode("ascii"),
            "copies": [copy.decode("ascii") for copy in copies],
            "expected_sha256": expected_sha256,
        },
        ensure_ascii=True, separators=(",", ":"), sort_keys=False,
    ).encode("ascii")


def process(payload, args=(), module="lightup.fictional_packet_cli_1503"):
    env = {**os.environ, "PYTHONPATH": str(PACKAGE), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=ROOT, timeout=15, check=False,
    )


class FictionalCliTests(unittest.TestCase):
    def assert_hold(self, payload):
        verdict = cli._parse_request(payload)
        self.assertEqual(verdict.status, "HOLD")
        self.assertIsNone(verdict.sha256)
        output = cli._render(verdict)
        self.assertEqual(output, cli._HOLD)
        self.assertNotIn(b"alpha.example.test", output)
        self.assertNotIn(b"beta.example.test", output)
        self.assertIs(verdict.authorized, False)
        self.assertIs(verdict.consent_verified, False)
        self.assertIs(verdict.dispatch_allowed, False)
        self.assertIs(verdict.release_allowed, False)

    def test_valid_single_copy_nonzero_exit_and_literal_false_flags(self):
        result = process(request())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"")
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "REVIEW_ONLY")
        self.assertEqual(data["sha256"], hashlib.sha256(GOOD).hexdigest())
        self.assertIs(data["authorized"], False)
        self.assertIs(data["consent_verified"], False)
        self.assertIs(data["dispatch_allowed"], False)
        self.assertIs(data["release_allowed"], False)
        self.assertNotIn(b"alpha.example.test", result.stdout)

    def test_valid_sixteen_copies_subprocess(self):
        result = process(request(copies=(GOOD,) * 16))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'"status":"REVIEW_ONLY"', result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_changed_last_copy_atomic_hold_subprocess(self):
        result = process(request(copies=(GOOD,) * 15 + (BAD_COPY,)))
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, cli._HOLD)
        self.assertEqual(result.stderr, b"")

    def test_checked_in_cli_fixtures_exact_no_newline_and_subprocess(self):
        folder = ROOT / "docs" / "examples"
        valid = (folder / "fictional-copy-cli-1503.json").read_bytes()
        held = (folder / "fictional-copy-cli-held-1503.json").read_bytes()
        self.assertEqual(valid, request(copies=(GOOD,) * 2))
        self.assertEqual(held, request(copies=(GOOD, BAD_COPY)))
        for raw, code, marker in (
            (valid, 2, b'"status":"REVIEW_ONLY"'),
            (held, 3, b'"status":"HOLD"'),
        ):
            with self.subTest(code=code):
                result = process(raw)
                self.assertEqual((result.returncode, result.stderr), (code, b""))
                self.assertIn(marker, result.stdout)
                self.assertNotIn(b".example.test", result.stdout)

    def test_changed_not_reparsed_with_whitespace_or_trailing_newline(self):
        self.assert_hold(b" " + request())
        self.assert_hold(request() + b"\n")
        self.assert_hold(request().replace(b":", b": ", 1))

    def test_extra_missing_duplicate_reordered_fields_hold(self):
        valid = request()
        self.assert_hold(valid[:-1] + b',"unknown":"approval"}')
        self.assert_hold(valid.replace(b'"copies":', b'"new_copies":'))
        self.assert_hold(valid[:-1] + b',"schema":"lightup-fictional-cli-v1"}')
        self.assert_hold(valid.replace(
            b'{"schema":"lightup-fictional-cli-v1","original":',
            b'{"original":'
        ))

    def test_invalid_envelope_types_fenced(self):
        valid = json.loads(request())
        for key, bad in (
            ("schema", None), ("schema", True), ("original", 1),
            ("original", None), ("copies", "not-a-list"),
            ("copies", {}), ("copies", []), ("copies", [GOOD.decode()] * 17),
            ("copies", [GOOD.decode(), None]),
        ):
            with self.subTest(key=key, bad=str(bad)[:20]):
                changed = dict(valid)
                changed[key] = bad
                self.assert_hold(json.dumps(
                    changed, separators=(",", ":"), ensure_ascii=True,
                ).encode("ascii"))

    def test_noncanonical_subpacket_held_without_partial_hash(self):
        for other in (
            GOOD + b" ", GOOD.replace(b"alpha", b"client"),
            GOOD.replace(b"false", b"true"),
            GOOD.replace(b"alpha", b"\\u0061lpha"),
        ):
            with self.subTest(other=other[:10]):
                self.assert_hold(request(copies=(other,)))

    def test_oversize_non_ascii_and_polymorphic_stdin_hold(self):
        class AlienBytes(bytes):
            pass
        for payload in (
            None, "", b"", bytearray(request()), AlienBytes(request()),
            b"x" * 8193, b'{"schema":"a","original":"\xff","copies":[]}',
            b"{" * 2500,
        ):
            with self.subTest(typ=type(payload).__name__):
                self.assert_hold(payload)

    def test_nans_unicode_alias_and_control_held(self):
        self.assert_hold(request().replace(b'"copies":', b'"copies":NaN,"unused":'))
        self.assert_hold(request().replace(b"alpha", b"\\u0061lpha"))
        self.assert_hold(request().replace(b"alpha", "álpha".encode("utf-8")))
        self.assert_hold(b"\xef\xbb\xbf" + request())

    def test_cli_parser_one_byte_mutation_never_yields_review(self):
        original = request()
        for index in range(len(original)):
            replacement = (original[index] + 1) % 256
            altered = original[:index] + bytes((replacement,)) + original[index + 1:]
            self.assertEqual(cli._parse_request(altered).status, "HOLD")

    def test_result_renderer_does_not_trust_polymorphic_or_poisoned_records(self):
        class AlienCopyReview(CopyReview):
            pass
        good = cli._parse_request(request())
        self.assertEqual(good.status, "REVIEW_ONLY")
        self.assertEqual(cli._render(AlienCopyReview("REVIEW_ONLY", good.sha256)),
                         cli._HOLD)
        object.__setattr__(good, "authorized", True)
        self.assertEqual(cli._render(good), cli._HOLD)
        object.__setattr__(good, "authorized", False)
        object.__setattr__(good, "sha256", "fake")
        self.assertEqual(cli._render(good), cli._HOLD)

    def test_real_subprocess_bad_input_is_generic_hold_and_nonzero(self):
        for payload in (
            b"", b"garbage", b"{", b"{" * 8300,
            request(copies=(GOOD, BAD_COPY)), request() + b"\n",
        ):
            result = process(payload)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, cli._HOLD)
            self.assertEqual(result.stderr, b"")

    def test_render_output_is_bounded_and_never_contains_source_values(self):
        for payload in (
            request(), request(copies=(BAD_COPY,)), b"secret-password",
        ):
            rendered = cli._render(cli._parse_request(payload))
            self.assertLessEqual(len(rendered), 200)
            self.assertTrue(rendered.endswith(b"\n"))
            self.assertNotIn(b"secret", rendered)
            self.assertNotIn(b".example.test", rendered)

    def test_unwired_cli_absent_from_production_source_modules(self):
        for path in (PACKAGE / "lightup").rglob("*.py"):
            if path.name in ("fictional_packet_cli_1503.py",
                             "fictional_packet_cli_pinned_1503.py",
                             "fictional_packet_copy_1503.py"):
                continue
            self.assertNotIn("fictional_packet_cli_1503",
                             path.read_text(encoding="utf-8"))

    def test_cli_holds_on_stdin_oserror_and_does_not_echo(self):
        class BadStdin:
            class buffer:
                @staticmethod
                def read(_amount):
                    raise OSError("fictional secret")
        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()
        o = Out()
        with patch.object(cli.sys, "stdin", BadStdin()), patch.object(cli.sys, "stdout", o):
            self.assertEqual(cli.main(), 3)
        self.assertEqual(o.buffer.getvalue(), cli._HOLD)

    def test_cli_fails_nonzero_on_broken_stdout(self):
        class Input:
            def __init__(self, payload):
                self.buffer = io.BytesIO(payload)
        class Broken:
            class buffer:
                @staticmethod
                def write(_data):
                    raise BrokenPipeError("disconnected")
        with patch.object(cli.sys, "stdin", Input(request())), \
             patch.object(cli.sys, "stdout", Broken()):
            self.assertEqual(cli.main(), 3)


    def test_unknown_commandline_flags_never_promote_review(self):
        for args in (
            ("--approve",), ("--grant", "yes"), ("--output", "approval.json"),
            ("--help",), ("--unsafe",), ("file.json",),
        ):
            with self.subTest(args=args):
                result = process(request(), args=args)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(result.stdout, cli._HOLD)
                self.assertEqual(result.stderr, b"")

    def test_incomplete_or_noninteger_stdout_write_always_exits_three(self):
        class Input:
            def __init__(self, raw):
                self.buffer = io.BytesIO(raw)
        class Out:
            def __init__(self, result):
                self.result = result
                self.buffer = self
                self.output = []
            def write(self, data):
                self.output.append(bytes(data))
                return self.result
            def flush(self):
                pass
        for wrote in (0, 1, None, True, False, -1, len(cli._HOLD)):
            with self.subTest(wrote=wrote):
                out = Out(wrote)
                with patch.object(cli.sys, "argv", ["fictional_packet_cli_1503.py"]), \
                     patch.object(cli.sys, "stdin", Input(request())), \
                     patch.object(cli.sys, "stdout", out):
                    self.assertEqual(cli.main(), 3)
                self.assertTrue(out.output)
                self.assertTrue(out.output[0].startswith(b'{"status":"REVIEW_ONLY"'))

    def test_successful_stdout_write_requires_full_length(self):
        class Input:
            def __init__(self):
                self.buffer = io.BytesIO(request())
        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()
        out = Out()
        with patch.object(cli.sys, "argv", ["fictional_packet_cli_1503.py"]), \
             patch.object(cli.sys, "stdin", Input()), \
             patch.object(cli.sys, "stdout", out):
            self.assertEqual(cli.main(), 2)
        self.assertTrue(out.buffer.getvalue().endswith(b"\n"))
        self.assertNotIn(b".example.test", out.buffer.getvalue())



    def test_missing_binary_stdin_or_stdout_is_generic_nonzero_hold(self):
        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()
        output = Out()
        with patch.object(cli.sys, "argv", ["fictional_packet_cli_1503.py"]), \
             patch.object(cli.sys, "stdin", io.StringIO("no-binary-input")), \
             patch.object(cli.sys, "stdout", output):
            self.assertEqual(cli.main(), 3)
        self.assertEqual(output.buffer.getvalue(), cli._HOLD)
        class Input:
            def __init__(self):
                self.buffer = io.BytesIO(request())
        with patch.object(cli.sys, "argv", ["fictional_packet_cli_1503.py"]), \
             patch.object(cli.sys, "stdin", Input()), \
             patch.object(cli.sys, "stdout", io.StringIO()):
            self.assertEqual(cli.main(), 3)

    def test_poisoned_review_status_type_is_generic_hold_without_callback(self):
        class Alien(str):
            def __ne__(self, other):
                raise AssertionError("should never call attacker comparison")
        good = cli._parse_request(request())
        object.__setattr__(good, "status", Alien("REVIEW_ONLY"))
        self.assertEqual(cli._render(good), cli._HOLD)


    def test_builder_reproduces_exact_committed_cli_examples(self):
        folder = ROOT / "docs" / "examples"
        self.assertEqual(
            cli.build_fictional_cli_envelope(GOOD, (GOOD, GOOD)),
            (folder / "fictional-copy-cli-1503.json").read_bytes(),
        )
        self.assertEqual(
            cli.build_fictional_cli_envelope(GOOD, (GOOD, BAD_COPY)),
            (folder / "fictional-copy-cli-held-1503.json").read_bytes(),
        )

    def test_builder_matches_canonical_reference_all_copy_count_boundaries(self):
        for count in (1, 2, 8, 15, 16):
            with self.subTest(count=count):
                copies = (GOOD,) * count
                built = cli.build_fictional_cli_envelope(GOOD, copies)
                self.assertEqual(built, request(copies=copies))
                self.assertLessEqual(len(built), 8192)
                self.assertEqual(cli._parse_request(built).status, "REVIEW_ONLY")
                self.assertEqual(process(built).returncode, 2)

    def test_builder_valid_changed_copy_produces_exact_hold_envelope(self):
        for count in (1, 2, 16):
            with self.subTest(count=count):
                copies = (GOOD,) * (count - 1) + (BAD_COPY,)
                encoded = cli.build_fictional_cli_envelope(GOOD, copies)
                self.assertEqual(encoded, request(copies=copies))
                review = cli._parse_request(encoded)
                self.assertEqual((review.status, review.sha256), ("HOLD", None))
                self.assertIs(review.authorized, False)

    def test_builder_rejects_bad_types_nonfictional_and_oversized_batches(self):
        class ByteSubclass(bytes):
            def decode(self, _encoding):
                raise AssertionError("subclass decode callback forbidden")
        class TupleSubclass(tuple):
            def __iter__(self):
                raise AssertionError("subclass iteration callback forbidden")
        for original, copies in (
            (None, (GOOD,)),
            (b"", (GOOD,)),
            (ByteSubclass(GOOD), (GOOD,)),
            (GOOD, []),
            (GOOD, ()),
            (GOOD, (GOOD,) * 17),
            (GOOD, TupleSubclass((GOOD,))),
            (GOOD, (ByteSubclass(GOOD),)),
            (GOOD, (GOOD, b"client.example.com")),
            (GOOD, (GOOD, None)),
        ):
            with self.subTest(typ=type(original).__name__, count=str(type(copies))):
                self.assertIsNone(cli.build_fictional_cli_envelope(original, copies))

    def test_builder_isolated_from_io_and_does_not_grant_consent(self):
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("socket.socket", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            good = cli.build_fictional_cli_envelope(GOOD, (GOOD,))
            bad = cli.build_fictional_cli_envelope(GOOD, (BAD_COPY,))
            self.assertEqual(cli._parse_request(good).status, "REVIEW_ONLY")
            self.assertEqual(cli._parse_request(bad).status, "HOLD")
            for raw in (good, bad):
                obj = json.loads(raw)
                self.assertEqual(tuple(obj), ("schema", "original", "copies"))
                self.assertEqual(obj["schema"], "lightup-fictional-cli-v1")
                self.assertNotIn("approved", obj)
                for p in (obj["original"], *obj["copies"]):
                    parsed = json.loads(p)
                    for k in ("authorized", "consent_verified", "dispatch_allowed",
                              "release_allowed"):
                        self.assertIs(parsed[k], False)



    def test_independently_pinned_cli_subprocess_is_non_authorizing(self):
        payload = request_pinned(copies=(GOOD,) * 16)
        result = process(payload)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"")
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "REVIEW_ONLY")
        self.assertEqual(parsed["sha256"], hashlib.sha256(GOOD).hexdigest())
        for field in ("authorized", "consent_verified", "dispatch_allowed",
                      "release_allowed"):
            self.assertIs(parsed[field], False)

    def test_pinned_cli_denies_both_packets_substituted_against_old_pin(self):
        # Unpinned v1 cannot detect synchronized replacement.
        forged_unpinned = request(original=BAD_COPY, copies=(BAD_COPY, BAD_COPY))
        self.assertEqual(cli._parse_request(forged_unpinned).status, "REVIEW_ONLY")
        old_pin = hashlib.sha256(GOOD).hexdigest()
        forged_pinned = request_pinned(
            original=BAD_COPY, copies=(BAD_COPY, BAD_COPY),
            expected_sha256=old_pin,
        )
        result = process(forged_pinned)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, cli._HOLD)
        self.assertEqual(result.stderr, b"")

    def test_caller_can_forge_new_pin_so_no_origin_authority(self):
        forged = request_pinned(
            original=BAD_COPY, copies=(BAD_COPY,),
            expected_sha256=hashlib.sha256(BAD_COPY).hexdigest(),
        )
        # Verifies only equality against caller-controlled pin, NOT consent.
        result = cli._parse_request(forged)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertIs(result.authorized, False)
        self.assertIs(result.release_allowed, False)

    def test_pinned_builder_is_exact_and_reproduces_reference(self):
        digest = hashlib.sha256(GOOD).hexdigest()
        for copies in ((GOOD,), (GOOD,) * 16, (GOOD, BAD_COPY)):
            with self.subTest(count=len(copies)):
                payload = cli.build_fictional_pinned_cli_envelope(
                    GOOD, copies, digest,
                )
                self.assertIs(type(payload), bytes)
                self.assertEqual(payload, request_pinned(copies=copies))
                self.assertLessEqual(len(payload), 8192)
        self.assertEqual(cli._parse_request(
            cli.build_fictional_pinned_cli_envelope(GOOD, (BAD_COPY,), digest)
        ).status, "HOLD")

    def test_strict_pinned_envelope_keys_and_schema_do_not_confuse_v1(self):
        basic = json.loads(request())
        basic["expected_sha256"] = hashlib.sha256(GOOD).hexdigest()
        self.assert_hold(json.dumps(
            basic, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii"))
        pinned = json.loads(request_pinned())
        pinned["schema"] = "lightup-fictional-cli-v1"
        self.assert_hold(json.dumps(
            pinned, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii"))
        valid = request_pinned()
        self.assert_hold(valid + b"\n")
        self.assert_hold(b" " + valid)
        self.assert_hold(valid[:-1] + b',"expected_sha256":"0"}')
        self.assert_hold(valid.replace(b'"expected_sha256":', b'"pin":'))
        self.assert_hold(valid.replace(
            b',"expected_sha256":', b',"unknown":1,"expected_sha256":'
        ))

    def test_pinned_malformed_hash_and_overlong_reference_atomic_hold(self):
        digest = hashlib.sha256(GOOD).hexdigest()
        for pin in (
            "0" * 64, digest.upper(), digest[:-1], digest + "0",
            " " + digest[:-1], "X" * 64, 0, True, None, [],
        ):
            with self.subTest(kind=str(type(pin))):
                envelope = json.dumps({
                    "schema": "lightup-fictional-cli-pinned-v1",
                    "original": GOOD.decode("ascii"),
                    "copies": [GOOD.decode("ascii")],
                    "expected_sha256": pin,
                }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
                result = cli._parse_request(envelope)
                self.assertEqual((result.status, result.sha256), ("HOLD", None))

    def test_pinned_builder_exact_type_boundary_no_subclass_callbacks(self):
        class AlienPin(str):
            def __eq__(self, _):
                raise AssertionError("must reject subclasses before equality")
        digest = hashlib.sha256(GOOD).hexdigest()
        for pin in (
            None, True, digest.upper(), "G" * 64,
            digest[:-1], AlienPin(digest),
        ):
            with self.subTest(type=type(pin).__name__):
                self.assertIsNone(
                    cli.build_fictional_pinned_cli_envelope(GOOD, (GOOD,), pin)
                )
        self.assertIsNone(
            cli.build_fictional_pinned_cli_envelope(
                GOOD, (GOOD,) * 17, digest
            )
        )

    def test_pinned_cli_output_does_not_echo_pin_or_target(self):
        supplied_pin = "0" * 64
        payload = request_pinned(
            original=BAD_COPY, copies=(BAD_COPY,), expected_sha256=supplied_pin,
        )
        result = process(payload)
        self.assertEqual(result.stdout, cli._HOLD)
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(b"beta.example.test", result.stdout)
        self.assertNotIn(supplied_pin.encode("ascii"), result.stdout)

    def test_pinned_path_no_file_socket_sqlite_process_adapters(self):
        digest = hashlib.sha256(GOOD).hexdigest()
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("socket.socket", side_effect=AssertionError("net")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            payload = cli.build_fictional_pinned_cli_envelope(
                GOOD, (GOOD,), digest,
            )
            self.assertEqual(cli._parse_request(payload).status, "REVIEW_ONLY")
            self.assertEqual(cli._parse_request(
                cli.build_fictional_pinned_cli_envelope(
                    GOOD, (BAD_COPY,), digest
                )
            ).status, "HOLD")



    def test_pinned_checked_in_exact_envelopes_exercise_real_cli(self):
        folder = ROOT / "docs" / "examples"
        valid = (folder / "fictional-copy-cli-pinned-1503.json").read_bytes()
        held = (folder / "fictional-copy-cli-pinned-held-1503.json").read_bytes()
        expected_pin = hashlib.sha256(GOOD).hexdigest()
        self.assertEqual(
            valid, request_pinned(copies=(GOOD, GOOD), expected_sha256=expected_pin),
        )
        self.assertEqual(
            held, request_pinned(original=BAD_COPY, copies=(BAD_COPY, BAD_COPY),
                                expected_sha256=expected_pin),
        )
        self.assertEqual(
            valid,
            cli.build_fictional_pinned_cli_envelope(
                GOOD, (GOOD, GOOD), expected_pin,
            ),
        )
        self.assertEqual(
            held,
            cli.build_fictional_pinned_cli_envelope(
                BAD_COPY, (BAD_COPY, BAD_COPY), expected_pin,
            ),
        )
        for payload, exit_status, expected_output in (
            (valid, 2, b'"status":"REVIEW_ONLY"'),
            (held, 3, b'"status":"HOLD"'),
        ):
            with self.subTest(status=exit_status):
                result = process(payload)
                self.assertEqual((result.returncode, result.stderr), (exit_status, b""))
                self.assertIn(expected_output, result.stdout)
                self.assertNotIn(b".example.test", result.stdout)
                self.assertLessEqual(len(result.stdout), 200)



    def test_pinned_only_subprocess_rejects_valid_unpinned_v1(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        for copies in ((GOOD,), (GOOD,) * 16):
            old = request(copies=copies)
            self.assertEqual(process(old).returncode, 2)
            result = process(old, module=module)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (3, cli._HOLD, b""))
            self.assertNotIn(b".example.test", result.stdout)

    def test_pinned_only_subprocess_accepts_valid_v2_without_authority(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        for copies in ((GOOD,), (GOOD, GOOD), (GOOD,) * 16):
            with self.subTest(count=len(copies)):
                result = process(request_pinned(copies=copies), module=module)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stderr, b"")
                verdict = json.loads(result.stdout)
                self.assertEqual(verdict["status"], "REVIEW_ONLY")
                self.assertEqual(verdict["sha256"], hashlib.sha256(GOOD).hexdigest())
                for key in ("authorized", "consent_verified",
                            "dispatch_allowed", "release_allowed"):
                    self.assertIs(verdict[key], False)
                self.assertNotIn(b".example.test", result.stdout)

    def test_pinned_only_denies_joint_forgery_with_fixed_external_pin(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        result = process(
            request_pinned(original=BAD_COPY, copies=(BAD_COPY,) * 16),
            module=module,
        )
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (3, cli._HOLD, b""))
        # A dishonest actor replacing the PIN too still cannot authenticate.
        same_forged_pin = request_pinned(
            original=BAD_COPY, copies=(BAD_COPY,),
            expected_sha256=hashlib.sha256(BAD_COPY).hexdigest(),
        )
        outcome = process(same_forged_pin, module=module)
        self.assertEqual(outcome.returncode, 2)
        self.assertIs(json.loads(outcome.stdout)["authorized"], False)

    def test_pinned_only_denies_downgrade_even_with_field_injection(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        for payload in (
            request(),
            request_pinned().replace(b"lightup-fictional-cli-pinned-v1",
                                     b"lightup-fictional-cli-v1"),
            request_pinned() + b"\\n",
            b" " + request_pinned(),
            request_pinned().replace(b'"expected_sha256":',
                                     b'"pinned_sha256":'),
            request_pinned().replace(b'"original":', b'"original" :'),
        ):
            with self.subTest(length=len(payload)):
                result = process(payload, module=module)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(result.stdout, cli._HOLD)
                self.assertEqual(result.stderr, b"")

    def test_pinned_only_denies_all_commandline_options(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        for args in (("--help",), ("--allow-unpinned",),
                     ("--approve",), ("file.json",)):
            result = process(request_pinned(), args=args, module=module)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (3, cli._HOLD, b""))

    def test_pinned_only_in_process_parser_enforces_dedicated_flag(self):
        old = request()
        pinned = request_pinned()
        self.assertEqual(cli._parse_request(old).status, "REVIEW_ONLY")
        self.assertEqual(
            (cli._parse_request(old, pinned_only=True).status,
             cli._parse_request(old, pinned_only=True).sha256),
            ("HOLD", None),
        )
        self.assertEqual(cli._parse_request(pinned, pinned_only=True).status,
                         "REVIEW_ONLY")
        for wrong in (None, 0, 1, "True", [], b"1"):
            with self.subTest(wrong=wrong):
                self.assertEqual(
                    cli._parse_request(pinned, pinned_only=wrong).status,
                    "HOLD",
                )

    def test_pinned_only_fixture_commands_match_legacy_cli_contract(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        examples = ROOT / "docs" / "examples"
        for fname, code in (
            ("fictional-copy-cli-pinned-1503.json", 2),
            ("fictional-copy-cli-pinned-held-1503.json", 3),
        ):
            data = (examples / fname).read_bytes()
            outcome = process(data, module=module)
            self.assertEqual(outcome.returncode, code)
            self.assertEqual(outcome.stderr, b"")
            self.assertNotIn(b".example.test", outcome.stdout)
            expected = process(data)
            self.assertEqual(outcome.stdout, expected.stdout)

    def test_pinned_only_parser_and_renderer_do_not_touch_external_adapters(self):
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("socket.socket", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            old = cli._parse_request(request(), pinned_only=True)
            same = cli._parse_request(request_pinned(), pinned_only=True)
            bad = cli._parse_request(request_pinned(original=BAD_COPY,
                                          copies=(BAD_COPY,)), pinned_only=True)
            self.assertEqual((old.status, bad.status, same.status),
                             ("HOLD", "HOLD", "REVIEW_ONLY"))
            self.assertEqual(cli._render(old), cli._HOLD)
            self.assertIn(b'"status":"REVIEW_ONLY"', cli._render(same))


    def test_pinned_only_every_single_byte_mutation_is_atomic_hold(self):
        # Every one-byte mutation of the canonical, independently pinned
        # synthetic request must fail closed, including schema and pin edits.
        payload = request_pinned(copies=(GOOD, GOOD))
        self.assertEqual(cli._parse_request(payload, pinned_only=True).status,
                         "REVIEW_ONLY")
        for index in range(len(payload)):
            altered = (
                payload[:index]
                + bytes(((payload[index] + 1) % 256,))
                + payload[index + 1:]
            )
            review = cli._parse_request(altered, pinned_only=True)
            self.assertEqual(
                (review.status, review.sha256), ("HOLD", None),
                msg="unexpected one-byte mutation acceptance at index %d" % index,
            )
            self.assertIs(review.authorized, False)

    def test_pinned_only_joint_copy_edits_still_held_with_original_pin(self):
        original_pin = hashlib.sha256(GOOD).hexdigest()
        raw = GOOD
        for index in range(len(raw)):
            replacement = bytes(((raw[index] + 1) % 256,))
            changed = raw[:index] + replacement + raw[index + 1:]
            # Any arbitrary synthetic corruption of all copies with the same
            # independent reference must hold without echo or partial SHA.
            wrapped = json.dumps(
                {
                    "schema": "lightup-fictional-cli-pinned-v1",
                    "original": changed.decode("latin1"),
                    "copies": [changed.decode("latin1"), changed.decode("latin1")],
                    "expected_sha256": original_pin,
                },
                ensure_ascii=True, separators=(",", ":"),
            ).encode("ascii")
            verdict = cli._parse_request(wrapped, pinned_only=True)
            self.assertEqual((verdict.status, verdict.sha256), ("HOLD", None))
            self.assertEqual(cli._render(verdict), cli._HOLD)

    def test_pinned_only_resource_caps_in_real_subprocess(self):
        module = "lightup.fictional_packet_cli_pinned_1503"
        for raw in (b"x" * 8193, b"{" * 8193, b"", b"\xff", b"[]",
                    request_pinned(copies=(GOOD,) * 16) + b" "):
            outcome = process(raw, module=module)
            self.assertEqual(
                (outcome.returncode, outcome.stdout, outcome.stderr),
                (3, cli._HOLD, b""),
            )



    def test_full_stdin_reader_reassembles_short_valid_pinned_chunks(self):
        source = request_pinned(copies=(GOOD, GOOD))
        class Chunks:
            def __init__(self, data, chunk_size):
                self.data = data
                self.chunk_size = chunk_size
                self.offset = 0
                self.calls = 0
            def read(self, max_length):
                self.calls += 1
                n = min(self.chunk_size, max_length, len(self.data) - self.offset)
                chunk = self.data[self.offset:self.offset + n]
                self.offset += n
                return chunk
        for size in (1, 2, 3, 7, 31, 1024):
            with self.subTest(size=size):
                reader = Chunks(source, size)
                received = cli._read_bounded_stdin(reader)
                self.assertEqual(received, source)
                self.assertEqual(
                    cli._parse_request(received, pinned_only=True).status,
                    "REVIEW_ONLY",
                )
                self.assertGreater(reader.calls, 1)

    def test_fragmented_stdin_never_ignores_trailing_bytes_after_valid_json(self):
        valid = request_pinned()
        class Delayed:
            def __init__(self, pieces):
                self.pieces = iter(pieces)
            def read(self, max_length):
                piece = next(self.pieces, b"")
                self.max_length = max_length
                return piece
        for trailing in (b" ", b"\n", b"{}", b'{"authorized":true}',
                         b"PASSWORD-DUMMY-NO-ECHO"):
            with self.subTest(trailing=trailing):
                stream = Delayed((valid, trailing, b""))
                received = cli._read_bounded_stdin(stream)
                self.assertEqual(received, valid + trailing)
                result = cli._parse_request(received, pinned_only=True)
                self.assertEqual((result.status, result.sha256), ("HOLD", None))
                self.assertEqual(cli._render(result), cli._HOLD)

    def test_pinned_only_main_reads_complete_fragmented_stream(self):
        valid = request_pinned()
        class Chunks:
            def __init__(self, data):
                self.data = data
                self.offset = 0
            def read(self, maximum):
                end = min(len(self.data), self.offset + 11, self.offset + maximum)
                result = self.data[self.offset:end]
                self.offset = end
                return result
        class Input:
            def __init__(self, data):
                self.buffer = Chunks(data)
        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()
        for raw, code in ((valid, 2), (valid + b" ", 3),
                          (valid + b'{"dispatch_allowed":true}', 3)):
            with self.subTest(ending=raw[len(valid):]):
                sink = Output()
                with patch.object(cli.sys, "argv", ["fictional-pinned"]), \
                     patch.object(cli.sys, "stdin", Input(raw)), \
                     patch.object(cli.sys, "stdout", sink):
                    self.assertEqual(cli.main_pinned(), code)
                output = sink.buffer.getvalue()
                self.assertLessEqual(len(output), 200)
                self.assertNotIn(b".example.test", output)
                self.assertIn(
                    b'"status":"REVIEW_ONLY"' if code == 2 else b'"status":"HOLD"',
                    output,
                )

    def test_reader_rejects_nonbytes_chunks_and_overlimit_without_coercion(self):
        class AlienBytes(bytes):
            def __bytes__(self):
                raise AssertionError("must not coerce caller chunk")
        class InvalidChunk:
            def __init__(self, chunk):
                self.chunk = chunk
            def read(self, _max_length):
                return self.chunk
        for chunk in (
            "text", None, memoryview(b"hi"), bytearray(b"hi"),
            AlienBytes(b"hi"), 1, True, b"x" * 8193,
        ):
            with self.subTest(kind=type(chunk).__name__):
                self.assertIsNone(
                    cli._read_bounded_stdin(InvalidChunk(chunk))
                )

    def test_reader_exact_8192_boundary_and_overflow_in_separate_chunks(self):
        class Parts:
            def __init__(self, parts):
                self.pieces = iter(parts)
                self.requested = []
            def read(self, maximum):
                self.requested.append(maximum)
                return next(self.pieces, b"")
        permitted = Parts((b"a" * 8192, b""))
        self.assertEqual(cli._read_bounded_stdin(permitted), b"a" * 8192)
        self.assertEqual(permitted.requested, [8193, 1])
        rejected = Parts((b"a" * 8192, b"b", b""))
        self.assertIsNone(cli._read_bounded_stdin(rejected))
        self.assertEqual(rejected.requested, [8193, 1])
        for path in (b"a" * 8191, b"x" * 8192):
            excess = Parts((path, b"zz", b""))
            self.assertIsNone(cli._read_bounded_stdin(excess))
            self.assertLessEqual(max(excess.requested), 8193)

    def test_reader_bounded_under_unending_one_byte_stream(self):
        class NeverEnd:
            def __init__(self):
                self.calls = 0
            def read(self, maximum):
                self.calls += 1
                self.last_maximum = maximum
                return b"x"
        stream = NeverEnd()
        self.assertIsNone(cli._read_bounded_stdin(stream))
        self.assertEqual(stream.calls, 8193)
        self.assertEqual(stream.last_maximum, 1)

    def test_trailing_chunks_do_not_bypass_legacy_or_pinned_cli(self):
        # Both public entrypoints share the same complete, bounded reader.
        cases = (
            (request(), cli.main),
            (request_pinned(), cli.main),
            (request_pinned(), cli.main_pinned),
        )
        class Pieces:
            def __init__(self, parts):
                self.parts = iter(parts)
            def read(self, maximum):
                return next(self.parts, b"")
        class In:
            def __init__(self, parts):
                self.buffer = Pieces(parts)
        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()
        for base, method in cases:
            with self.subTest(method=method.__name__, size=len(base)):
                dest = Out()
                with patch.object(cli.sys, "argv", ["only-command"]), \
                     patch.object(cli.sys, "stdin", In((base, b" ", b""))), \
                     patch.object(cli.sys, "stdout", dest):
                    self.assertEqual(method(), 3)
                self.assertEqual(dest.buffer.getvalue(), cli._HOLD)


if __name__ == "__main__":
    unittest.main()
