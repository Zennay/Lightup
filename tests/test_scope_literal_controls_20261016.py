"""Inert control-character scope witness and offline reviewer contract."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Target
from lightup.scope import ScopePolicy
from lightup.scope_literal_control_review_20261016 import LiteralReview, review_literals

CLI = ROOT / "scripts" / "review_scope_literal_controls_20261016.py"


class LiteralReviewTests(unittest.TestCase):
    def test_valid_literal_is_review_only_and_all_authority_false(self):
        value = review_literals(("localhost", "127.0.0.1", "security.example.test"))
        self.assertEqual(value.status, "REVIEW_ONLY")
        self.assertFalse(value.authorized)
        self.assertFalse(value.consent_verified)
        self.assertFalse(value.dispatch_allowed)
        self.assertFalse(value.release_allowed)

    def test_all_ascii_controls_and_delete_hold(self):
        for number in list(range(32)) + [127]:
            with self.subTest(code=number):
                self.assertEqual(review_literals(("local" + chr(number) + "host",)).status, "HOLD")

    def test_unicode_format_and_bidirectional_controls_hold(self):
        for ch in ("\u202e", "\u200b", "\u2066", "\u00a0", "\u0085", "\ufeff"):
            with self.subTest(code=hex(ord(ch))):
                self.assertEqual(review_literals(("lab" + ch + ".test",)).status, "HOLD")

    def test_no_coercion_of_untrusted_types(self):
        class Sneaky(str):
            def __str__(self):
                raise AssertionError("must not call user methods")
        for value in (Sneaky("localhost"), b"localhost", 1, True, None, object()):
            with self.subTest(kind=type(value).__name__):
                self.assertEqual(review_literals((value,)).status, "HOLD")

    def test_container_must_be_builtin_tuple(self):
        for value in (["localhost"], "localhost", {}, (), tuple(["localhost"] * 65)):
            self.assertEqual(review_literals(value).status, "HOLD")

    def test_duplicates_are_atomic_hold(self):
        self.assertEqual(review_literals(("localhost", "localhost")).status, "HOLD")

    def test_length_fences(self):
        self.assertEqual(review_literals(("a" * 512,)).status, "REVIEW_ONLY")
        self.assertEqual(review_literals(("a" * 513,)).status, "HOLD")
        self.assertEqual(review_literals(("",)).status, "HOLD")
        self.assertEqual(review_literals(tuple(str(i) for i in range(64))).status, "REVIEW_ONLY")

    def test_review_result_is_immutable(self):
        value = review_literals(("localhost",))
        with self.assertRaises((AttributeError, TypeError)):
            value.authorized = True
        self.assertFalse(review_literals(("localhost",)).authorized)

    def test_constructor_cannot_claim_authority(self):
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            with self.subTest(flag=flag):
                with self.assertRaises(TypeError):
                    LiteralReview("REVIEW_ONLY", **{flag: True})

    def test_object_bypass_cannot_poison_later_reviews(self):
        first = review_literals(("localhost",))
        object.__setattr__(first, "authorized", True)
        self.assertTrue(first.authorized)  # Frozen is not a cryptographic boundary.
        second = review_literals(("localhost",))
        self.assertIsNot(first, second)
        self.assertFalse(second.authorized)
        self.assertFalse(review_literals(("local\nhost",)).authorized)

    def test_never_echo_candidate_in_result(self):
        result = review_literals(("fictional-private-secret-not-an-asset",))
        self.assertNotIn("fictional-private-secret", repr(result))

    def test_review_module_stays_unwired_from_real_runtime(self):
        reviewer = "scope_literal_control_review_20261016"
        for file in sorted((ROOT / "src" / "lightup").rglob("*.py")):
            if file.stem == reviewer:
                continue
            with self.subTest(module=str(file.relative_to(ROOT))):
                tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotIn(reviewer, node.module or "")
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn(reviewer, alias.name)

    def test_strictly_offline_no_sockets(self):
        from unittest.mock import patch
        with patch("socket.socket", side_effect=AssertionError("no network")):
            self.assertEqual(review_literals(("localhost",)).status, "REVIEW_ONLY")


class LiteralCliTests(unittest.TestCase):
    def run_cli(self, payload):
        return subprocess.run(
            [sys.executable, str(CLI)], input=payload, capture_output=True,
            cwd=ROOT, check=False, timeout=12, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )

    def test_review_output_is_hardcoded_no_authority(self):
        result = self.run_cli(b'{"authorities":["localhost","lab.example.test"]}')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "REVIEW_ONLY")
        self.assertNotIn(b"localhost", result.stdout)
        self.assertNotIn(b"lab.example.test", result.stdout)
        self.assertNotIn(True, json.loads(result.stdout).values())

    def test_every_ascii_control_is_generic_hold(self):
        for code in list(range(32)) + [127]:
            with self.subTest(code=code):
                payload = json.dumps({"authorities": ["loc" + chr(code) + "alhost"]}, separators=(",", ":")).encode("ascii")
                result = self.run_cli(payload)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")

    def test_malformed_schema_and_bytes_hold(self):
        cases = [
            b"", b"[]", b"{}", b'{"authorities":[]}', b'{"authorities":"localhost"}',
            b'{"authorities":["localhost"],"extra":0}',
            b'{"authorities":["localhost"],"authorities":["localhost"]}',
            b'{"authorities":["localhost"]} ', b'{"authorities":["localhost"]}\n',
            b'{"authorit\\u0069es":["localhost"]}', b'{"authorities":[NaN]}',
            b'{"authorities":[Infinity]}', b'{"authorities":["local\nhost"]}',
            b'{"authorities":["localhost"]}x', b'{"authorities":["',
            b'{"authorities":["localhost"]}' + b" " * 9000,
            b'{"authorities":[123]}', b'{"authorities":[null]}',
            b'{"authorities":["localhost","localhost"]}',
        ]
        for payload in cases:
            with self.subTest(payload=payload[:70]):
                result = self.run_cli(payload)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
                self.assertNotIn(b"localhost", result.stdout)

    def test_fragmented_pipe_stdin_reaches_same_result(self):
        payload = b'{"authorities":["localhost"]}'
        with subprocess.Popen(
            [sys.executable, str(CLI)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
        ) as proc:
            for value in payload:
                proc.stdin.write(bytes([value]))
                proc.stdin.flush()
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=12), 2)
            self.assertEqual(json.loads(proc.stdout.read())["status"], "REVIEW_ONLY")

    def test_never_returns_success_exit_zero(self):
        for payload in (b'{"authorities":["localhost"]}', b"bad", b""):
            self.assertIn(self.run_cli(payload).returncode, (2, 3))


class InstalledSourceRedWitness(unittest.TestCase):
    """Expected failures belong to the existing source owner #1289.

    Do not patch the real admission logic from this separate parallel lane.
    """
    @unittest.expectedFailure
    def test_original_scope_must_not_convert_newline_to_loopback(self):
        self.assertFalse(ScopePolicy().decide(Target("local\nhost")).allowed)

    @unittest.expectedFailure
    def test_original_scope_must_not_convert_tab_to_loopback(self):
        self.assertFalse(ScopePolicy().decide(Target("127.0.0.\t1")).allowed)

    @unittest.expectedFailure
    def test_original_lab_activation_must_deny_control_char_authority(self):
        gate = ActivationGate(
            ScopePolicy(), ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        with self.assertRaises(PermissionError):
            gate.issue(Target("local\nhost"), "fictional.test-only")

    @unittest.expectedFailure
    def test_original_scope_must_not_convert_newline_in_url(self):
        self.assertFalse(ScopePolicy().decide(Target("https://127.0.0.\n1/")).allowed)


if __name__ == "__main__":
    unittest.main()
