"""Offline negative and positive safety acceptance for #1509."""
import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "scope_ci_static_fence_1509", ROOT / "scripts/scope_ci_static_fence_1509.py"
)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class StaticFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = (ROOT / ".github/workflows/lightup-ci.yml").read_bytes()

    def assert_no_authority(self, result, state):
        self.assertEqual(result.state, state)
        self.assertFalse(result.authorized)
        self.assertFalse(result.consent_verified)
        self.assertFalse(result.dispatch_allowed)
        self.assertFalse(result.release_allowed)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.authorized = True

    def test_pinned_main_workflow_only_review(self):
        self.assert_no_authority(MOD.review_workflow(self.baseline), "REVIEW_ONLY")

    def test_every_critical_line_removed_is_hold(self):
        original = self.baseline.decode("ascii")
        for line in MOD.REQUIRED_LINES:
            with self.subTest(line=line):
                changed = original.replace(line + "\n", "", 1).encode()
                self.assert_no_authority(MOD.review_workflow(changed), "HOLD")

    def test_critical_changes_are_hold(self):
        variants = {
            "hosted runner": (b"self-hosted, zcloud, vps", b"ubuntu-latest"),
            "wrong host": (b"vps-bb300bba", b"untrusted-host"),
            "extra permissions": (b"contents: read", b"contents: write"),
            "skip integration": (b"tests/integration -v", b"tests/unit -v"),
            "skip canaries": (b"check_safety_canaries.py", b"check_other.py"),
            "persist credentials": (b"persist-credentials: false", b"persist-credentials: true"),
            "loose checkout": (b"pull_request.head.sha", b"pull_request.base.sha"),
            "version drift": (b'\"3.14\"', b'\"3.15\"'),
            "job duration": (b"timeout-minutes: 10", b"timeout-minutes: 120"),
        }
        for name, (before, after) in variants.items():
            with self.subTest(name=name):
                self.assertIn(before, self.baseline)
                self.assert_no_authority(
                    MOD.review_workflow(self.baseline.replace(before, after, 1)), "HOLD"
                )

    def test_all_single_byte_mutations_are_hold(self):
        for offset in range(len(self.baseline)):
            changed = bytearray(self.baseline)
            changed[offset] ^= 1
            with self.subTest(byte=offset):
                self.assert_no_authority(MOD.review_workflow(bytes(changed)), "HOLD")

    def test_ambiguity_and_type_boundary_are_hold(self):
        class BytesSubclass(bytes):
            def decode(self, *args, **kwargs):
                raise AssertionError("must not call attacker-controlled decode")

        inputs = [
            None, True, False, 1, "text", bytearray(self.baseline),
            memoryview(self.baseline), BytesSubclass(self.baseline), b"",
            b"x" * (MOD.MAX_BYTES + 1), self.baseline + b"\n",
            self.baseline.replace(b"\n", b"\r\n"), self.baseline + b"\x00",
            self.baseline + b"# duplicate harmless comment\n",
            self.baseline + b"jobs:\n  release:\n    runs-on: ubuntu-latest\n",
            self.baseline + b"\xff",
        ]
        for value in inputs:
            with self.subTest(kind=type(value).__name__):
                self.assert_no_authority(MOD.review_workflow(value), "HOLD")

    def test_pure_function_has_no_operational_side_effects(self):
        import builtins
        import socket
        import subprocess
        from unittest.mock import patch
        with patch.object(builtins, "open", side_effect=AssertionError("I/O")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assert_no_authority(MOD.review_workflow(self.baseline), "REVIEW_ONLY")
            self.assert_no_authority(MOD.review_workflow(b"bad"), "HOLD")


if __name__ == "__main__":
    unittest.main()
