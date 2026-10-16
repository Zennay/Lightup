"""#1499 hermetic static source inventory acceptance; never imports LightUp code."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import scope_authority_source_inventory_1499 as inventory


class StaticAuthoritySourceInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = {
            rel: (ROOT / rel).read_bytes()
            for rel in inventory.PINNED_SOURCES
        }

    def test_actual_original_five_sources_are_review_only_never_authorized(self):
        verdict = inventory.review_checked_in_sources()
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertEqual(verdict.source_count, 5)
        for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(verdict, name), False)

    def test_explicit_pinned_sha256_match_in_original_all_five(self):
        import hashlib
        self.assertEqual(set(self.baseline), set(inventory.PINNED_SOURCES))
        for path, digest in inventory.PINNED_SOURCES.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(self.baseline[path]).hexdigest(), digest)
                self.assertTrue(inventory.inspect_static_shape(path, self.baseline[path].decode()))

    def test_pure_review_is_deterministic_and_no_source_echo(self):
        first = inventory.review_source_bytes(self.baseline)
        second = inventory.review_source_bytes(dict(reversed(list(self.baseline.items()))))
        self.assertEqual(first, second)
        self.assertNotIn("ScopePolicy", repr(first))
        self.assertNotIn("ExecutionPermit", repr(first))
        self.assertIn("REVIEW_ONLY", repr(first))

    def test_one_byte_mutations_in_each_source_are_atomic_hold(self):
        for path in self.baseline:
            payload = self.baseline[path]
            for offset in (0, len(payload) // 3, len(payload) // 2, len(payload) - 1):
                with self.subTest(path=path, offset=offset):
                    flipped = bytes([payload[offset] ^ 1])
                    changed = {**self.baseline, path: payload[:offset] + flipped + payload[offset + 1:]}
                    self.assertEqual(inventory.review_source_bytes(changed), inventory._hold())

    def test_read_only_trailing_newline_and_crlf_drift_hold(self):
        for path in self.baseline:
            with self.subTest(path=path):
                src = self.baseline[path]
                for new in (src + b"\n", src.replace(b"\n", b"\r\n")):
                    self.assertEqual(inventory.review_source_bytes({**self.baseline, path: new}).status, "HOLD")

    def test_swapped_missing_and_extra_files_hold(self):
        keys = list(self.baseline)
        reversed_bytes = {**self.baseline, keys[0]: self.baseline[keys[1]], keys[1]: self.baseline[keys[0]]}
        missing = dict(self.baseline)
        missing.pop(keys[-1])
        extra = {**self.baseline, "src/lightup/extra.py": b"no"}
        for case in (reversed_bytes, missing, extra):
            with self.subTest(size=len(case)):
                self.assertEqual(inventory.review_source_bytes(case).status, "HOLD")

    def test_invalid_source_mapping_types_never_iterated_or_coerced(self):
        class Malicious(dict):
            def __getitem__(self, key):
                raise AssertionError("do not iterate")
        for case in (None, [], (), "source", {}, Malicious(self.baseline)):
            with self.subTest(type=type(case)):
                self.assertEqual(inventory.review_source_bytes(case).status, "HOLD")

    def test_bytes_subclass_and_nonbytes_hold(self):
        class Malicious(bytes):
            def decode(self, *args):
                raise AssertionError("do not decode")
        file = next(iter(self.baseline))
        for bad in (Malicious(self.baseline[file]), self.baseline[file].decode(), None, memoryview(self.baseline[file])):
            with self.subTest(type=type(bad)):
                self.assertEqual(inventory.review_source_bytes({**self.baseline, file: bad}).status, "HOLD")

    def test_oversized_source_is_rejected_before_hash_or_parse(self):
        file = next(iter(self.baseline))
        self.assertEqual(inventory.review_source_bytes({**self.baseline, file: b"X" * (inventory.MAX_FILE_BYTES + 1)}).status, "HOLD")

    def test_ast_renamed_required_class_method_and_duplicate_class_hold(self):
        original = self.baseline["src/lightup/scope.py"].decode()
        candidates = (
            original.replace("class ScopePolicy:", "class ScopePolicY:"),
            original.replace("def decide(self, target:", "def decide_renamed(self, target:"),
            original + "\nclass ScopePolicy:\n    pass\n",
        )
        for candidate in candidates:
            with self.subTest(index=len(candidate)):
                self.assertFalse(inventory.inspect_static_shape("src/lightup/scope.py", candidate))

    def test_ast_awaitable_and_extra_default_or_decorator_rejected(self):
        original = self.baseline["src/lightup/scope.py"].decode()
        candidates = (
            original.replace("    def decide(self, target:", "    async def decide(self, target:"),
            original.replace("    def decide(self, target: Target)", "    def decide(self, target: Target, bypass=False)"),
            original.replace("    def decide(self, target: Target)", "    @property\n    def decide(self, target: Target)"),
            original.replace("    def decide(self, target: Target)", "    def decide(self, target: Target, *args)"),
        )
        for candidate in candidates:
            with self.subTest(tag=candidate[-100:]):
                self.assertFalse(inventory.inspect_static_shape("src/lightup/scope.py", candidate))

    def test_ast_known_dynamic_interpreter_calls_in_gates_are_flagged(self):
        original = self.baseline["src/lightup/activation.py"].decode()
        for call in ("eval('1')", "exec('a=1')", "compile('a=1','x','exec')", "__import__('os')"):
            with self.subTest(call=call):
                modified = original.replace(
                    "    def issue(self, target: Target, capability_id: str) -> ExecutionPermit:",
                    "    def issue(self, target: Target, capability_id: str) -> ExecutionPermit:\n"
                    "        " + call + "\n",
                )
                self.assertFalse(inventory.inspect_static_shape("src/lightup/activation.py", modified))

    def test_source_scope_normalization_call_cannot_be_replaced(self):
        original = self.baseline["src/lightup/scope.py"].decode()
        modified = original.replace(
            "host = self.normalize_host(target.value)",
            "host = target.value",
        )
        self.assertNotEqual(modified, original)
        self.assertFalse(inventory.inspect_static_shape("src/lightup/scope.py", modified))

    def test_source_scope_current_authorization_call_cannot_be_removed(self):
        original = self.baseline["src/lightup/scope.py"].decode()
        modified = original.replace("target.authorization.is_current()", "True")
        self.assertNotEqual(modified, original)
        self.assertFalse(inventory.inspect_static_shape("src/lightup/scope.py", modified))

    def test_source_activation_early_deny_cannot_be_removed(self):
        original = self.baseline["src/lightup/activation.py"].decode()
        modified = original.replace("if not decision.allowed:", "if False:")
        self.assertNotEqual(modified, original)
        self.assertFalse(inventory.inspect_static_shape("src/lightup/activation.py", modified))

    def test_source_activation_missing_decision_call_holds(self):
        original = self.baseline["src/lightup/activation.py"].decode()
        modified = original.replace("decision = self.scope_policy.decide(target)", "decision = target")
        self.assertNotEqual(modified, original)
        self.assertFalse(inventory.inspect_static_shape("src/lightup/activation.py", modified))

    def test_source_execution_policy_grant_checks_cannot_be_removed(self):
        original = self.baseline["src/lightup/execution_policy.py"].decode()
        for old in ("grant.is_current()", "grant.scope.allows_asset(request.asset)",
                    "grant.scope.allows_capability(request.capability_id)"):
            with self.subTest(check=old):
                modified = original.replace(old, "True")
                self.assertNotEqual(modified, original)
                self.assertFalse(inventory.inspect_static_shape("src/lightup/execution_policy.py", modified))

    def test_call_order_cannot_be_reversed_in_scope_source(self):
        original = self.baseline["src/lightup/scope.py"].decode()
        # Inserting the real ip_address call ahead of normalize_host must
        # change the lexical first occurrence. Source is only AST-parsed.
        modified = original.replace(
            "        host = self.normalize_host(target.value)",
            "        ip_address('127.0.0.1')\n        host = self.normalize_host(target.value)",
        )
        self.assertNotEqual(modified, original)
        self.assertFalse(inventory.inspect_static_shape("src/lightup/scope.py", modified))
        self.assertEqual(
            inventory.review_source_bytes({
                **self.baseline, "src/lightup/scope.py": modified.encode(),
            }).status,
            "HOLD",
        )

    def test_import_never_executes_production_authority_source(self):
        # In-memory AST parse cannot execute an injected top-level payload.
        original = self.baseline["src/lightup/scope.py"]
        attack = original + b"\nraise RuntimeError('WOULD EXECUTE IF IMPORTED')\n"
        modified = {**self.baseline, "src/lightup/scope.py": attack}
        before_module = sys.modules.get("lightup.scope")
        self.assertEqual(inventory.review_source_bytes(modified).status, "HOLD")
        self.assertIs(sys.modules.get("lightup.scope"), before_module)

    def test_no_file_db_socket_process_from_pure_in_memory_api(self):
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("os.open", side_effect=AssertionError("os")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("db")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")):
            self.assertEqual(inventory.review_source_bytes(self.baseline).status, "REVIEW_ONLY")

    def test_result_is_frozen_and_direct_flags_cannot_be_forged(self):
        result = inventory._hold()
        with self.assertRaises(FrozenInstanceError):
            result.status = "AUTHORIZED"
        with self.assertRaises(TypeError):
            inventory.InventoryVerdict("HOLD", 0, authorized=True)
        with self.assertRaises(ValueError):
            inventory.InventoryVerdict("REVIEW_ONLY", 0)
        with self.assertRaises(ValueError):
            inventory.InventoryVerdict("APPROVED", 5)

    def test_read_only_stable_checkout_and_symlink_confusion(self):
        # An in-memory copy of the original 5 pinned files behaves identically.
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            for rel, contents in self.baseline.items():
                target = base / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
            with patch.object(inventory, "REPO_ROOT", base):
                self.assertEqual(inventory.review_checked_in_sources().status, "REVIEW_ONLY")
                changed_path = base / next(iter(self.baseline))
                changed_path.unlink()
                try:
                    changed_path.symlink_to(base / "src/lightup/models.py")
                except (OSError, NotImplementedError):
                    self.skipTest("symlink unsupported on runner")
                self.assertEqual(inventory.review_checked_in_sources().status, "HOLD")

    def test_cli_real_subprocess_only_exit_two_or_three_and_exact_fields(self):
        base = [sys.executable, str(ROOT / "tools/scope_authority_source_inventory_1499.py")]
        for argv, expected in ((["--offline-review-only"], ("REVIEW_ONLY", 2)),
                               ([], ("HOLD", 3)),
                               (["--unsafe-target", "https://example.com"], ("HOLD", 3)),
                               (["--offline-review-only", "--root=/tmp"], ("HOLD", 3))):
            with self.subTest(argv=argv):
                result = subprocess.run(base + argv, capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, expected[1], result.stderr)
                self.assertEqual(result.stderr, b"")
                body = json.loads(result.stdout)
                self.assertEqual(body["status"], expected[0])
                self.assertEqual(body["contract"], inventory.CONTRACT)
                self.assertEqual(body["source_count"], 5 if expected[1] == 2 else 0)
                self.assertEqual(set(body), {
                    "status", "source_count", "contract", "authorized",
                    "consent_verified", "dispatch_allowed", "release_allowed",
                })
                self.assertTrue(all(body[field] is False for field in
                                    ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")))


if __name__ == "__main__":
    unittest.main()
