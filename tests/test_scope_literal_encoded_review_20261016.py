"""Additional isolated adversarial proof for byte-exact fictional scope review.

No real target or execution, no source-owner code modified.
"""
from __future__ import annotations
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.scope_literal_control_review_20261016 import review_literals

CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"


class EncodedLiteralReview(unittest.TestCase):
    def test_encoded_controls_and_backslash_are_hold(self):
        values = (
            "local%0ahost", "local%09host", "local%0dhost",
            "local%250ahost", "local%25250ahost", "localhost%",
            "local\\nhost", "local\\u000ahost",
            "http://localhost\\victim", "http://local%68ost",
        )
        for value in values:
            with self.subTest(value=value):
                reviewed = review_literals((value,))
                self.assertEqual(reviewed.status, "HOLD")
                self.assertFalse(reviewed.authorized)
                self.assertFalse(reviewed.dispatch_allowed)

    def test_atomic_sixty_four_item_review(self):
        items = tuple(f"fictional-{i}.example.test" for i in range(64))
        self.assertEqual(review_literals(items).status, "REVIEW_ONLY")
        for index in (0, 31, 63):
            bad = list(items)
            bad[index] = "fictional%0a.test"
            self.assertEqual(review_literals(tuple(bad)).status, "HOLD")
        self.assertEqual(review_literals(items + ("fictional-64.example.test",)).status, "HOLD")

    def test_ascii_mutations_never_claim_authority(self):
        for code in range(128):
            for stem in ("local", "127.0.0.", "http://local", ""):
                result = review_literals((stem + chr(code) + "host",))
                self.assertFalse(result.authorized)
                self.assertFalse(result.consent_verified)
                self.assertFalse(result.dispatch_allowed)
                self.assertFalse(result.release_allowed)
                if code < 33 or code in (37, 92, 127):
                    self.assertEqual(result.status, "HOLD")

    def test_cli_boundary_and_generic_no_echo(self):
        def call(values):
            data = json.dumps({"authorities": values}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            return subprocess.run([sys.executable, str(CLI)], input=data, capture_output=True, check=False, timeout=10, cwd=ROOT)
        for name in ("local%0ahost", r"local\nhost", "lab%250a.test"):
            result = call(["public-fictional-marker", name])
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
            self.assertNotIn(b"public-fictional-marker", result.stdout)
            self.assertEqual(result.stderr, b"")
        items = [f"fictional-{i}.test" for i in range(64)]
        self.assertEqual(call(items).returncode, 2)
        items[-1] = "fictional%0a.test"
        self.assertEqual(call(items).returncode, 3)
        items[-1] = "fictional-63.test"
        items.append("fictional-64.test")
        self.assertEqual(call(items).returncode, 3)

    def test_inprocess_cli_is_no_network_no_child_no_file_open(self):
        mod = runpy.run_path(str(CLI), run_name="offline_scope_review_import")
        for payload, expected in (
            (b'{"authorities":["fictional.test"]}', 2),
            (b'{"authorities":["local%0ahost"]}', 3),
            (b'{"authorities":["local\\\\nhost"]}', 3),
        ):
            with self.subTest(payload=payload):
                output = io.BytesIO()
                stdin = SimpleNamespace(buffer=io.BytesIO(payload))
                stdout = SimpleNamespace(buffer=output)
                with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout), \
                     patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                     patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
                     patch("builtins.open", side_effect=AssertionError("file forbidden")):
                    self.assertEqual(mod["main"](), expected)
                body = json.loads(output.getvalue())
                self.assertFalse(any(value is True for value in body.values()))
                self.assertNotIn(b"fictional.test", output.getvalue())


if __name__ == "__main__":
    unittest.main()
