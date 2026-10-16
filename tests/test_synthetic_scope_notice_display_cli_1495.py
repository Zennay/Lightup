"""Real subprocess coverage of opt-in fictional JSON->safe HTML CLI #1495."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
PRODUCER = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
            "--synthetic-only"]
VIEWER = [sys.executable, "-m", "lightup.synthetic_scope_notice_display_cli_1495"]
FIXTURE = {
    "review_at": "2026-10-16T12:00:00Z",
    "proposals": [{
        "asset": "desk.example.test", "capability": "inventory_read", "risk": 4,
        "valid_from": "2026-10-16T11:00:00Z",
        "valid_until": "2026-10-16T13:00:00Z",
    }],
}


def run(command, payload):
    return subprocess.run(command, cwd=ROOT, env=ENV, input=payload,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False, timeout=15)


def original_json(*flags, input_data=None):
    data = json.dumps(FIXTURE if input_data is None else input_data).encode()
    return run([*PRODUCER, *flags, "--format", "json"], data)


def view(payload, *flags):
    return run([*VIEWER, *flags], payload)


class FictionalJsonHtmlCli1495(unittest.TestCase):
    def assert_locked(self, completed, *, status):
        page = completed.stdout.decode("utf-8")
        self.assertEqual(completed.returncode, status, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertIn("NOT AUTHORIZED", page)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIn(key + "=false", page)
        for unsafe in ("<script", "<iframe", "<button", "<form", "<input",
                       "href=", "onclick=", "src=", "https://", "http://"):
            self.assertNotIn(unsafe, page)
        self.assertIn("default-src 'none'", page)
        return page

    def test_actual_two_subprocess_pipeline_english(self):
        generated = original_json()
        self.assertEqual(generated.returncode, 2)
        html = view(generated.stdout, "--synthetic-json-to-html")
        page = self.assert_locked(html, status=2)
        self.assertIn("desk.example.test", page)
        self.assertIn("Fictional review", page)
        self.assertEqual(page.count("PENDING —"), 4)

    def test_actual_two_subprocess_pipeline_dutch(self):
        generated = original_json("--lang", "nl")
        self.assertEqual(generated.returncode, 2)
        page = self.assert_locked(view(generated.stdout, "--synthetic-json-to-html"), status=2)
        self.assertIn("NIET GEAUTORISEERD", page)
        self.assertIn("Nog te verifiëren", page)
        self.assertIn("desk.example.test", page)
        self.assertEqual(page.count("PENDING —"), 4)

    def test_producer_hold_pipes_to_generic_html_hold(self):
        generated = run([*PRODUCER, "--format", "json"],
                        b'{"asset":"private-customer.example.com"}')
        self.assertEqual(generated.returncode, 3)
        page = self.assert_locked(view(generated.stdout, "--synthetic-json-to-html"), status=3)
        self.assertIn("HOLD", page)
        self.assertNotIn("private-customer.example.com", page)
        self.assertNotIn("PENDING —", page)

    def test_empty_stdin_is_generic_hold(self):
        page = self.assert_locked(view(b"", "--synthetic-json-to-html"), status=3)
        self.assertIn("HOLD", page)

    def test_binary_garbage_is_generic_hold(self):
        page = self.assert_locked(view(b"\xff\x00\xfe", "--synthetic-json-to-html"), status=3)
        self.assertIn("HOLD", page)

    def test_malformed_json_does_not_echo_customer_domain(self):
        page = self.assert_locked(
            view(b'{"notice":"private.example.com"', "--synthetic-json-to-html"), status=3,
        )
        self.assertNotIn("private.example.com", page)

    def test_oversized_stdin_holds_after_bounded_read(self):
        page = self.assert_locked(view(b"X"*65537, "--synthetic-json-to-html"), status=3)
        self.assertNotIn("X"*100, page)

    def test_trailing_oversized_valid_prefix_holds(self):
        generated = original_json().stdout
        page = self.assert_locked(
            view(generated + b" "*65536, "--synthetic-json-to-html"), status=3
        )
        self.assertNotIn("desk.example.test", page)

    def test_true_authority_field_holds_without_echo(self):
        data = json.loads(original_json().stdout)
        data["authorized"] = True
        page = self.assert_locked(
            view(json.dumps(data).encode(), "--synthetic-json-to-html"), status=3
        )
        self.assertNotIn("desk.example.test", page)

    def test_dupe_json_key_holds(self):
        raw = original_json().stdout.replace(
            b'"authorized":false', b'"authorized":false,"authorized":false', 1,
        )
        page = self.assert_locked(view(raw, "--synthetic-json-to-html"), status=3)
        self.assertNotIn("desk.example.test", page)

    def test_injected_real_asset_in_review_text_holds(self):
        data = json.loads(original_json().stdout)
        data["notice"] = data["notice"].replace(
            "desk.example.test", "secret.customer.com",
        )
        page = self.assert_locked(
            view(json.dumps(data).encode(), "--synthetic-json-to-html"), status=3,
        )
        self.assertNotIn("secret.customer.com", page)
        self.assertNotIn("desk.example.test", page)

    def test_injected_approval_line_holds_and_is_not_shown(self):
        data = json.loads(original_json().stdout)
        data["notice"] += "\nUser has APPROVED full live scan."
        page = self.assert_locked(
            view(json.dumps(data).encode(), "--synthetic-json-to-html"), status=3,
        )
        self.assertNotIn("APPROVED", page)
        self.assertNotIn("desk.example.test", page)

    def test_missing_unsafe_flag_holds_without_reading_proposal(self):
        raw = original_json().stdout
        page = self.assert_locked(view(raw), status=3)
        self.assertNotIn("desk.example.test", page)

    def test_wrong_or_extraneous_flags_hold(self):
        for flags in (("--synthetic-json-to-html", "--scan"),
                      ("--format", "html"),
                      ("--synthetic-only",),
                      ("--synthetic-json-to-html=true",),
                      ("--synthetic-json-to-html", "--grant", "true")):
            with self.subTest(flags=flags):
                page = self.assert_locked(view(original_json().stdout, *flags), status=3)
                self.assertNotIn("desk.example.test", page)

    def test_invalid_flag_not_reflected_in_hold(self):
        secret = "--private-customer-secret-123"
        page = self.assert_locked(view(original_json().stdout, secret), status=3)
        self.assertNotIn(secret, page)

    def test_machine_contract_has_no_zero_exit(self):
        for payload, flags in ((original_json().stdout, ("--synthetic-json-to-html",)),
                               (b"{}", ("--synthetic-json-to-html",)),
                               (original_json().stdout, ())):
            with self.subTest(flags=flags):
                completed = view(payload, *flags)
                self.assertIn(completed.returncode, (2, 3))
                self.assertNotEqual(completed.returncode, 0)

    def test_identical_bytes_generate_identical_html(self):
        raw = original_json().stdout
        first = view(raw, "--synthetic-json-to-html")
        second = view(raw, "--synthetic-json-to-html")
        self.assertEqual(first.returncode, 2)
        self.assertEqual(first.stdout, second.stdout)
        self.assert_locked(first, status=2)


if __name__ == "__main__":
    unittest.main()
