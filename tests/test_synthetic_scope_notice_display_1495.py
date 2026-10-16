"""End-to-end fictional CLI JSON -> strict decoder -> inert HTML viewer."""
from __future__ import annotations

from html.parser import HTMLParser
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))

from lightup.synthetic_scope_notice_display_1495 import render_fictional_envelope_html

FIXTURE = {
    "review_at": "2026-10-16T12:00:00Z",
    "proposals": [{
        "asset": "desk.example.test", "capability": "inventory_read", "risk": 4,
        "valid_from": "2026-10-16T11:00:00Z",
        "valid_until": "2026-10-16T13:00:00Z",
    }],
}


def generated(lang="en", *, raw=None):
    cmd = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
           "--synthetic-only", "--lang", lang, "--format", "json"]
    res = subprocess.run(
        cmd, input=json.dumps(FIXTURE).encode() if raw is None else raw,
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False,
    )
    return res


class StrictElements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.append((tag, dict(attrs)))


class OfflineFictionalEnvelopeDisplay1495(unittest.TestCase):
    def assert_inert(self, html):
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("NOT AUTHORIZED", html)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIn(key+"=false", html)
        self.assertIn("default-src 'none'", html)
        self.assertIn("script-src 'none'", html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn("form-action 'none'", html)
        self.assertIn("base-uri 'none'", html)
        parser = StrictElements()
        parser.feed(html)
        for tag in ("script", "iframe", "form", "input", "button", "img", "a"):
            self.assertNotIn(tag, parser.tags)
        for _, attrs in parser.attrs:
            self.assertNotIn("href", attrs)
            self.assertNotIn("src", attrs)
            self.assertNotIn("action", attrs)
            self.assertFalse(any(k.startswith("on") for k in attrs))

    def test_real_cli_json_roundtrip_english(self):
        run = generated("en")
        self.assertEqual(run.returncode, 2)
        html = render_fictional_envelope_html(run.stdout)
        self.assertIn('<html lang="en">', html)
        self.assertIn("REVIEW_ONLY", html)
        self.assertIn("desk.example.test", html)
        self.assertIn("inventory_read", html)
        self.assertIn("Proposed entries: 1", html)
        self.assert_inert(html)

    def test_real_cli_json_roundtrip_dutch(self):
        run = generated("nl")
        self.assertEqual(run.returncode, 2)
        html = render_fictional_envelope_html(run.stdout)
        self.assertIn('<html lang="nl">', html)
        self.assertIn("NIET GEAUTORISEERD", html)
        self.assertIn("Voorgestelde regels: 1", html)
        self.assert_inert(html)

    def test_real_cli_json_invalid_is_generic_hold(self):
        run = generated("en", raw=b'{"bad":"client.example.com"}')
        self.assertEqual(run.returncode, 3)
        html = render_fictional_envelope_html(run.stdout)
        self.assertIn("HOLD", html)
        self.assertNotIn("client.example.com", html)
        self.assert_inert(html)

    def test_raw_bad_bytes_are_generic_hold(self):
        for raw in (b"", b"not json", b"null", b"{}", b"\xff", b"[]" ):
            with self.subTest(raw=raw):
                html = render_fictional_envelope_html(raw)
                self.assertIn("HOLD", html)
                self.assertNotIn("desk.example.test", html)
                self.assert_inert(html)

    def test_true_grant_forgery_is_denied_before_html(self):
        value = json.loads(generated().stdout)
        value["authorized"] = True
        html = render_fictional_envelope_html(json.dumps(value).encode())
        self.assertIn("HOLD", html)
        self.assertNotIn("desk.example.test", html)
        self.assert_inert(html)

    def test_extra_approved_property_cannot_promote_review(self):
        value = json.loads(generated().stdout)
        value["approved"] = True
        html = render_fictional_envelope_html(json.dumps(value).encode())
        self.assertIn("HOLD", html)
        self.assertNotIn("desk.example.test", html)
        self.assert_inert(html)

    def test_corrupted_markup_turns_entire_notice_to_generic_hold(self):
        value = json.loads(generated().stdout)
        value["notice"] += "\n<script>alert(1)</script><img src=//evil.example/>"
        html = render_fictional_envelope_html(json.dumps(value).encode())
        self.assertIn("HOLD", html)
        self.assertNotIn("desk.example.test", html)
        self.assertNotIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=", html)
        self.assert_inert(html)

    def test_appended_javascript_url_causes_generic_hold(self):
        value = json.loads(generated().stdout)
        value["notice"] += "\njavascript:alert(1)"
        html = render_fictional_envelope_html(json.dumps(value).encode())
        self.assertIn("HOLD", html)
        self.assertNotIn("javascript:alert(1)", html)
        self.assertNotIn("desk.example.test", html)
        self.assertNotIn("href=", html)
        self.assert_inert(html)

    def test_renderer_is_deterministic_with_identical_bytes(self):
        raw = generated().stdout
        self.assertEqual(render_fictional_envelope_html(raw), render_fictional_envelope_html(raw))

    def test_long_oversized_payload_holds_without_echo(self):
        data = generated().stdout + b" " * 65536
        html = render_fictional_envelope_html(data)
        self.assertIn("HOLD", html)
        self.assertNotIn("desk.example.test", html)
        self.assert_inert(html)

    def test_partial_json_or_duplicate_keys_are_generic_hold(self):
        raw = generated().stdout
        raw = raw.replace(b'"authorized":false', b'"authorized":false,"authorized":false', 1)
        html = render_fictional_envelope_html(raw)
        self.assertIn("HOLD", html)
        self.assertNotIn("desk.example.test", html)
        self.assert_inert(html)

    def test_nul_control_code_rejected_from_display(self):
        value = json.loads(generated().stdout)
        value["notice"] += "\u0000"
        html = render_fictional_envelope_html(json.dumps(value).encode())
        self.assertIn("HOLD", html)
        self.assertNotIn("desk.example.test", html)
        self.assert_inert(html)

    def test_hold_notice_does_not_let_fake_release_workflow_start(self):
        for bad in (b'{"authorized":true}', b'{"dispatch_allowed":true}',
                    b'{"status":"AUTHORIZED"}'):
            with self.subTest(bad=bad):
                html = render_fictional_envelope_html(bad)
                self.assertIn("HOLD", html)
                self.assert_inert(html)

    def test_embedded_style_is_static_no_external_resources(self):
        html = render_fictional_envelope_html(generated().stdout)
        self.assertIn("pre.review-text{white-space:pre-wrap", html)
        self.assertIn("@media print", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assert_inert(html)

    def test_none_and_mutable_input_fails_closed(self):
        for payload in (None, {}, [], bytearray(b"{}")):
            with self.subTest(type=type(payload)):
                html = render_fictional_envelope_html(payload)
                self.assertIn("HOLD", html)
                self.assert_inert(html)


if __name__ == "__main__":
    unittest.main()
