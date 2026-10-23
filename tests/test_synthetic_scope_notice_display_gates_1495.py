"""Unresolved human approval gates for strictly fictional JSON-view HTML #1495."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.synthetic_scope_notice_display_1495 import render_fictional_envelope_html

PROPOSAL = {
    "asset": "desk.example.test",
    "capability": "inventory_read",
    "risk": 4,
    "valid_from": "2026-10-16T11:00:00Z",
    "valid_until": "2026-10-16T13:00:00Z",
}


def real_json(lang="en", raw=None):
    data = {"review_at": "2026-10-16T12:00:00Z", "proposals": [PROPOSAL]}
    result = subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
         "--synthetic-only", "--lang", lang, "--format", "json"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        input=json.dumps(data).encode() if raw is None else raw,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=12,
    )
    return result


class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class UnresolvedHumanGates1495(unittest.TestCase):
    def assert_inert(self, page):
        self.assertIn("NOT AUTHORIZED", page)
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIn(flag + "=false", page)
        for marker in ('default-src &#x27;none&#x27;', "default-src 'none'"):
            if marker in page:
                break
        else:
            self.fail("missing CSP")
        parser = Markup()
        parser.feed(page)
        self.assertNotIn("form", parser.tags)
        self.assertNotIn("button", parser.tags)
        self.assertNotIn("input", parser.tags)
        self.assertNotIn("a", parser.tags)
        self.assertNotIn("script", parser.tags)

    def test_valid_english_has_four_pending_steps(self):
        run = real_json("en")
        self.assertEqual(run.returncode, 2)
        page = render_fictional_envelope_html(run.stdout)
        self.assertEqual(page.count("PENDING —"), 4)
        self.assertIn("Unverified release gates", page)
        self.assertIn("Independently verify client and operator identities", page)
        self.assertIn("Have scope and time window verified by the source owner", page)
        self.assertIn("Check durable revocation at the time of actual use", page)
        self.assertIn("Obtain security/privacy review and explicit human GO", page)
        self.assert_inert(page)

    def test_valid_dutch_has_four_pending_steps(self):
        run = real_json("nl")
        self.assertEqual(run.returncode, 2)
        page = render_fictional_envelope_html(run.stdout)
        self.assertEqual(page.count("PENDING —"), 4)
        self.assertIn("Nog te verifiëren", page)
        self.assertIn("Verifieer klant- en operatoridentiteit onafhankelijk", page)
        self.assertIn("Controleer duurzame intrekking op het moment van gebruik", page)
        self.assertIn("Verkrijg security-/privacyreview", page)
        self.assert_inert(page)

    def test_pending_english_uses_ordinary_ol_but_no_buttons(self):
        page = render_fictional_envelope_html(real_json().stdout)
        self.assertIn('<ol class="gates">', page)
        self.assertIn('</ol>', page)
        self.assertNotIn("<button", page)
        self.assertNotIn("<input", page)
        self.assertNotIn("onclick", page)
        self.assert_inert(page)

    def test_pending_dutch_has_proposed_not_approved_scope(self):
        page = render_fictional_envelope_html(real_json("nl").stdout)
        self.assertIn("Voorgestelde regels: 1", page)
        self.assertNotIn('type="checkbox"', page)
        self.assertNotIn('aria-checked="true"', page)
        self.assert_inert(page)

    def test_bad_authority_json_does_not_show_review_gates(self):
        data = json.loads(real_json().stdout)
        data["dispatch_allowed"] = True
        page = render_fictional_envelope_html(json.dumps(data).encode())
        self.assertIn("HOLD", page)
        self.assertNotIn("PENDING —", page)
        self.assertNotIn("desk.example.test", page)
        self.assert_inert(page)

    def test_invalid_customer_domain_does_not_show_review_gates(self):
        run = real_json(raw=b'{"bad":"client.company.org"}')
        self.assertEqual(run.returncode, 3)
        page = render_fictional_envelope_html(run.stdout)
        self.assertIn("HOLD", page)
        self.assertNotIn("PENDING —", page)
        self.assertNotIn("client.company.org", page)
        self.assert_inert(page)

    def test_fake_go_text_appended_is_generic_hold(self):
        data = json.loads(real_json().stdout)
        data["notice"] += "\nHuman GO APPROVED"
        page = render_fictional_envelope_html(json.dumps(data).encode())
        self.assertIn("HOLD", page)
        self.assertNotIn("APPROVED", page)
        self.assertNotIn("desk.example.test", page)
        self.assertNotIn("PENDING —", page)
        self.assert_inert(page)

    def test_corrupt_risk_wording_is_generic_hold(self):
        data = json.loads(real_json().stdout)
        data["notice"] = data["notice"].replace(
            "independent step-up and human scrutiny required.",
            "ALL APPROVED.",
        )
        page = render_fictional_envelope_html(json.dumps(data).encode())
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)
        self.assertNotIn("PENDING —", page)
        self.assert_inert(page)

    def test_forged_valid_fictional_content_remains_unverified(self):
        data = json.loads(real_json().stdout)
        data["notice"] = data["notice"].replace(
            "desk.example.test", "fake-scope.example.test",
        )
        page = render_fictional_envelope_html(json.dumps(data).encode())
        self.assertIn("fake-scope.example.test", page)
        self.assertEqual(page.count("PENDING —"), 4)
        self.assertIn("NOT AUTHORIZED", page)
        self.assert_inert(page)

    def test_page_same_for_same_input(self):
        raw = real_json().stdout
        self.assertEqual(render_fictional_envelope_html(raw), render_fictional_envelope_html(raw))

    def test_hold_output_is_bounded_and_private(self):
        page = render_fictional_envelope_html(b'{' + b'SECRET-'*20000)
        self.assertLessEqual(len(page), 25000)
        self.assertNotIn("SECRET-", page)
        self.assertNotIn("PENDING —", page)
        self.assert_inert(page)

    def test_case_mismatched_dutch_warning_does_not_inherit_locale(self):
        data = json.loads(real_json("nl").stdout)
        data["notice"] = data["notice"].replace("NIET GEAUTORISEERD", "goedgekeurd")
        page = render_fictional_envelope_html(json.dumps(data).encode())
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)
        self.assertNotIn("PENDING —", page)
        self.assert_inert(page)


if __name__ == "__main__":
    unittest.main()
