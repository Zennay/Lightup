"""Inert bilingual HTML operator preview acceptance on real fictional stdin (#1495)."""
from __future__ import annotations

import builtins
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.synthetic_scope_notice_1495 import ScopeProposal
from lightup.synthetic_scope_notice_html_1495 import render_synthetic_scope_html

AT = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def sample(asset="desk.example.test", *, risk=4, capability="inventory_read"):
    return ScopeProposal(asset, capability, risk, AT-timedelta(hours=1), AT+timedelta(hours=1))


def html(*items, language="en", at=AT):
    return render_synthetic_scope_html(tuple(items), review_at=at, language=language)


def real_cli(*flags, data=None, raw=None):
    payload = json.dumps(data or {
        "review_at": "2026-10-16T12:00:00Z",
        "proposals": [{
            "asset": "desk.example.test", "capability": "inventory_read", "risk": 4,
            "valid_from": "2026-10-16T11:00:00Z", "valid_until": "2026-10-16T13:00:00Z",
        }],
    }).encode() if raw is None else raw
    return subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
         "--synthetic-only", *flags],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=12,
    )


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.append((tag, dict(attrs)))


class SyntheticHtmlPreview1495(unittest.TestCase):
    def assert_inert(self, page):
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertIn("NOT AUTHORIZED", page)
        self.assertIn("authorized=false", page)
        self.assertIn("consent_verified=false", page)
        self.assertIn("dispatch_allowed=false", page)
        self.assertIn("release_allowed=false", page)
        self.assertIn("Content-Security-Policy", page)
        self.assertIn("default-src 'none'", page)
        self.assertIn("script-src 'none'", page)
        self.assertIn("connect-src 'none'", page)
        self.assertIn("form-action 'none'", page)
        self.assertIn("base-uri 'none'", page)
        self.assertIn("referrer\" content=\"no-referrer", page)
        self.assertLessEqual(len(page), 65536)
        parsed = Elements()
        parsed.feed(page)
        self.assertNotIn("script", parsed.tags)
        self.assertNotIn("iframe", parsed.tags)
        self.assertNotIn("form", parsed.tags)
        self.assertNotIn("button", parsed.tags)
        self.assertNotIn("input", parsed.tags)
        self.assertNotIn("img", parsed.tags)
        self.assertNotIn("a", parsed.tags)
        for tag, attrs in parsed.attrs:
            self.assertNotIn("href", attrs)
            self.assertNotIn("src", attrs)
            self.assertNotIn("action", attrs)
            self.assertFalse(any(k.startswith("on") for k in attrs))

    def test_default_html_card_displays_exact_scope(self):
        page = html(sample())
        self.assertIn('<html lang="en">', page)
        self.assertIn("<table>", page)
        self.assertIn("desk.example.test", page)
        self.assertIn("inventory_read", page)
        self.assertIn("4/5", page)
        self.assertIn("2026-10-16T13:00:00Z", page)
        self.assertIn("REVIEW_ONLY", page)
        self.assert_inert(page)

    def test_dutch_html_card(self):
        page = html(sample(), language="nl")
        self.assertIn('<html lang="nl">', page)
        self.assertIn("NIET GEAUTORISEERD", page)
        self.assertIn("Geen klanttoestemming", page)
        self.assertIn("Hoog risico", page)
        self.assertIn("Voorgesteld bereik", page)
        self.assert_inert(page)

    def test_english_low_risk_remains_non_authorizing(self):
        page = html(sample(risk=1))
        self.assertIn("Every proposed scope requires independent human review.", page)
        self.assertNotIn("High risk:", page)
        self.assert_inert(page)

    def test_dutch_low_risk_remains_non_authorizing(self):
        page = html(sample(risk=2), language="nl")
        self.assertIn("Iedere scope vereist een onafhankelijke menselijke toets.", page)
        self.assert_inert(page)

    def test_high_risk_4_and_5_require_human_stepup(self):
        for risk in (4, 5):
            with self.subTest(risk=risk):
                page = html(sample(risk=risk))
                self.assertIn("independent step-up", page)
                self.assertIn(f"{risk}/5", page)
                self.assert_inert(page)

    def test_hold_never_echoes_customer_hostname_or_approved_fields(self):
        page = html(sample("secret.customer.example.com"), language="nl")
        self.assertIn("HOLD", page)
        self.assertNotIn("secret.customer.example.com", page)
        self.assertNotIn("<table>", page)
        self.assert_inert(page)

    def test_invalid_language_fails_closed_does_not_show_asset(self):
        for language in ("NL", "en-US", None, True, "nl\nignore"):
            with self.subTest(language=language):
                page = html(sample(), language=language)
                self.assertIn("HOLD", page)
                self.assertNotIn("desk.example.test", page)
                self.assert_inert(page)

    def test_no_proposals_or_mutable_container_holds(self):
        self.assertIn("HOLD", html())
        page = render_synthetic_scope_html([sample()], review_at=AT)
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)
        self.assert_inert(page)

    def test_expired_candidate_holds_without_revealing_asset(self):
        page = html(sample(), at=AT+timedelta(hours=2))
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)
        self.assert_inert(page)

    def test_duplicate_pair_holds_atomically(self):
        page = html(sample("alpha.example.test"), sample("desk.example.test"), sample("desk.example.test"))
        self.assertIn("HOLD", page)
        self.assertNotIn("alpha.example.test", page)
        self.assertNotIn("desk.example.test", page)
        self.assert_inert(page)

    def test_order_invariant_for_independent_scopes(self):
        values = (sample("zeta.example.test"), sample("alpha.example.test"))
        first = html(*values)
        second = html(*reversed(values))
        self.assertEqual(first, second)
        self.assertLess(first.index("alpha.example.test"), first.index("zeta.example.test"))
        self.assert_inert(first)

    def test_large_batch_of_32_stays_bounded(self):
        samples = tuple(sample(f"fake{i:02d}.example.test") for i in range(32))
        page = html(*samples)
        self.assertNotIn("HOLD", page)
        self.assertEqual(page.count("<tr>"), 33)
        self.assert_inert(page)

    def test_batch_of_33_holds_atomically(self):
        samples = tuple(sample(f"fake{i:02d}.example.test") for i in range(33))
        page = html(*samples)
        self.assertIn("HOLD", page)
        self.assertNotIn("fake00.example.test", page)
        self.assert_inert(page)

    def test_repeated_calls_have_no_state(self):
        self.assertEqual(html(sample()), html(sample()))
        self.assertEqual(html(sample(), language="nl"), html(sample(), language="nl"))

    def test_in_process_render_performs_no_disk_network_db_or_command(self):
        with patch.object(builtins, "open", side_effect=AssertionError("filesystem")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("database")), \
             patch.object(subprocess, "run", side_effect=AssertionError("process")):
            first = html(sample())
            denied = html(sample("client.example.com"))
        self.assert_inert(first)
        self.assert_inert(denied)

    def test_cli_html_default_is_real_page_and_nonzero_exit(self):
        p = real_cli("--format", "html")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertFalse(p.stderr)
        self.assert_inert(p.stdout.decode())
        self.assertIn(b"desk.example.test", p.stdout)

    def test_cli_dutch_html_real_process(self):
        p = real_cli("--lang", "nl", "--format", "html")
        self.assertEqual(p.returncode, 2, p.stderr)
        page = p.stdout.decode()
        self.assertIn("NIET GEAUTORISEERD", page)
        self.assertIn('<html lang="nl">', page)
        self.assert_inert(page)

    def test_cli_explicit_english_equals_default(self):
        a = real_cli("--format", "html")
        b = real_cli("--lang", "en", "--format", "html")
        self.assertEqual(a.returncode, 2)
        self.assertEqual(b.returncode, 2)
        self.assertEqual(a.stdout, b.stdout)

    def test_cli_rejects_bad_json_with_full_html_hold(self):
        p = real_cli("--format", "html", raw=b'{"asset":"live-customer.example.com"}')
        self.assertEqual(p.returncode, 3)
        self.assertFalse(p.stderr)
        page = p.stdout.decode()
        self.assertIn("HOLD", page)
        self.assertNotIn("live-customer.example.com", page)
        self.assert_inert(page)

    def test_cli_rejects_bad_json_in_dutch_mode(self):
        p = real_cli("--lang", "nl", "--format", "html", raw=b'{"bad":"secret.example.com"}')
        self.assertEqual(p.returncode, 3)
        page = p.stdout.decode()
        self.assertIn("NIET GEAUTORISEERD", page)
        self.assertNotIn("secret.example.com", page)
        self.assert_inert(page)

    def test_cli_blocks_reordered_or_unknown_html_flags(self):
        for flags in (("--format", "html", "--lang", "nl"),
                      ("--format", "HTML"), ("--format=html",),
                      ("--lang", "nl", "--format", "html", "--scan")):
            with self.subTest(flags=flags):
                p = real_cli(*flags)
                self.assertEqual(p.returncode, 3)
                self.assertIn(b"NOT AUTHORIZED", p.stdout)
                self.assertNotIn(b"desk.example.test", p.stdout)

    def test_cli_never_emits_external_link_or_script(self):
        page = real_cli("--lang", "nl", "--format", "html").stdout.decode()
        for token in ("<script", "<iframe", "<form", "<a ", "http://", "https://"):
            self.assertNotIn(token, page.lower())
        self.assert_inert(page)


if __name__ == "__main__":
    unittest.main()
