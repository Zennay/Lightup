"""Real NL/EN fictional-only comparison UI and CLI safety tests (#1495)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.synthetic_scope_notice_compare_1495 import compare_fictional_scope_envelopes

ENV = {**os.environ, "PYTHONPATH": str(ROOT/"src")}
COMPARE_CLI = [sys.executable, "-m", "lightup.synthetic_scope_notice_compare_cli_1495"]
SOURCE_CLI = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495"]


def origin(*, risk=2, asset="fictional-desk.example.test", language="en"):
    payload = {
        "review_at": "2026-10-16T12:00:00Z",
        "proposals": [{
            "asset": asset,
            "capability": "inventory_read",
            "risk": risk,
            "valid_from": "2026-10-16T11:00:00Z",
            "valid_until": "2026-10-16T13:00:00Z",
        }],
    }
    result = subprocess.run(
        [*SOURCE_CLI, "--synthetic-only", "--lang", language, "--format", "json"],
        input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=15, cwd=ROOT, env=ENV,
    )
    assert result.returncode == 2, result.stderr
    return json.loads(result.stdout)


def rawpair(a=None, b=None):
    return json.dumps({
        "before": origin() if a is None else a,
        "after": origin(risk=5) if b is None else b,
    }).encode()


def run(raw, *flags):
    return subprocess.run(
        [*COMPARE_CLI, *flags], input=raw, cwd=ROOT, env=ENV,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15, check=False,
    )


class FictionalDutchComparison1495(unittest.TestCase):
    def assert_inert(self, page):
        self.assertIn("NOT AUTHORIZED", page)
        self.assertIn("authorized=false", page)
        self.assertIn("consent_verified=false", page)
        self.assertIn("dispatch_allowed=false", page)
        self.assertIn("release_allowed=false", page)
        self.assertIn("default-src 'none'", page)
        for token in ("<script", "<a ", "<form", "<input", "<button", "href=", "onclick="):
            self.assertNotIn(token, page)
        self.assertEqual(page.count("PENDING —"), 4)

    def test_direct_nl_compares_changed_risk_without_approval(self):
        result = compare_fictional_scope_envelopes(rawpair(), language="nl")
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.changes, 1)
        self.assertIn('<html lang="nl">', result.html)
        self.assertIn("NIET GEAUTORISEERD", result.html)
        self.assertIn("VOORGESTELDE DETAILS VERANDERD", result.html)
        self.assertIn("Nog niet geverifieerde vrijgavevoorwaarden", result.html)
        self.assert_inert(result.html)

    def test_direct_nl_added_remains_not_granted(self):
        result = compare_fictional_scope_envelopes(rawpair(
            origin(asset="before.example.test"),
            origin(asset="after.example.test"),
        ), language="nl")
        self.assertIn("ALLEEN IN NA — NIET TOEGEKEND", result.html)
        self.assertIn("ALLEEN IN VOOR — NIET INGETROKKEN", result.html)
        self.assertEqual(result.changes, 2)
        self.assert_inert(result.html)

    def test_direct_nl_identical_reports_still_not_authorized(self):
        x = origin()
        result = compare_fictional_scope_envelopes(rawpair(x, x), language="nl")
        self.assertEqual(result.changes, 0)
        self.assertIn("IDENTIEK FICTIEF VOORSTEL", result.html)
        self.assert_inert(result.html)

    def test_mixed_source_locale_accepted_by_nl_viewer(self):
        result = compare_fictional_scope_envelopes(
            rawpair(origin(language="en"), origin(risk=5, language="nl")),
            language="nl",
        )
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.changes, 1)
        self.assert_inert(result.html)

    def test_direct_invalid_lang_holds_atomically_without_echo(self):
        for lang in ("NL", "en-US", "", "\nnl", True, None):
            with self.subTest(lang=lang):
                result = compare_fictional_scope_envelopes(rawpair(), language=lang)
                self.assertEqual(result.status, "HOLD")
                self.assertEqual(result.compared, 0)
                self.assertNotIn("fictional-desk.example.test", result.html)
                self.assertIn("NOT AUTHORIZED", result.html)

    def test_dutch_atomic_hold_uses_dutch_language(self):
        document = origin()
        document["authorized"] = True
        result = compare_fictional_scope_envelopes(rawpair(document, origin()),
                                                    language="nl")
        self.assertEqual(result.status, "HOLD")
        self.assertIn('<html lang="nl">', result.html)
        self.assertIn("NIET GEAUTORISEERD", result.html)
        self.assertNotIn("fictional-desk.example.test", result.html)
        self.assertIs(result.authorized, False)

    def test_cli_dutch_real_subprocess(self):
        result = run(rawpair(), "--synthetic-pair-to-html", "--lang", "nl")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(result.stderr)
        html = result.stdout.decode()
        self.assertIn('<html lang="nl">', html)
        self.assertIn("VOORGESTELDE DETAILS VERANDERD", html)
        self.assert_inert(html)

    def test_cli_default_matches_explicit_english(self):
        raw = rawpair()
        a = run(raw, "--synthetic-pair-to-html")
        b = run(raw, "--synthetic-pair-to-html", "--lang", "en")
        self.assertEqual(a.returncode, 2)
        self.assertEqual(b.returncode, 2)
        self.assertEqual(a.stdout, b.stdout)

    def test_cli_bad_lang_or_order_fails_without_echo(self):
        for flags in (
            ("--synthetic-pair-to-html", "--lang", "NL"),
            ("--synthetic-pair-to-html", "--lang", "fr"),
            ("--lang", "nl", "--synthetic-pair-to-html"),
            ("--synthetic-pair-to-html", "--lang"),
            ("--synthetic-pair-to-html", "--lang", "nl", "--scan"),
        ):
            with self.subTest(flags=flags):
                result = run(rawpair(), *flags)
                self.assertEqual(result.returncode, 3)
                self.assertIn(b"NOT AUTHORIZED", result.stdout)
                self.assertNotIn(b"fictional-desk.example.test", result.stdout)

    def test_cli_nl_rejected_scope_returns_nl_generic_hold(self):
        before = origin()
        after = origin()
        after["authorized"] = True
        result = run(rawpair(before, after),
                     "--synthetic-pair-to-html", "--lang", "nl")
        self.assertEqual(result.returncode, 3)
        self.assertIn(b'<html lang="nl">', result.stdout)
        self.assertNotIn(b"fictional-desk.example.test", result.stdout)

    def test_cli_en_nl_never_return_zero(self):
        for lang in ("en", "nl"):
            for payload in (rawpair(), b"{}"):
                with self.subTest(lang=lang, length=len(payload)):
                    result = run(payload, "--synthetic-pair-to-html", "--lang", lang)
                    self.assertIn(result.returncode, (2, 3))
                    self.assertNotEqual(result.returncode, 0)

    def test_direct_english_default_unchanged(self):
        raw = rawpair()
        self.assertEqual(
            compare_fictional_scope_envelopes(raw),
            compare_fictional_scope_envelopes(raw, language="en"),
        )

    def test_localized_output_is_deterministic(self):
        raw = rawpair()
        self.assertEqual(
            compare_fictional_scope_envelopes(raw, language="nl"),
            compare_fictional_scope_envelopes(raw, language="nl"),
        )


if __name__ == "__main__":
    unittest.main()
