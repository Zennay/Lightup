"""Locale identity and no-authority acceptance for fictional scope notices (#1495)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.synthetic_scope_notice_1495 import ScopeProposal, render_scope_notice

AT = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
SAMPLE = ScopeProposal(
    asset="desk.example.test",
    capability="inventory_read",
    risk=4,
    valid_from=AT - timedelta(hours=1),
    valid_until=AT + timedelta(hours=1),
)


def input_bytes():
    return json.dumps({
        "review_at": "2026-10-16T12:00:00Z",
        "proposals": [{
            "asset": "desk.example.test",
            "capability": "inventory_read",
            "risk": 4,
            "valid_from": "2026-10-16T11:00:00Z",
            "valid_until": "2026-10-16T13:00:00Z",
        }],
    }).encode()


def cli(*flags, payload=None):
    return subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495", "--synthetic-only", *flags],
        input=input_bytes() if payload is None else payload,
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT/"src")},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False,
    )


class FictionalNoticeLocale1495(unittest.TestCase):
    def assert_non_authority(self, result):
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)
        self.assertIn("NOT AUTHORIZED", result.text)

    def test_dutch_direct_operator_preview(self):
        r = render_scope_notice((SAMPLE,), review_at=AT, language="nl")
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assertEqual(r.reviewed, 1)
        self.assertTrue(r.elevated_risk)
        self.assertIn("NIET GEAUTORISEERD", r.text)
        self.assertIn("Geen klanttoestemming", r.text)
        self.assertIn("Voorgesteld systeem", r.text)
        self.assertIn("aparte bevestiging", r.text)
        self.assert_non_authority(r)

    def test_dutch_low_risk_never_promotes(self):
        low = ScopeProposal(SAMPLE.asset, SAMPLE.capability, 2, SAMPLE.valid_from, SAMPLE.valid_until)
        r = render_scope_notice((low,), review_at=AT, language="nl")
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assertFalse(r.elevated_risk)
        self.assertIn("altijd een onafhankelijke menselijke toets", r.text)
        self.assert_non_authority(r)

    def test_english_explicit_equals_default(self):
        a = render_scope_notice((SAMPLE,), review_at=AT)
        b = render_scope_notice((SAMPLE,), review_at=AT, language="en")
        self.assertEqual(a, b)
        self.assertIn("independent step-up", a.text)
        self.assert_non_authority(a)

    def test_never_echo_or_autocorrect_invalid_language(self):
        class MyString(str):
            pass
        invalid = (None, 1, False, "", "NL", "dutch", "en-US", "nl\nINJECT", MyString("nl"))
        for language in invalid:
            with self.subTest(language=language):
                result = render_scope_notice((SAMPLE,), review_at=AT, language=language)
                self.assertEqual(result.status, "HOLD")
                self.assertEqual(result.reviewed, 0)
                self.assertNotIn("desk.example.test", result.text)
                self.assert_non_authority(result)

    def test_dutch_malformed_scope_is_full_hold(self):
        bad = ScopeProposal("customer.example.com", SAMPLE.capability, 4, SAMPLE.valid_from, SAMPLE.valid_until)
        r = render_scope_notice((SAMPLE, bad), review_at=AT, language="nl")
        self.assertEqual(r.status, "HOLD")
        self.assertEqual(r.reviewed, 0)
        self.assertNotIn("customer.example.com", r.text)
        self.assertNotIn("desk.example.test", r.text)
        self.assert_non_authority(r)

    def test_english_real_subprocess_explicit(self):
        r = cli("--lang", "en")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn(b"NOT AUTHORIZED", r.stdout)
        self.assertIn(b"independent step-up", r.stdout)
        self.assertNotIn(b"NIET GEAUTORISEERD", r.stdout)
        self.assertFalse(r.stderr)

    def test_dutch_real_subprocess_plain_text(self):
        r = cli("--lang", "nl")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn(b"NOT AUTHORIZED", r.stdout)
        self.assertIn("NIET GEAUTORISEERD".encode(), r.stdout)
        self.assertIn("Geen klanttoestemming".encode(), r.stdout)
        self.assertIn("aparte bevestiging".encode(), r.stdout)
        self.assertIn(b"desk.example.test", r.stdout)
        self.assertFalse(r.stderr)

    def test_dutch_cli_repeatability(self):
        x = cli("--lang", "nl")
        y = cli("--lang", "nl")
        self.assertEqual(x.stdout, y.stdout)
        self.assertEqual(x.returncode, 2)
        self.assertEqual(y.returncode, 2)

    def test_invalid_cli_language_flags_hold_with_no_echo(self):
        options = [
            ("--lang", "NL"), ("--lang", "fr"), ("--lang", ""),
            ("--lang", "nl", "extra"), ("--lang",), ("nl", "--lang"),
            ("--lang=nl",), ("--lang", "en", "--lang", "nl"),
        ]
        for flags in options:
            with self.subTest(flags=flags):
                r = cli(*flags)
                self.assertEqual(r.returncode, 3)
                self.assertIn(b"HOLD", r.stdout)
                self.assertIn(b"NOT AUTHORIZED", r.stdout)
                self.assertNotIn(b"desk.example.test", r.stdout)
                self.assertFalse(r.stderr)

    def test_dutch_cli_corrupt_json_never_displays_requested_asset(self):
        bad = input_bytes().replace(b"desk.example.test", b"private-customer.example.com")
        r = cli("--lang", "nl", payload=bad)
        self.assertEqual(r.returncode, 3)
        self.assertNotIn(b"private-customer.example.com", r.stdout)
        self.assertIn(b"NOT AUTHORIZED", r.stdout)
        self.assertFalse(r.stderr)


if __name__ == "__main__":
    unittest.main()
