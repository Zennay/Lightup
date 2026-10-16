"""Safety review checklist and risk summary acceptance for inert fictive card #1495."""
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

from lightup.synthetic_scope_notice_1495 import ScopeProposal
from lightup.synthetic_scope_notice_html_1495 import render_synthetic_scope_html

AT = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def item(asset="desk.example.test", capability="inventory_read", risk=2, ends=60):
    return ScopeProposal(
        asset=asset, capability=capability, risk=risk,
        valid_from=AT-timedelta(minutes=20), valid_until=AT+timedelta(minutes=ends),
    )


def render(*proposals, lang="en"):
    return render_synthetic_scope_html(tuple(proposals), review_at=AT, language=lang)


def from_cli(lang="en"):
    data = {
        "review_at": "2026-10-16T12:00:00Z",
        "proposals": [{
            "asset": "desk.example.test", "capability": "inventory_read", "risk": 5,
            "valid_from": "2026-10-16T11:00:00Z",
            "valid_until": "2026-10-16T13:00:00Z",
        }],
    }
    result = subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
         "--synthetic-only", "--lang", lang, "--format", "html"],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        input=json.dumps(data).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=12, check=False,
    )
    return result


class FictionalHumanReleaseGates1495(unittest.TestCase):
    def assert_restricted(self, page):
        self.assertIn("NOT AUTHORIZED", page)
        self.assertIn("authorized=false", page)
        self.assertIn("consent_verified=false", page)
        self.assertIn("dispatch_allowed=false", page)
        self.assertIn("release_allowed=false", page)
        self.assertLessEqual(len(page), 65536)

    def test_plain_english_summary_and_all_pending_gates(self):
        page = render(item(risk=4))
        self.assertIn("Fictional scope summary", page)
        self.assertIn("Fictional assets", page)
        self.assertIn("Elevated risks", page)
        self.assertIn("Earliest expiry (UTC)", page)
        self.assertIn("2026-10-16T13:00:00Z", page)
        self.assertIn("Outstanding release requirements", page)
        self.assertEqual(page.count("PENDING —"), 4)
        self.assert_restricted(page)

    def test_dutch_summary_and_four_pending_gates(self):
        page = render(item(risk=5), lang="nl")
        self.assertIn("Overzicht fictieve scope", page)
        self.assertIn("Fictieve systemen", page)
        self.assertIn("Hoog risico", page)
        self.assertIn("Eerste verloopmoment", page)
        self.assertIn("Open vrijgavevoorwaarden", page)
        self.assertIn("Klanten- en operatoridentiteit", page)
        self.assertEqual(page.count("PENDING —"), 4)
        self.assert_restricted(page)

    def test_capabilities_on_one_asset_not_double_counted_as_assets(self):
        page = render(item(), item(capability="metadata_read"))
        self.assertIn("Fictional proposals: 2", page)
        self.assertIn("Fictional assets</span><strong>1</strong>", page)
        self.assertIn("Elevated risks</span><strong>0</strong>", page)
        self.assert_restricted(page)

    def test_risk_summary_counts_elevated_records_not_unique_assets(self):
        page = render(
            item("a.example.test", risk=4),
            item("b.example.test", risk=5),
            item("c.example.test", risk=3),
        )
        self.assertIn("Fictional assets</span><strong>3</strong>", page)
        self.assertIn("Elevated risks</span><strong>2</strong>", page)
        self.assertIn("High risk: independent step-up", page)
        self.assert_restricted(page)

    def test_earliest_expiry_uses_minimum_utc_not_last_entry(self):
        page = render(
            item("zeta.example.test", ends=40),
            item("alpha.example.test", ends=55),
        )
        self.assertIn("Earliest expiry (UTC)</span><strong>2026-10-16T12:40:00Z</strong>", page)
        self.assert_restricted(page)

    def test_input_order_cannot_change_counts_or_release_gates(self):
        a = (item("alpha.example.test", risk=4),
             item("zeta.example.test", risk=2, ends=29))
        self.assertEqual(render(*a), render(*reversed(a)))

    def test_high_risk_never_changes_pending_to_go(self):
        for risk in (1, 2, 3, 4, 5):
            with self.subTest(risk=risk):
                page = render(item(risk=risk))
                self.assertEqual(page.count("PENDING —"), 4)
                self.assertIn("explicit human GO obtained", page)
                self.assert_restricted(page)

    def test_hold_rejects_raw_customer_asset_and_omits_counters(self):
        page = render(item("private-client.example.com"), item("desk.example.test"))
        self.assertIn("HOLD", page)
        self.assertNotIn("private-client.example.com", page)
        self.assertNotIn("desk.example.test", page)
        self.assertNotIn("Fictional scope summary", page)
        self.assertNotIn("Outstanding release requirements", page)
        self.assert_restricted(page)

    def test_largest_valid_batch_metrics_fit_page(self):
        proposals = tuple(item(f"lab-{i:02}.example.test", risk=5 if i % 2 else 2)
                          for i in range(32))
        page = render(*proposals)
        self.assertIn("Fictional assets</span><strong>32</strong>", page)
        self.assertIn("Elevated risks</span><strong>16</strong>", page)
        self.assertNotIn("HOLD", page)
        self.assert_restricted(page)

    def test_real_subprocess_english_contains_unchecked_gates(self):
        result = from_cli("en")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(result.stderr)
        page = result.stdout.decode()
        self.assertEqual(page.count("PENDING —"), 4)
        self.assertIn("Fictional assets", page)
        self.assert_restricted(page)

    def test_real_subprocess_dutch_contains_unchecked_gates(self):
        result = from_cli("nl")
        self.assertEqual(result.returncode, 2, result.stderr)
        page = result.stdout.decode()
        self.assertEqual(page.count("PENDING —"), 4)
        self.assertIn("NIET GEAUTORISEERD", page)
        self.assertIn("Open vrijgavevoorwaarden", page)
        self.assert_restricted(page)

    def test_printable_local_card_has_no_approval_actions(self):
        page = render(item())
        self.assertIn("@media print", page)
        for forbidden in ("<button", "<form", "<input", "<script", "href=", "src=", "onclick="):
            self.assertNotIn(forbidden, page)
        self.assertIn("default-src 'none'", page)
        self.assert_restricted(page)


if __name__ == "__main__":
    unittest.main()
